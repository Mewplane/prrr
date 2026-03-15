// FRD: specs/frds/FRD-20260225-h2-sender-receiver.md

//! HTTP/2 stream adapters for the HARP transport.
//!
//! Bridges `h2::SendStream<Bytes>` and `h2::RecvStream` to prrr's
//! [`DatagramSender`] / [`DatagramReceiver`] traits, enabling HARP
//! frame exchange over HTTP/2 multiplexed streams.
//!
//! [`DatagramSender`]: crate::tunnel::pipeline::DatagramSender
//! [`DatagramReceiver`]: crate::tunnel::pipeline::DatagramReceiver

use std::sync::Mutex;

use bytes::Bytes;
use tokio::sync::Mutex as TokioMutex;

use super::TransportError;
use super::harp::{HarpFrame, HarpFrameReader, HarpFrameType};
use crate::tunnel::pipeline::{DatagramReceiver, DatagramSender};

/// Sends HARP DATA frames over an HTTP/2 send stream.
///
/// Wraps `h2::SendStream<Bytes>` behind a `Mutex` to satisfy the
/// `&self` signature of [`DatagramSender::send_datagram`].
pub struct H2Sender {
    stream: Mutex<h2::SendStream<Bytes>>,
}

impl H2Sender {
    /// Create a new `H2Sender` wrapping the given H2 send stream.
    pub fn new(stream: h2::SendStream<Bytes>) -> Self {
        Self {
            stream: Mutex::new(stream),
        }
    }
}

impl DatagramSender for H2Sender {
    fn send_datagram(&self, payload: &[u8]) -> Result<(), TransportError> {
        let frame = HarpFrame::data(payload.to_vec());
        let wire_bytes = frame.encode()?;
        let mut stream = self.stream.lock().expect("H2Sender lock poisoned");
        stream
            .send_data(Bytes::from(wire_bytes), false)
            .map_err(|e| TransportError::H2Stream(e.to_string()))
    }
}

/// Internal state for the HTTP/2 receiver.
struct H2ReceiverInner {
    stream: h2::RecvStream,
    frame_reader: HarpFrameReader,
}

/// Receives HARP frames from an HTTP/2 receive stream.
///
/// Wraps `h2::RecvStream` + [`HarpFrameReader`] behind a `TokioMutex`
/// to satisfy the `&self` signature of [`DatagramReceiver::recv_datagram`].
///
/// Automatically releases HTTP/2 flow control capacity after consuming
/// each DATA chunk.
pub struct H2Receiver {
    inner: TokioMutex<H2ReceiverInner>,
}

impl H2Receiver {
    /// Create a new `H2Receiver` wrapping the given H2 receive stream.
    pub fn new(stream: h2::RecvStream) -> Self {
        Self {
            inner: TokioMutex::new(H2ReceiverInner {
                stream,
                frame_reader: HarpFrameReader::new(),
            }),
        }
    }
}

impl DatagramReceiver for H2Receiver {
    async fn recv_datagram(&self) -> Result<Vec<u8>, TransportError> {
        let mut inner = self.inner.lock().await;
        loop {
            // Drain buffered frames first
            if let Some(result) = inner.frame_reader.next_frame() {
                let frame = result?;
                match frame.frame_type {
                    HarpFrameType::Data => return Ok(frame.payload),
                    HarpFrameType::Keepalive => continue,
                    HarpFrameType::Close => return Err(TransportError::HarpSessionClosed),
                }
            }

            // Read next H2 DATA chunk
            let chunk = inner
                .stream
                .data()
                .await
                .ok_or(TransportError::HarpChannelClosed)?
                .map_err(|e| TransportError::H2Stream(e.to_string()))?;

            let len = chunk.len();
            inner.frame_reader.push(&chunk);

            // Release flow control capacity back to the peer
            inner
                .stream
                .flow_control()
                .release_capacity(len)
                .map_err(|e| TransportError::H2Stream(e.to_string()))?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::harp::HarpFrame;
    use hyper::{Request, Response};

    /// Helper: creates a connected H2 client/server pair over an in-memory transport.
    ///
    /// Returns `(client_send_request, server_connection_accept)` where:
    /// - `client_send_request` can open new H2 streams (SendRequest<Bytes>)
    /// - The server connection is spawned as a background task
    ///
    /// The server echoes back any received DATA by wrapping each chunk in a response body.
    async fn h2_echo_pair() -> (h2::client::SendRequest<Bytes>, tokio::task::JoinHandle<()>) {
        let (client_io, server_io) = tokio::io::duplex(65536);

        // Client handshake
        let (send_request, connection) = h2::client::handshake(client_io).await.expect("client handshake");

        // Spawn client connection driver
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::debug!("client h2 connection ended: {e}");
            }
        });

        // Server handshake
        let mut server_conn = h2::server::handshake(server_io).await.expect("server handshake");

        // Spawn server task: for each request, echo received DATA back in the response
        let server_handle = tokio::spawn(async move {
            while let Some(result) = server_conn.accept().await {
                let (request, mut respond) = result.expect("accept stream");
                let mut recv_body = request.into_body();

                // Send response headers
                let response = Response::builder().status(200).body(()).expect("build response");
                let mut send_body = respond.send_response(response, false).expect("send response");

                // Echo received data back
                tokio::spawn(async move {
                    while let Some(chunk) = recv_body.data().await {
                        match chunk {
                            Ok(data) => {
                                let len = data.len();
                                let _ = recv_body.flow_control().release_capacity(len);
                                let _ = send_body.send_data(data, false);
                            }
                            Err(_) => break,
                        }
                    }
                    // End of stream — close the response
                    let _ = send_body.send_data(Bytes::new(), true);
                });
            }
        });

        (send_request, server_handle)
    }

    // AC-10: H2Stream error variant exists and formats correctly
    #[test]
    fn h2_stream_error_variant() {
        let err = TransportError::H2Stream("test error".to_string());
        assert_eq!(err.to_string(), "H2 stream error: test error");
    }

    // AC-1: H2Sender implements DatagramSender (compile-time + runtime check)
    #[tokio::test]
    async fn h2_sender_implements_datagram_sender() {
        let (mut send_request, _server) = h2_echo_pair().await;

        // Open a new H2 stream
        let request = Request::builder()
            .method("POST")
            .uri("https://localhost/upload")
            .body(())
            .expect("build request");
        let (response_future, send_stream) = send_request.send_request(request, false).expect("send request");

        let sender = H2Sender::new(send_stream);

        // Verify it satisfies DatagramSender via trait object
        let sender_ref: &dyn DatagramSender = &sender;
        let result = sender_ref.send_datagram(b"hello h2");
        assert!(result.is_ok(), "send_datagram should succeed: {result:?}");

        // Drop to avoid warnings
        drop(response_future);
    }

    // AC-2: H2Receiver implements DatagramReceiver (compile-time + runtime check)
    #[tokio::test]
    async fn h2_receiver_implements_datagram_receiver() {
        let (mut send_request, _server) = h2_echo_pair().await;

        // Open a stream and send a HARP DATA frame
        let request = Request::builder()
            .method("POST")
            .uri("https://localhost/echo")
            .body(())
            .expect("build request");
        let (response_future, mut send_stream) = send_request.send_request(request, false).expect("send request");

        // Send a HARP frame via H2
        let frame = HarpFrame::data(b"test payload".to_vec());
        let wire = frame.encode().expect("encode");
        send_stream.send_data(Bytes::from(wire), false).expect("h2 send");

        // Get the response stream (server echoes back)
        let response = response_future.await.expect("response");
        let recv_stream = response.into_body();

        let receiver = H2Receiver::new(recv_stream);

        // Verify it satisfies DatagramReceiver
        let result = receiver.recv_datagram().await;
        assert!(result.is_ok(), "recv_datagram should succeed: {result:?}");
        assert_eq!(result.unwrap(), b"test payload");
    }

    // AC-3: Round-trip send through H2Sender, receive through H2Receiver
    #[tokio::test]
    async fn h2_round_trip_send_receive() {
        let (mut send_request, _server) = h2_echo_pair().await;

        let request = Request::builder()
            .method("POST")
            .uri("https://localhost/roundtrip")
            .body(())
            .expect("build request");
        let (response_future, send_stream) = send_request.send_request(request, false).expect("send request");

        let sender = H2Sender::new(send_stream);
        let payload = b"round-trip-test-data";
        sender.send_datagram(payload).expect("send_datagram");

        let response = response_future.await.expect("response");
        let recv_stream = response.into_body();
        let receiver = H2Receiver::new(recv_stream);

        let received = receiver.recv_datagram().await.expect("recv_datagram");
        assert_eq!(received, payload);
    }

    // AC-3 extended: Multiple round-trips through same H2 stream
    #[tokio::test]
    async fn h2_multiple_round_trips() {
        let (mut send_request, _server) = h2_echo_pair().await;

        let request = Request::builder()
            .method("POST")
            .uri("https://localhost/multi")
            .body(())
            .expect("build request");
        let (response_future, send_stream) = send_request.send_request(request, false).expect("send request");

        let sender = H2Sender::new(send_stream);

        let packet_count: usize = 5;
        for i in 0..packet_count {
            let msg = format!("packet-{i}");
            sender.send_datagram(msg.as_bytes()).expect("send_datagram");
        }

        let response = response_future.await.expect("response");
        let receiver = H2Receiver::new(response.into_body());

        for i in 0..packet_count {
            let expected = format!("packet-{i}");
            let received = receiver.recv_datagram().await.expect("recv_datagram");
            assert_eq!(received, expected.as_bytes(), "mismatch at packet {i}");
        }
    }

    // AC-4: Receiver skips KEEPALIVE frames
    #[tokio::test]
    async fn h2_receiver_skips_keepalive() {
        let (mut send_request, _server) = h2_echo_pair().await;

        let request = Request::builder()
            .method("POST")
            .uri("https://localhost/keepalive")
            .body(())
            .expect("build request");
        let (response_future, mut send_stream) = send_request.send_request(request, false).expect("send request");

        // Send a KEEPALIVE frame followed by a DATA frame
        let keepalive_wire = HarpFrame::keepalive().encode().expect("encode keepalive");
        send_stream.send_data(Bytes::from(keepalive_wire), false).expect("send keepalive");

        let data_payload = b"after-keepalive".to_vec();
        let data_wire = HarpFrame::data(data_payload.clone()).encode().expect("encode data");
        send_stream.send_data(Bytes::from(data_wire), false).expect("send data");

        let response = response_future.await.expect("response");
        let receiver = H2Receiver::new(response.into_body());

        // Receiver should skip keepalive and return the data payload
        let received = receiver.recv_datagram().await.expect("recv_datagram");
        assert_eq!(received, data_payload);
    }

    // AC-5: Receiver returns HarpSessionClosed on CLOSE frame
    #[tokio::test]
    async fn h2_receiver_errors_on_close() {
        let (mut send_request, _server) = h2_echo_pair().await;

        let request = Request::builder()
            .method("POST")
            .uri("https://localhost/close")
            .body(())
            .expect("build request");
        let (response_future, mut send_stream) = send_request.send_request(request, false).expect("send request");

        // Send a CLOSE frame
        let close_wire = HarpFrame::close().encode().expect("encode close");
        send_stream.send_data(Bytes::from(close_wire), false).expect("send close");

        let response = response_future.await.expect("response");
        let receiver = H2Receiver::new(response.into_body());

        let result = receiver.recv_datagram().await;
        assert!(
            matches!(result, Err(TransportError::HarpSessionClosed)),
            "expected HarpSessionClosed, got {result:?}"
        );
    }

    // AC-6: Receiver returns HarpChannelClosed when H2 stream ends
    #[tokio::test]
    async fn h2_receiver_errors_on_stream_end() {
        let (mut send_request, _server) = h2_echo_pair().await;

        let request = Request::builder()
            .method("POST")
            .uri("https://localhost/streamend")
            .body(())
            .expect("build request");
        let (response_future, mut send_stream) = send_request.send_request(request, false).expect("send request");

        // Send empty data with end_of_stream=true to close the request body
        send_stream.send_data(Bytes::new(), true).expect("send eos");

        let response = response_future.await.expect("response");
        let receiver = H2Receiver::new(response.into_body());

        let result = receiver.recv_datagram().await;
        assert!(
            matches!(result, Err(TransportError::HarpChannelClosed)),
            "expected HarpChannelClosed, got {result:?}"
        );
    }

    // AC-9: HARP frame encoding is preserved across H2 DATA framing
    #[tokio::test]
    async fn h2_frame_encoding_preserved() {
        let (mut send_request, _server) = h2_echo_pair().await;

        let request = Request::builder()
            .method("POST")
            .uri("https://localhost/encoding")
            .body(())
            .expect("build request");
        let (response_future, mut send_stream) = send_request.send_request(request, false).expect("send request");

        // Send raw HARP wire bytes through H2, verify they decode correctly on the other side
        let original_payload = vec![0xAA; 1024];
        let frame = HarpFrame::data(original_payload.clone());
        let wire = frame.encode().expect("encode");
        send_stream.send_data(Bytes::from(wire), false).expect("h2 send");

        let response = response_future.await.expect("response");
        let receiver = H2Receiver::new(response.into_body());

        let received = receiver.recv_datagram().await.expect("recv_datagram");
        assert_eq!(received, original_payload);
    }

    // AC-7: Sender returns H2Stream error when H2 send fails
    #[tokio::test]
    async fn h2_sender_errors_on_stream_failure() {
        let (mut send_request, _server) = h2_echo_pair().await;

        let request = Request::builder()
            .method("POST")
            .uri("https://localhost/fail")
            .body(())
            .expect("build request");
        let (_response_future, mut send_stream) = send_request.send_request(request, false).expect("send request");

        // Close the stream with end_of_stream=true
        send_stream.send_data(Bytes::new(), true).expect("send eos");

        let sender = H2Sender::new(send_stream);

        // Sending after end-of-stream should fail with H2Stream error
        let result = sender.send_datagram(b"after-eos");
        assert!(
            matches!(result, Err(TransportError::H2Stream(_))),
            "expected H2Stream error, got {result:?}"
        );
    }

    // AC-8: Receiver releases flow control capacity after each data chunk
    //
    // We verify this indirectly: if flow control is NOT released, the sender
    // will eventually stall because the window fills up. By sending many frames
    // totaling more than the default 64KB window, we prove release_capacity works.
    #[tokio::test]
    async fn h2_receiver_releases_capacity() {
        let (mut send_request, _server) = h2_echo_pair().await;

        let request = Request::builder()
            .method("POST")
            .uri("https://localhost/flowcontrol")
            .body(())
            .expect("build request");
        let (response_future, send_stream) = send_request.send_request(request, false).expect("send request");

        let sender = H2Sender::new(send_stream);

        // Send enough data to exceed the default 64KB H2 window.
        // Each HARP frame has 4-byte header + payload.
        let chunk_size: usize = 4096;
        let chunk_count: usize = 20; // 20 * 4096 = ~80KB > 64KB window
        for i in 0..chunk_count {
            let payload = vec![(i & 0xFF) as u8; chunk_size];
            sender.send_datagram(&payload).expect("send_datagram");
        }

        let response = response_future.await.expect("response");
        let receiver = H2Receiver::new(response.into_body());

        // Receive all frames — if flow control wasn't released, this would hang
        for i in 0..chunk_count {
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), receiver.recv_datagram())
                .await
                .expect("timeout: flow control may not be released")
                .expect("recv_datagram");
            assert_eq!(result.len(), chunk_size, "wrong size at frame {i}");
            assert_eq!(result[0], (i & 0xFF) as u8, "wrong content at frame {i}");
        }
    }
}
