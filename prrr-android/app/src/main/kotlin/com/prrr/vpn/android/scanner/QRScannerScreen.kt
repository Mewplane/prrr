// FRD: specs/frds/FRD-M009-qr-code-scanner.md
package com.prrr.vpn.android.scanner

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel

/**
 * QR Scanner screen with camera preview and permission handling.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QRScannerScreen(
    onConfigScanned: (uniffi.prrr_mobile.VpnConfig) -> Unit,
    onNavigateBack: () -> Unit,
    viewModel: QRScanViewModel = viewModel()
) {
    val context = LocalContext.current
    val scanState by viewModel.scanState.collectAsState()

    var hasCameraPermission by remember { mutableStateOf(false) }
    var showPermissionRationale by remember { mutableStateOf(false) }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        hasCameraPermission = isGranted
        if (!isGranted) {
            showPermissionRationale = true
        }
    }

    LaunchedEffect(Unit) {
        permissionLauncher.launch(Manifest.permission.CAMERA)
    }

    // Handle scan success
    LaunchedEffect(scanState) {
        if (scanState is ScanState.Success) {
            onConfigScanned((scanState as ScanState.Success).config)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Scan QR Code") },
                navigationIcon = {
                    TextButton(onClick = onNavigateBack) {
                        Text("Cancel")
                    }
                }
            )
        }
    ) { paddingValues ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
        ) {
            when {
                !hasCameraPermission -> {
                    PermissionDeniedContent(
                        showRationale = showPermissionRationale,
                        onRequestPermission = {
                            permissionLauncher.launch(Manifest.permission.CAMERA)
                        },
                        onOpenSettings = {
                            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                data = Uri.fromParts("package", context.packageName, null)
                            }
                            context.startActivity(intent)
                        }
                    )
                }

                scanState is ScanState.Error -> {
                    ErrorContent(
                        message = (scanState as ScanState.Error).message,
                        onRetry = {
                            viewModel.resetState()
                        }
                    )
                }

                else -> {
                    CameraPreviewView(
                        onQRCodeDetected = { rawValue ->
                            viewModel.onQRCodeDetected(rawValue)
                        },
                        modifier = Modifier.fillMaxSize()
                    )

                    // Scanning overlay
                    ScanningOverlay(isScanning = scanState is ScanState.Scanning)
                }
            }
        }
    }
}

@Composable
private fun PermissionDeniedContent(
    showRationale: Boolean,
    onRequestPermission: () -> Unit,
    onOpenSettings: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Camera Access Required",
            style = MaterialTheme.typography.headlineSmall,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Camera access is needed to scan QR codes for VPN configuration.",
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(24.dp))

        if (showRationale) {
            Button(onClick = onOpenSettings) {
                Text("Open Settings")
            }
        } else {
            Button(onClick = onRequestPermission) {
                Text("Grant Permission")
            }
        }
    }
}

@Composable
private fun ErrorContent(
    message: String,
    onRetry: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Scan Failed",
            style = MaterialTheme.typography.headlineSmall,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = message,
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.error
        )

        Spacer(modifier = Modifier.height(24.dp))

        Button(onClick = onRetry) {
            Text("Scan Again")
        }
    }
}

@Composable
private fun ScanningOverlay(isScanning: Boolean) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        // Semi-transparent overlay
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color.Black.copy(alpha = 0.3f))
        )

        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            // Scanning frame indicator
            Box(
                modifier = Modifier
                    .size(250.dp)
                    .background(Color.Transparent)
            ) {
                // Corner indicators
                Canvas(modifier = Modifier.fillMaxSize()) {
                    val cornerLength = 40.dp.toPx()
                    val strokeWidth = 4.dp.toPx()
                    val color = Color.White

                    // Top-left
                    drawLine(color, Offset(0f, 0f), Offset(cornerLength, 0f), strokeWidth)
                    drawLine(color, Offset(0f, 0f), Offset(0f, cornerLength), strokeWidth)

                    // Top-right
                    drawLine(color, Offset(size.width - cornerLength, 0f), Offset(size.width, 0f), strokeWidth)
                    drawLine(color, Offset(size.width, 0f), Offset(size.width, cornerLength), strokeWidth)

                    // Bottom-left
                    drawLine(color, Offset(0f, size.height - cornerLength), Offset(0f, size.height), strokeWidth)
                    drawLine(color, Offset(0f, size.height), Offset(cornerLength, size.height), strokeWidth)

                    // Bottom-right
                    drawLine(color, Offset(size.width, size.height - cornerLength), Offset(size.width, size.height), strokeWidth)
                    drawLine(color, Offset(size.width - cornerLength, size.height), Offset(size.width, size.height), strokeWidth)
                }
            }

            Spacer(modifier = Modifier.height(32.dp))

            if (isScanning) {
                CircularProgressIndicator(color = Color.White)
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = "Processing...",
                    color = Color.White,
                    style = MaterialTheme.typography.bodyLarge
                )
            } else {
                Text(
                    text = "Point camera at QR code",
                    color = Color.White,
                    style = MaterialTheme.typography.bodyLarge
                )
            }
        }
    }
}
