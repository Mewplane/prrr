// FRD: specs/frds/FRD-004-client-sharing-toggle-and-remote-enable.md
package com.prrr.vpn.android.ecosystem

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import java.io.File
import uniffi.prrr_mobile.SharingStateDto
import uniffi.prrr_mobile.sharingGetState
import uniffi.prrr_mobile.sharingSetEnabled

/**
 * Signature-protected coordination surface for the client-to-client sharing
 * toggle (SPEC §3 / §9.3, decision §9.4).
 *
 * This provider is intentionally *thin*: all sharing state and enforcement
 * logic lives in the vendor-neutral Rust core ([uniffi.prrr_mobile]), which is
 * the single source of truth. The provider only marshals the toggle across the
 * signature boundary so co-signed ecosystem apps (sy / cathouse) read and
 * observe the same state with no user setup.
 *
 * Protection: declared in AndroidManifest with `android:protectionLevel`
 * `signature` via [PERMISSION_COORDINATE], so only apps co-signed with the same
 * developer key may query/update it. prrr remains the enforcement point — a
 * remote enable still requires the server-side pair authorization and the
 * per-use biometric signature, verified in the Rust core, never here.
 *
 * Query (`query`): returns a one-row cursor with [COLUMN_ENABLED] (0/1) and
 * [COLUMN_PEER_MESH_ADDR] (null until Step 5).
 * Update (`update`): set [COLUMN_ENABLED] to 0/1 to flip the local toggle.
 */
class SharingProvider : ContentProvider() {

    companion object {
        /** Signature permission guarding read/observe of the sharing state. */
        const val PERMISSION_COORDINATE = "com.prrr.vpn.android.permission.ECOSYSTEM_COORDINATE"

        /** Column carrying the enabled flag as 0 (off) or 1 (on). */
        const val COLUMN_ENABLED = "enabled"

        /** Column carrying the peer mesh address (null until Step 5). */
        const val COLUMN_PEER_MESH_ADDR = "peer_mesh_addr"

        /** App-private file holding the persisted sharing state (matches the Rust store). */
        const val STATE_FILENAME = "sharing.json"
    }

    /** Absolute path of the app-private sharing-state file passed to the Rust seam. */
    private fun statePath(): String = File(context!!.filesDir, STATE_FILENAME).absolutePath

    /** Build a one-row cursor from a [SharingStateDto]. */
    private fun cursorOf(state: SharingStateDto): Cursor {
        val cursor = MatrixCursor(arrayOf(COLUMN_ENABLED, COLUMN_PEER_MESH_ADDR))
        cursor.addRow(arrayOf(if (state.enabled) 1 else 0, state.peerMeshAddr))
        return cursor
    }

    override fun onCreate(): Boolean = true

    override fun query(
        uri: Uri,
        projection: Array<String>?,
        selection: String?,
        selectionArgs: Array<String>?,
        sortOrder: String?,
    ): Cursor = cursorOf(sharingGetState(statePath()))

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<String>?,
    ): Int {
        val enabled = values?.getAsInteger(COLUMN_ENABLED) ?: return 0
        sharingSetEnabled(statePath(), enabled != 0)
        return 1
    }

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?): Int = 0
}
