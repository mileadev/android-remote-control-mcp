package com.danielealbano.androidremotecontrolmcp.services.storage

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.provider.MediaStore
import android.util.Log
import com.danielealbano.androidremotecontrolmcp.data.model.ServerConfig
import com.danielealbano.androidremotecontrolmcp.mcp.McpToolException

/**
 * Streams a download into a pending MediaStore entry, clearing IS_PENDING on success and
 * deleting the entry on any failure. Network behavior is delegated to [DownloadEngine];
 * logs never include the (possibly secret-carrying) URL.
 */
internal class MediaStoreDownloader(
    private val context: Context,
    private val downloadEngine: DownloadEngine = DownloadEngine(SecureDownloadTransportFactory()),
) {
    @Suppress("TooGenericExceptionCaught")
    fun downloadToPendingUri(
        insertUri: Uri,
        url: String,
        config: ServerConfig,
        logContext: String,
    ): Long =
        try {
            val totalBytesWritten =
                downloadEngine.download(url, config) {
                    context.contentResolver.openOutputStream(insertUri, WRITE_TRUNCATE)
                }
            markDownloadComplete(insertUri)
            Log.i(TAG, "Downloaded $totalBytesWritten bytes to $logContext")
            totalBytesWritten
        } catch (e: McpToolException) {
            context.contentResolver.delete(insertUri, null, null)
            throw e
        } catch (e: Exception) {
            // Storage-layer failures (ContentResolver/ContentValues) are normalized like
            // network failures so callers only ever see McpToolException.
            context.contentResolver.delete(insertUri, null, null)
            throw McpToolException.ActionFailed(
                "Download failed: ${e.message ?: "Unknown error"}",
                e,
            )
        }

    private fun markDownloadComplete(insertUri: Uri) {
        // Clear IS_PENDING on success
        val updateValues =
            ContentValues().apply {
                put(MediaStore.MediaColumns.IS_PENDING, 0)
            }
        context.contentResolver.update(insertUri, updateValues, null, null)
    }

    companion object {
        private const val TAG = "MCP:MediaStoreDownload"
        private const val WRITE_TRUNCATE = "wt"
    }
}
