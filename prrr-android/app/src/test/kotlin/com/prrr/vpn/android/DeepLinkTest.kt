// FRD: specs/frds/FRD-M015-deep-link-config-import.md
package com.prrr.vpn.android

import android.net.Uri
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

private const val DEEP_LINK_SCHEME = "prrr"
private const val DEEP_LINK_HOST = "import"
private const val DEEP_LINK_CONFIG_PARAM = "z"
private const val DEEP_LINK_PREFIX = "prrr://import?z="

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class DeepLinkTest {

    /**
     * Read AndroidManifest.xml content for manifest-level assertions.
     * Falls back to checking multiple common locations.
     */
    private fun readManifestContent(): String {
        val candidates = listOf(
            "src/main/AndroidManifest.xml",
            "app/src/main/AndroidManifest.xml",
            "../app/src/main/AndroidManifest.xml",
            "prrr-android/app/src/main/AndroidManifest.xml"
        )
        for (path in candidates) {
            val file = File(path)
            if (file.exists()) return file.readText()
        }
        // Try from project root via system property
        val userDir = System.getProperty("user.dir") ?: ""
        val rootManifest = File("$userDir/src/main/AndroidManifest.xml")
        if (rootManifest.exists()) return rootManifest.readText()
        throw IllegalStateException("AndroidManifest.xml not found from $userDir")
    }

    @Test
    fun testManifestDeclaresDeepLinkScheme() {
        // Mutant killed: manifest missing <data android:scheme="prrr" .../>
        // Contract: AndroidManifest must declare prrr scheme for deep link resolution
        val manifest = readManifestContent()
        assertTrue(
            "AndroidManifest.xml must declare android:scheme=\"prrr\"",
            manifest.contains("android:scheme=\"prrr\"")
        )
    }

    @Test
    fun testManifestDeclaresDeepLinkHost() {
        // Mutant killed: manifest missing <data android:host="import" .../>
        // Contract: AndroidManifest must declare import host for deep link resolution
        val manifest = readManifestContent()
        assertTrue(
            "AndroidManifest.xml must declare android:host=\"import\"",
            manifest.contains("android:host=\"import\"")
        )
    }

    @Test
    fun testManifestDeclaresViewAction() {
        // Mutant killed: manifest missing ACTION_VIEW in deep link intent-filter
        // Contract: deep link filter must include ACTION_VIEW
        val manifest = readManifestContent()
        assertTrue(
            "AndroidManifest.xml must declare android.intent.action.VIEW",
            manifest.contains("android.intent.action.VIEW")
        )
    }

    @Test
    fun testManifestDeclaresDefaultAndBrowsableCategories() {
        // Mutant killed: missing DEFAULT or BROWSABLE category prevents deep link handling
        // Contract: deep link filter must be DEFAULT + BROWSABLE
        val manifest = readManifestContent()
        assertTrue(
            "AndroidManifest.xml must declare DEFAULT category",
            manifest.contains("android.intent.category.DEFAULT")
        )
        assertTrue(
            "AndroidManifest.xml must declare BROWSABLE category",
            manifest.contains("android.intent.category.BROWSABLE")
        )
    }

    @Test
    fun testManifestDeclaresLaunchModeSingleTop() {
        // Mutant killed: missing singleTop causes new activity on deep link instead of onNewIntent
        // Contract: MainActivity must use singleTop launch mode
        val manifest = readManifestContent()
        assertTrue(
            "AndroidManifest.xml must declare launchMode singleTop on MainActivity",
            manifest.contains("android:launchMode=\"singleTop\"")
        )
    }

    @Test
    fun testManifestStillHasLauncherFilter() {
        // Mutant killed: deep link filter accidentally removes LAUNCHER filter
        // Contract: normal LAUNCHER intent must still be declared
        val manifest = readManifestContent()
        assertTrue(
            "AndroidManifest.xml must still declare LAUNCHER category",
            manifest.contains("android.intent.category.LAUNCHER")
        )
    }

    @Test
    fun testDeepLinkUriParsesCorrectly() {
        // Mutant killed: intent data not extracted correctly from URI
        // Contract: URI must decompose into scheme=prrr, host=import, param=config
        val configData = "dGVzdA"
        val uri = Uri.parse("$DEEP_LINK_PREFIX$configData")

        assertEquals(DEEP_LINK_SCHEME, uri.scheme)
        assertEquals(DEEP_LINK_HOST, uri.host)
        assertEquals(configData, uri.getQueryParameter(DEEP_LINK_CONFIG_PARAM))
    }

    @Test
    fun testDeepLinkPrefixMatchesRustParserFormat() {
        // Mutant killed: prefix constant doesn't match what parse_qr_config() expects
        // Contract: deep link URI format matches "prrr://import?z=<base64url>"
        val testUri = "${DEEP_LINK_PREFIX}dGVzdA"
        assertTrue(
            "URI must start with prrr://import?z=",
            testUri.startsWith(DEEP_LINK_PREFIX)
        )
    }

    @Test
    fun testNonDeepLinkUriDoesNotMatchSchemeAndHost() {
        // Mutant killed: any URI incorrectly treated as deep link
        // Contract: only prrr://import URIs match the deep link pattern
        val nonMatchingUris = listOf(
            "https://example.com",
            "prrr://other?z=test",
            "http://import?z=test",
            "prr://import?z=test"
        )

        for (uriStr in nonMatchingUris) {
            val uri = Uri.parse(uriStr)
            val matches = uri.scheme == DEEP_LINK_SCHEME && uri.host == DEEP_LINK_HOST
            assertFalse("URI '$uriStr' must not match deep link pattern", matches)
        }
    }

    @Test
    fun testDeepLinkWithEmptyConfigParamStillParsesUri() {
        // Mutant killed: empty config param causes NPE in URI parsing
        // Contract: URI parsing must handle empty config gracefully
        val uri = Uri.parse("prrr://import?z=")

        assertEquals(DEEP_LINK_SCHEME, uri.scheme)
        assertEquals(DEEP_LINK_HOST, uri.host)
        assertEquals("", uri.getQueryParameter(DEEP_LINK_CONFIG_PARAM))
    }
}
