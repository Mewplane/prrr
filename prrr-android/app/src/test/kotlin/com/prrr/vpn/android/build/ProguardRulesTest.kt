// FRD: specs/frds/FRD-M014-android-internal-testing.md
package com.prrr.vpn.android.build

import org.junit.Test
import org.junit.Assert.assertTrue
import java.io.File

/**
 * Validates that ProGuard/R8 rules contain all required keep patterns
 * to prevent stripping of critical runtime classes.
 */
class ProguardRulesTest {

    companion object {
        private const val PROGUARD_FILE_NAME = "proguard-rules.pro"
        private const val UNIFFI_KEEP_PATTERN = "-keep class uniffi.**"
        private const val JNA_KEEP_PATTERN = "-keep class com.sun.jna.**"
        private const val JNA_LIBRARY_KEEP_PATTERN = "com.sun.jna.Library"
        private const val KOTLIN_COROUTINES_KEEP_PATTERN = "kotlinx.coroutines"
        private const val PRRR_MOBILE_KEEP_PATTERN = "-keep class com.prrr.mobile.**"
        private const val MAPPING_FILE_PATTERN = "-printmapping"
    }

    private fun loadProguardRules(): String {
        // Walk up from test class location to find project root
        val projectDir = File(System.getProperty("user.dir"))
        val proguardFile = File(projectDir, "app/$PROGUARD_FILE_NAME")
        val altProguardFile = File(projectDir, PROGUARD_FILE_NAME)

        val file = when {
            proguardFile.exists() -> proguardFile
            altProguardFile.exists() -> altProguardFile
            else -> error("ProGuard rules file not found at ${proguardFile.absolutePath} or ${altProguardFile.absolutePath}")
        }
        return file.readText()
    }

    @Test
    fun testProguardRulesContainUniffiKeep() {
        val rules = loadProguardRules()
        assertTrue(
            "ProGuard rules must keep UniFFI generated classes",
            rules.contains(UNIFFI_KEEP_PATTERN)
        )
    }

    @Test
    fun testProguardRulesContainJnaKeep() {
        val rules = loadProguardRules()
        assertTrue(
            "ProGuard rules must keep JNA classes",
            rules.contains(JNA_KEEP_PATTERN)
        )
    }

    @Test
    fun testProguardRulesContainJnaLibraryKeep() {
        val rules = loadProguardRules()
        assertTrue(
            "ProGuard rules must keep JNA Library implementors",
            rules.contains(JNA_LIBRARY_KEEP_PATTERN)
        )
    }

    @Test
    fun testProguardRulesContainKotlinCoroutinesKeep() {
        val rules = loadProguardRules()
        assertTrue(
            "ProGuard rules must keep Kotlin coroutines infrastructure",
            rules.contains(KOTLIN_COROUTINES_KEEP_PATTERN)
        )
    }

    @Test
    fun testProguardRulesContainPrrrMobileKeep() {
        val rules = loadProguardRules()
        assertTrue(
            "ProGuard rules must keep prrr mobile classes",
            rules.contains(PRRR_MOBILE_KEEP_PATTERN)
        )
    }

    @Test
    fun testProguardRulesContainMappingFileOutput() {
        val rules = loadProguardRules()
        assertTrue(
            "ProGuard rules must output mapping file for crash deobfuscation",
            rules.contains(MAPPING_FILE_PATTERN)
        )
    }
}
