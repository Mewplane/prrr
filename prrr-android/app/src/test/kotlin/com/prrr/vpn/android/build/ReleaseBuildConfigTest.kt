// FRD: specs/frds/FRD-M014-android-internal-testing.md
package com.prrr.vpn.android.build

import org.junit.Test
import org.junit.Assert.assertTrue
import java.io.File

/**
 * Validates that build.gradle.kts contains required release build configuration
 * for Play Store distribution.
 */
class ReleaseBuildConfigTest {

    companion object {
        private const val BUILD_GRADLE_FILE_NAME = "build.gradle.kts"
        private const val ALT_BUILD_GRADLE_PATH = "app/build.gradle.kts"
        private const val SIGNING_CONFIGS_PATTERN = "signingConfigs"
        private const val RELEASE_SIGNING_PATTERN = "create(\"release\")"
        private const val MINIFY_ENABLED_PATTERN = "isMinifyEnabled = true"
        private const val SHRINK_RESOURCES_PATTERN = "isShrinkResources = true"
        private const val KEYSTORE_ENV_VAR = "PRRR_KEYSTORE_PATH"
        private const val VERSION_CODE_PROPERTY = "versionCode"
        private const val VERSION_NAME_PROPERTY = "versionName"
    }

    private fun loadBuildGradle(): String {
        val projectDir = File(System.getProperty("user.dir"))
        val primaryPath = File(projectDir, BUILD_GRADLE_FILE_NAME)
        val altPath = File(projectDir, ALT_BUILD_GRADLE_PATH)

        val file = when {
            primaryPath.exists() -> primaryPath
            altPath.exists() -> altPath
            else -> error(
                "build.gradle.kts not found at ${primaryPath.absolutePath} " +
                "or ${altPath.absolutePath}"
            )
        }
        return file.readText()
    }

    @Test
    fun testBuildGradleContainsSigningConfigs() {
        val content = loadBuildGradle()
        assertTrue(
            "build.gradle.kts must define signingConfigs block",
            content.contains(SIGNING_CONFIGS_PATTERN)
        )
    }

    @Test
    fun testBuildGradleContainsReleaseSigningConfig() {
        val content = loadBuildGradle()
        assertTrue(
            "build.gradle.kts must define a release signing config",
            content.contains(RELEASE_SIGNING_PATTERN)
        )
    }

    @Test
    fun testBuildGradleContainsMinifyEnabled() {
        val content = loadBuildGradle()
        assertTrue(
            "Release build type must have R8 minification enabled",
            content.contains(MINIFY_ENABLED_PATTERN)
        )
    }

    @Test
    fun testBuildGradleContainsShrinkResources() {
        val content = loadBuildGradle()
        assertTrue(
            "Release build type must have resource shrinking enabled",
            content.contains(SHRINK_RESOURCES_PATTERN)
        )
    }

    @Test
    fun testBuildGradleUsesEnvironmentVariablesForSigning() {
        val content = loadBuildGradle()
        assertTrue(
            "Signing config must read keystore path from environment variable",
            content.contains(KEYSTORE_ENV_VAR)
        )
    }

    @Test
    fun testBuildGradleContainsVersionCode() {
        val content = loadBuildGradle()
        assertTrue(
            "build.gradle.kts must define versionCode",
            content.contains(VERSION_CODE_PROPERTY)
        )
    }

    @Test
    fun testBuildGradleContainsVersionName() {
        val content = loadBuildGradle()
        assertTrue(
            "build.gradle.kts must define versionName",
            content.contains(VERSION_NAME_PROPERTY)
        )
    }
}
