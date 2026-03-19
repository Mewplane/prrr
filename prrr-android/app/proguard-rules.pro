# FRD: specs/frds/FRD-M014-android-internal-testing.md
# ProGuard/R8 rules for prrr VPN Android app

# ===========================================================================
# UniFFI generated classes (Rust FFI bindings)
# ===========================================================================
-keep class uniffi.** { *; }
-keep class com.prrr.mobile.** { *; }

# ===========================================================================
# JNA (Java Native Access - required for UniFFI native calls)
# ===========================================================================
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.Library { *; }
-keepclassmembers class * extends com.sun.jna.** {
    public *;
}
-dontwarn com.sun.jna.**

# ===========================================================================
# Kotlin coroutines
# ===========================================================================
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}
-keep class kotlinx.coroutines.internal.MainDispatcherLoader { *; }
-keep class kotlinx.coroutines.CoroutineExceptionHandler { *; }

# ===========================================================================
# AndroidX Lifecycle (ViewModel, LiveData)
# ===========================================================================
-keep class * extends androidx.lifecycle.ViewModel { *; }

# ===========================================================================
# Google Tink / ErrorProne annotations (used by EncryptedSharedPreferences)
# ===========================================================================
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.Nullable
-dontwarn javax.annotation.concurrent.GuardedBy

# ===========================================================================
# R8 mapping file for crash report deobfuscation
# ===========================================================================
-printmapping build/outputs/mapping/release/mapping.txt
