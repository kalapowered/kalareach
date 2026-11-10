# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile
# The platform TLS verifier's Kotlin half is reached over JNI by class and member name, which a
# minified build would otherwise rename or remove.
-keep, includedescriptorclasses class org.rustls.platformverifier.** { *; }
# The media library (`io.github.webrtc-sdk:android`, declared in this module's build file) is native
# code that finds its own Java classes by name: its start-up asks for `org.jni_zero.JniZero`, and the
# calls it makes into Java name a class, a method and a signature that match as strings. Its archive
# carries no rules, and no Java code reaches most of those classes, so a minified build removes or
# renames them: the library then loads, asks for a class that is gone, and the runtime aborts the
# process before the first call opens. The names native code asks for cannot be listed from the Java
# side, so both packages are kept whole, with the classes their members' signatures name. The check in
# `scripts/android-classes.mjs` reads the names out of the packaged libraries and fails when the
# dex does not define one of them.
-keep, includedescriptorclasses class org.webrtc.** { *; }
-keep, includedescriptorclasses class org.jni_zero.** { *; }
# `org.jni_zero.JniZero` refers to a class its build generates only for natives it registers, which
# its archive does not carry: the library exports its natives by name instead, and no code calls the
# method that refers to it. The debug build holds the same reference, which only a minifier that
# keeps the class reports.
-dontwarn org.jni_zero.JniZeroJni
