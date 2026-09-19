/*
 * The hand-written native half of the Android application, as a module of its own.
 *
 * Everything here is plain Kotlin on the Java virtual machine: what a push payload is, what a
 * notification shows and why, where a message's work runs, and what the application may sign. None
 * of it touches an Android class, so its tests run on a developer's machine and in continuous
 * integration without a device, an emulator or the application's own native library.
 *
 * The classes that do need Android -- the messaging service, the background worker, the keystore,
 * the audio session and the share sheet -- are in `android/`, compiled into the application, and
 * they call into this module for every decision.
 */

apply(plugin = "org.jetbrains.kotlin.jvm")

// The output goes under the generated Android project rather than beside these sources. The
// interface package's linter walks this directory, and a Gradle report is not source.
layout.buildDirectory.set(rootProject.layout.buildDirectory.dir("krnative"))

dependencies {
    add("testImplementation", "junit:junit:4.13.2")
}

extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension>("kotlin") {
    sourceSets["main"].kotlin.srcDir("src/main/kotlin")
    sourceSets["test"].kotlin.srcDir("src/test/kotlin")
}

tasks.withType<Test>().configureEach { useJUnit() }
