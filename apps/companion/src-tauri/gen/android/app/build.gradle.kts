import java.security.MessageDigest
import java.util.Properties
import javax.inject.Inject
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.api.attributes.Attribute
import org.gradle.process.ExecOperations

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

/**
 * The application's hand-written Android sources -- the push receiver, the background worker, the
 * keystore reader and everything else that needs the framework -- kept outside this generated
 * directory so regenerating the project never touches them.
 *
 * The directory is checked here, at configuration time, because Gradle treats a source directory
 * that does not exist as an empty one. A path that resolves nowhere compiles nothing, packages
 * nothing and still reports a successful build, so a mistake in it is otherwise silent: the
 * application loses its push receiver and no build output says so. A wrong path fails here, by
 * name, instead.
 */
val handWrittenNativeSources = file("../../../../native/android/android/src/main/java")
check(handWrittenNativeSources.isDirectory) {
    "The application's hand-written Android sources are not at $handWrittenNativeSources"
}

/**
 * The tests of those sources that need an Android device: the voice call against a peer in the same
 * process. Checked for the same reason as the sources are.
 */
val handWrittenNativeDeviceTests = file("../../../../native/android/android/src/androidTest/kotlin")
check(handWrittenNativeDeviceTests.isDirectory) {
    "The application's hand-written Android device tests are not at $handWrittenNativeDeviceTests"
}

/**
 * Firebase's configuration, as the string resources Firebase reads at start.
 *
 * It belongs to the account that owns the Firebase project, so it is made from the file
 * `KR_GOOGLE_SERVICES_JSON` names (`scripts/firebase-android-configuration.mjs`): a debug build with
 * no file leaves Firebase alone, a file that cannot be used fails the build, and a release build with
 * no file fails. The resources go to a directory of the build's own, so a build with no file carries
 * none from another.
 */
abstract class FirebaseResources : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val script: RegularFileProperty

    @get:Input
    abstract val buildType: Property<String>

    @get:Input
    abstract val applicationId: Property<String>

    @get:OutputDirectory
    abstract val output: DirectoryProperty

    @get:Inject
    abstract val exec: ExecOperations

    @TaskAction
    fun generate() {
        exec.exec {
            commandLine(
                "node", script.get().asFile.path, output.get().asFile.path,
                buildType.get(), applicationId.get(),
            )
        }
    }
}

androidComponents {
    onVariants { variant ->
        val generate = tasks.register<FirebaseResources>(
            "generateFirebaseResources" + variant.name.replaceFirstChar { it.uppercase() }
        ) {
            script.set(file("../../../../scripts/firebase-android-configuration.mjs"))
            buildType.set(variant.buildType ?: "debug")
            applicationId.set("to.kala.reach")
            inputs.property("file", providers.environmentVariable("KR_GOOGLE_SERVICES_JSON").orElse(""))
            outputs.upToDateWhen { false }
        }
        variant.sources.res?.addGeneratedSourceDirectory(generate, FirebaseResources::output)
    }
}

android {
    compileSdk = 36
    // Android 15 and later run with 16 KB memory pages, and a library linked for 4 KB pages is
    // refused. This is the first toolchain whose linker aligns to 16 KB by default, so it is named
    // rather than left to whichever one happens to be installed.
    ndkVersion = "28.2.13676358"
    namespace = "to.kala.reach"
    defaultConfig {
        manifestPlaceholders["usesCleartextTraffic"] = "false"
        applicationId = "to.kala.reach"
        minSdk = 29
        targetSdk = 36
        versionCode = tauriProperties.getProperty("tauri.android.versionCode", "1").toInt()
        versionName = tauriProperties.getProperty("tauri.android.versionName", "1.0")
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    buildTypes {
        getByName("debug") {
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            isDebuggable = true
            isJniDebuggable = true
            isMinifyEnabled = false
            packaging {                jniLibs.keepDebugSymbols.add("*/arm64-v8a/*.so")
                jniLibs.keepDebugSymbols.add("*/armeabi-v7a/*.so")
                jniLibs.keepDebugSymbols.add("*/x86/*.so")
                jniLibs.keepDebugSymbols.add("*/x86_64/*.so")
            }
        }
        getByName("release") {
            isMinifyEnabled = true
            proguardFiles(
                *fileTree(".") { include("**/*.pro") }
                    .plus(getDefaultProguardFile("proguard-android-optimize.txt"))
                    .toList().toTypedArray()
            )
        }
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    buildFeatures {
        buildConfig = true
    }
    sourceSets {
        getByName("main").java.srcDir(handWrittenNativeSources)
        getByName("androidTest").java.srcDir(handWrittenNativeDeviceTests)
    }
}

rust {
    rootDirRel = "../../../"
}

dependencies {
    // The decisions the receiver and the worker make, as plain Kotlin with its own tests.
    implementation(project(":krnative"))
    // Native WebRTC. Section 15 paragraph 2 requires native WebRTC and native platform audio to own
    // capture and playback, so the application links the library itself rather than reaching a
    // WebView's `getUserMedia`. The constraint is strict rather than a plain version: a checksum
    // verifies bytes, and only a strict constraint stops conflict resolution raising the version
    // that is fetched. This artefact's PT_LOAD segments align to 16 KiB, which is what Android 15
    // and later require.
    implementation("io.github.webrtc-sdk:android") { version { strictly("150.7871.01") } }
    // The device-owner ceremony an unlocked-screen confirmation needs, with the device-credential
    // fallback for a device that has no biometric enrolled.
    implementation("androidx.biometric:biometric:1.2.0-alpha05")
    // Push, and the scheduler that runs what a message callback cannot finish in its budget.
    implementation("com.google.firebase:firebase-messaging:24.1.2")
    implementation("androidx.work:work-runtime-ktx:2.10.1")
    // Keys wrapped by the hardware-backed keystore, which is where a preview key belongs.
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("androidx.webkit:webkit:1.14.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.lifecycle:lifecycle-process:2.10.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.4")
    androidTestImplementation("androidx.test:runner:1.5.2")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.0")
}

/*
 * What this build is allowed to link.
 *
 * A version number selects an artefact; it does not establish that the same bytes arrive next
 * time. The libraries below carry native code into the packaged application, so their bytes are
 * checked as well as their versions: the media library, and the camera library whose two native
 * libraries the scanner loads (every one of their segments aligns to 16 KiB, which Android 15 and
 * later require). Gradle's own `verification-metadata.xml` is deliberately not used: once that file
 * exists Gradle verifies every artefact in the graph and fails on any without an entry, which would
 * make one pinned library the whole build's problem. This checks the artefacts this build pinned,
 * and says plainly when it cannot find one.
 *
 * The check reads what the release build resolves for its runtime, the files it will package, and
 * not a separate resolution of the same names: a version another dependency raises is the version
 * checked.
 */
val pinnedNativeLibraries = mapOf(
    "io.github.webrtc-sdk:android:150.7871.01" to
        "0a1627b1a48c2bc17d9a40d62fc47bd45166f44a311e95917f147c402de379b0",
    "androidx.camera:camera-core:1.4.2" to
        "bbca13760ce1587502eb15723d0e17fa0a3495d084e609c4e4c8d3c2e1c85cf8",
    // The verifier's Kotlin half carries no native code, but it is fetched from a repository this
    // project does not run, and it decides which certificates the application trusts.
    "org.rustls:rustls-platform-verifier:0.2.0" to
        "aa021794230fbc2f0be355999e2cf67398dd563de066a2e17001ffbd0b69101b",
)

/*
 * The verifier's Kotlin half and its Rust crate are one component, and the version of the one is
 * the lock's for the other: the root build reads it from `Cargo.lock`, and the plugin links exactly
 * that. A lock that names a version this build holds no digest for stops the build.
 */
val rustlsPlatformVerifierKotlinVersion = rootProject.extra["rustlsPlatformVerifierKotlinVersion"] as String

afterEvaluate {
    val verifyNativeLibraries by tasks.registering {
        description = "Checks each native library's bytes against the digest this build pins."
        doLast {
            val verifier = "org.rustls:rustls-platform-verifier:$rustlsPlatformVerifierKotlinVersion"
            if (verifier !in pinnedNativeLibraries) {
                throw GradleException(
                    "Cargo.lock holds the platform verifier's Kotlin half at $rustlsPlatformVerifierKotlinVersion, " +
                        "and this build pins no digest for it"
                )
            }
            // What each variant this build makes links for its runtime: the files it packages. A
            // variant is a build type, debug or release, of one of the application's ABI flavors.
            val variantClasspath = Regex("^[a-z0-9]*(Debug|Release)RuntimeClasspath$", RegexOption.IGNORE_CASE)
            val classpaths = configurations.filter { it.isCanBeResolved && variantClasspath.matches(it.name) }
            if (classpaths.isEmpty()) throw GradleException("this build has no runtime classpath to check")
            for (classpath in classpaths) {
                // The published archives, as the classpath resolves them: the modules from the
                // repositories, in the form they are fetched in, and not the project's own.
                val linked = classpath.incoming.artifactView {
                    isLenient = true
                    componentFilter { it is ModuleComponentIdentifier }
                    attributes { attribute(Attribute.of("artifactType", String::class.java), "aar") }
                }.artifacts.artifacts.associate { artifact ->
                    val module = artifact.id.componentIdentifier as ModuleComponentIdentifier
                    "${module.group}:${module.module}:${module.version}" to artifact.file
                }
                for ((coordinates, pinned) in pinnedNativeLibraries) {
                    val file = linked[coordinates]
                        ?: throw GradleException("${classpath.name} does not link $coordinates, which this build pins")
                    val digestBytes = MessageDigest.getInstance("SHA-256").digest(file.readBytes())
                    val digest = digestBytes.joinToString("") { b -> "%02x".format(b) }
                    if (digest != pinned) {
                        throw GradleException(
                            "the bytes of $coordinates are not the ones this build pins: expected " +
                                "$pinned, found $digest"
                        )
                    }
                }
            }
        }
    }

    tasks.named("preBuild") { dependsOn(verifyNativeLibraries) }
}

apply(from = "tauri.build.gradle.kts")