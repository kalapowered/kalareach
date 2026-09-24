buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath("com.android.tools.build:gradle:8.11.0")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.25")
    }
}

/*
 * The platform TLS verifier's Kotlin half ships inside its Rust crate as a local Maven repository.
 * The companion's platform plugin depends on it, and the application resolves the plugin's
 * dependencies through its own repositories, so the repository is declared here for every project,
 * limited to the verifier's group. Where the crate sits on disk is asked of Cargo rather than
 * assumed.
 */
val rustlsPlatformVerifierRepository: File by lazy {
    val metadata = providers.exec {
        workingDir = file("../../../../..")
        commandLine(
            "cargo", "metadata", "--format-version", "1", "--filter-platform", "aarch64-linux-android"
        )
    }.standardOutput.asText.get()
    @Suppress("UNCHECKED_CAST")
    val packages = (groovy.json.JsonSlurper().parseText(metadata) as Map<String, Any>)["packages"]
        as List<Map<String, Any>>
    val manifest = packages.first { it["name"] == "rustls-platform-verifier-android" }["manifest_path"]
        as String
    File(File(manifest).parentFile, "maven")
}

allprojects {
    repositories {
        google()
        mavenCentral()
        maven {
            url = uri(rustlsPlatformVerifierRepository)
            metadataSources { mavenPom(); artifact() }
            content { includeGroup("rustls") }
        }
    }
}

tasks.register("clean").configure {
    delete("build")
}

