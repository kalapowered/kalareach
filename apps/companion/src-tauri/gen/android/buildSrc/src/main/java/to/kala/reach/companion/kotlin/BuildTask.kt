import java.io.File
import org.apache.tools.ant.taskdefs.condition.Os
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.logging.LogLevel
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.TaskAction

open class BuildTask : DefaultTask() {
    @Input
    var rootDirRel: String? = null
    @Input
    var target: String? = null
    @Input
    var release: Boolean? = null

    @TaskAction
    fun assemble() {
        val executable = """pnpm""";
        try {
            runTauriCli(executable)
        } catch (e: Exception) {
            if (Os.isFamily(Os.FAMILY_WINDOWS)) {
                // Try different Windows-specific extensions
                val fallbacks = listOf(
                    "$executable.exe",
                    "$executable.cmd",
                    "$executable.bat",
                )
                
                var lastException: Exception = e
                for (fallback in fallbacks) {
                    try {
                        runTauriCli(fallback)
                        return
                    } catch (fallbackException: Exception) {
                        lastException = fallbackException
                    }
                }
                throw lastException
            } else {
                throw e;
            }
        }
    }

    fun runTauriCli(executable: String) {
        val rootDirRel = rootDirRel ?: throw GradleException("rootDirRel cannot be null")
        val target = target ?: throw GradleException("target cannot be null")
        val release = release ?: throw GradleException("release cannot be null")
        val args = listOf("tauri", "android", "android-studio-script");

        project.exec {
            workingDir(File(project.projectDir, rootDirRel))
            executable(executable)
            // A dependency that builds a C library from source runs the archive tools it finds on
            // the path, and on a developer's machine those are the host's. The host's archiver
            // produces an empty archive for this target, the shared library then loads with
            // undefined symbols, and the application fails at start with nothing in the build
            // output to say why. Naming the toolchain's own tools is what stops that.
            archiveTools()?.let { tools ->
                environment("AR", File(tools, "llvm-ar").absolutePath)
                environment("RANLIB", File(tools, "llvm-ranlib").absolutePath)
                environment("NM", File(tools, "llvm-nm").absolutePath)
                environment("STRIP", File(tools, "llvm-strip").absolutePath)
            }
            args(args)
            if (project.logger.isEnabled(LogLevel.DEBUG)) {
                args("-vv")
            } else if (project.logger.isEnabled(LogLevel.INFO)) {
                args("-v")
            }
            if (release) {
                args("--release")
            }
            args(listOf("--target", target))
        }.assertNormalExitValue()
    }

    /// The toolchain's own binaries, or null when this build cannot find the toolchain.
    ///
    /// Null is not a failure here: the build is about to run the command line tool, which reports
    /// a missing toolchain far better than this task could.
    fun archiveTools(): File? {
        val ndk = System.getenv("NDK_HOME")
            ?: System.getenv("ANDROID_NDK_HOME")
            ?: System.getenv("ANDROID_NDK_ROOT")
            ?: return null
        val prebuilt = File(ndk, "toolchains/llvm/prebuilt")
        val host = prebuilt.listFiles()?.firstOrNull { File(it, "bin/llvm-ar").exists() }
            ?: return null
        return File(host, "bin")
    }
}