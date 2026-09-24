# Tauri instantiates the plugin by its class name, and the JVM finds the TLS verifier's native method
# by its class and method names, so neither may be renamed or removed.
-keep class to.kala.reach.platform.PlatformPlugin { *; }
-keep class to.kala.reach.platform.TlsVerifier { *; }
-keep class to.kala.reach.platform.*Arguments { *; }
