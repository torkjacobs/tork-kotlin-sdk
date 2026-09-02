package network.tork

/**
 * SDK version reported on receipts (e.g. `tool_result_scan.sdk_version`).
 *
 * Kotlin/Gradle has no build-time string injection equivalent to the JS
 * SDK's tsup `define` (see tork-js-sdk/src/version.ts), so this constant is
 * hand-kept in sync with `version` in build.gradle.kts, the same discipline
 * the Java port uses for its `pom.xml`.
 */
object Version {
    /** Current SDK version. Keep in sync with build.gradle.kts's `version`. */
    const val SDK_VERSION = "0.2.0"
}
