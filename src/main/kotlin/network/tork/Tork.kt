package network.tork

/**
 * Configuration for the Tork governance client.
 */
data class TorkConfig(
    val policyVersion: String = "1.0.0",
    val defaultAction: GovernanceAction = GovernanceAction.REDACT
)

/**
 * Main Tork governance client.
 *
 * Detects PII in text, applies governance policies, and generates
 * cryptographic receipts for audit trails.
 *
 * ```kotlin
 * val tork = Tork()
 * val result = tork.govern("My SSN is 123-45-6789")
 * println(result.output)  // "My SSN is [SSN_REDACTED]"
 * println(result.receipt.receiptId)  // "rcpt_..."
 * ```
 */
class Tork(val config: TorkConfig = TorkConfig()) {

    private var totalCalls: Long = 0
    private var totalPiiDetected: Long = 0

    /**
     * Apply governance rules with regional and industry-specific detection.
     *
     * @param text the text to govern
     * @param options regional, industry, and session context options
     * @return governance result with action, output, and receipt
     */
    fun govern(text: String, options: GovernOptions): GovernanceResult {
        val result = govern(text, options.sessionContext)
        return result.copy(region = options.region, industry = options.industry)
    }

    /**
     * Apply governance rules to the input text.
     *
     * Detects PII, applies the configured action (ALLOW/DENY/REDACT),
     * and returns a [GovernanceResult] with a cryptographic receipt.
     *
     * @param text the text to govern
     * @param sessionContext optional agent/session context for multi-agent tracking
     */
    fun govern(text: String, sessionContext: SessionContext? = null): GovernanceResult {
        val piiMatches = PiiDetector.detect(text)

        val action: GovernanceAction
        val output: String

        if (piiMatches.isNotEmpty()) {
            action = config.defaultAction
            output = PiiDetector.redact(text)
        } else {
            action = GovernanceAction.ALLOW
            output = text
        }

        val receipt = ReceiptBuilder.build(text, output, piiMatches, action)

        totalCalls++
        if (piiMatches.isNotEmpty()) totalPiiDetected++

        return GovernanceResult(
            action = action,
            output = output,
            piiDetected = piiMatches,
            receipt = receipt,
            sessionContext = sessionContext
        )
    }

    /**
     * Scan a tool result (MCP server response, or any external system's
     * output) for PII and prompt injection BEFORE it is appended to model
     * context, and record the scan on a receipt.
     *
     * The scan itself is the pure [ToolResultScanner.scanToolResult] --
     * on-device, synchronous, zero network calls, using the same PII
     * detector as [govern]. This method adds the receipt:
     * `receipt.toolResultScan` carries counts by kind and type, the tool
     * name, the server URI, whether the result was blocked, and the SDK
     * version. It never carries the payload, a matched substring, or a
     * location path.
     *
     * This is a CLIENT-SIDE, CLIENT-ATTESTED control: it runs in the
     * caller's process, so the receipt records `attested_by: "client"` and
     * `capture_mode: "edge"` -- Tork did not execute this scan and cannot
     * verify it ran at all. Enforcement at the gateway, where a caller
     * cannot skip the scan, is a separate and later control.
     *
     * Action mapping (fixed, NOT [config]'s defaultAction: unlike [govern],
     * this path always returns masked output when it returns any, so the
     * action must describe what actually happened to the tool result):
     * - blocked -> DENY (nothing is returned to append)
     * - injection detected -> ESCALATE (returned, flagged for a human)
     * - PII masked -> REDACT
     * - nothing found -> ALLOW
     *
     * @param input the tool result to scan
     * @param options optional scan behavior (block-on-injection, custom
     * redaction patterns, max traversal depth)
     * @return the scan result plus a receipt carrying the tool_result_scan block
     */
    fun scanToolResult(
        input: ToolResultScanInput,
        options: ToolResultScanOptions = ToolResultScanOptions()
    ): GovernedToolResultScanResult {
        val scan = ToolResultScanner.scanToolResult(input, options)

        val piiCount = ToolResultScanner.scanPIICount(scan.findings)
        val injectionCount = ToolResultScanner.scanInjectionCount(scan.findings)

        val action = when {
            scan.blocked -> GovernanceAction.DENY
            injectionCount > 0 -> GovernanceAction.ESCALATE
            piiCount > 0 -> GovernanceAction.REDACT
            else -> GovernanceAction.ALLOW
        }

        val block = ToolResultScanner.buildToolResultScanBlock(input.toolName, input.serverUri, scan, Version.SDK_VERSION)

        // Hashes, not content: hashText is SHA256, so neither the payload nor
        // the sanitized copy is recoverable from the receipt. A blocked scan
        // has no output to hash and records the hash of the empty string.
        val stableInput = ToolResultScanner.stableStringify(input.payload)
        val stableOutput = if (scan.blocked) "" else ToolResultScanner.stableStringify(scan.sanitized)

        val piiTypes = ToolResultScanner.scanPIITypes(scan.findings).mapNotNull { PiiType.fromCode(it) }

        val receipt = GovernanceReceipt(
            receiptId = ReceiptBuilder.generateId(),
            timestamp = java.time.Instant.now().toString(),
            inputHash = ReceiptBuilder.hashText(stableInput),
            outputHash = ReceiptBuilder.hashText(stableOutput),
            piiCount = piiCount,
            piiTypes = piiTypes,
            action = action,
            toolResultScan = block
        )

        totalCalls++
        if (piiCount > 0) totalPiiDetected++

        return GovernedToolResultScanResult(scan.sanitized, scan.findings, scan.blocked, scan.reason, receipt)
    }

    /** Total number of governance calls made. */
    fun getCallCount(): Long = totalCalls

    /** Total number of calls that detected PII. */
    fun getPiiDetectedCount(): Long = totalPiiDetected

    /** Reset all statistics. */
    fun resetStats() {
        totalCalls = 0
        totalPiiDetected = 0
    }
}
