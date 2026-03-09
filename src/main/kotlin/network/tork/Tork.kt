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
            output = if (action == GovernanceAction.REDACT) {
                PiiDetector.redact(text)
            } else {
                text
            }
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
