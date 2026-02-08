package network.tork

import java.security.MessageDigest
import java.time.Instant
import java.util.UUID

/**
 * Governance action taken on input.
 */
enum class GovernanceAction {
    ALLOW,
    DENY,
    REDACT,
    ESCALATE
}

/**
 * Cryptographic receipt for a governance operation.
 */
data class GovernanceReceipt(
    val receiptId: String,
    val timestamp: String,
    val inputHash: String,
    val outputHash: String,
    val piiCount: Int,
    val piiTypes: List<PiiType>,
    val action: GovernanceAction
)

/**
 * Result of a governance operation.
 */
data class GovernanceResult(
    val action: GovernanceAction,
    val output: String,
    val piiDetected: List<PiiMatch>,
    val receipt: GovernanceReceipt
)

/**
 * Builds cryptographic governance receipts.
 */
object ReceiptBuilder {

    /**
     * Build a governance receipt.
     */
    fun build(
        input: String,
        output: String,
        pii: List<PiiMatch>,
        action: GovernanceAction
    ): GovernanceReceipt {
        return GovernanceReceipt(
            receiptId = generateId(),
            timestamp = Instant.now().toString(),
            inputHash = hashText(input),
            outputHash = hashText(output),
            piiCount = pii.size,
            piiTypes = pii.map { it.type }.distinct(),
            action = action
        )
    }

    /**
     * Generate a unique receipt ID.
     */
    fun generateId(): String {
        return "rcpt_${UUID.randomUUID().toString().replace("-", "").take(32)}"
    }

    /**
     * Compute a SHA-256 hash of the given text.
     */
    fun hashText(text: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(text.toByteArray())
        val hex = hash.joinToString("") { "%02x".format(it) }
        return "sha256:$hex"
    }
}
