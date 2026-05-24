package network.tork

/**
 * Types of personally identifiable information.
 */
enum class PiiType {
    SSN,
    CREDIT_CARD,
    EMAIL,
    PHONE,
    IP_ADDRESS
}

/**
 * A detected PII match in text.
 */
data class PiiMatch(
    val type: PiiType,
    val match: String,
    val range: IntRange
)

/**
 * Detects and redacts PII in text using regex patterns.
 */
object PiiDetector {

    private val patterns: List<Triple<PiiType, Regex, String>> = listOf(
        Triple(PiiType.SSN, Regex("""\d{3}-\d{2}-\d{4}"""), "[SSN_REDACTED]"),
        Triple(PiiType.CREDIT_CARD, Regex("""\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"""), "[CARD_REDACTED]"),
        Triple(PiiType.EMAIL, Regex("""[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"""), "[EMAIL_REDACTED]"),
        Triple(PiiType.PHONE, Regex("""(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"""), "[PHONE_REDACTED]"),
        Triple(PiiType.IP_ADDRESS, Regex("""\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"""), "[IP_REDACTED]"),
    )

    /**
     * Detect all PII matches in the given text.
     */
    fun detect(text: String): List<PiiMatch> {
        val matches = mutableListOf<PiiMatch>()
        for ((type, regex, _) in patterns) {
            for (result in regex.findAll(text)) {
                matches.add(PiiMatch(type, "[REDACTED]", result.range))
            }
        }
        return matches
    }

    /**
     * Redact all PII in text, replacing matches with type-specific placeholders.
     */
    fun redact(text: String): String {
        var result = text
        for ((_, regex, replacement) in patterns) {
            result = regex.replace(result, replacement)
        }
        return result
    }
}
