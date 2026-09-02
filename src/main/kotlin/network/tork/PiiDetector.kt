package network.tork

/**
 * Types of personally identifiable information.
 *
 * Tier 1 basic vocabulary (10 types), matching tork-js-sdk/src/pii.ts's
 * `PIIType` and tork-java-sdk's `PIIType` with identical string [code]s.
 * Declaration order matters: it is the same order [PiiDetector]'s pattern
 * table iterates in, so sequential redaction sees the broad [BANK_ACCOUNT]
 * pattern last, after more specific patterns have already claimed their
 * matches (see [PiiDetector]).
 */
enum class PiiType(val code: String, val redaction: String) {
    SSN("ssn", "[SSN_REDACTED]"),
    CREDIT_CARD("credit_card", "[CARD_REDACTED]"),
    EMAIL("email", "[EMAIL_REDACTED]"),
    PHONE("phone", "[PHONE_REDACTED]"),
    ADDRESS("address", "[ADDRESS_REDACTED]"),
    IP_ADDRESS("ip_address", "[IP_REDACTED]"),
    DATE_OF_BIRTH("date_of_birth", "[DOB_REDACTED]"),
    PASSPORT("passport", "[PASSPORT_REDACTED]"),
    DRIVERS_LICENSE("drivers_license", "[DL_REDACTED]"),
    BANK_ACCOUNT("bank_account", "[ACCOUNT_REDACTED]");

    companion object {
        /** Find a [PiiType] by its [code]. */
        fun fromCode(code: String): PiiType? = entries.firstOrNull { it.code == code }
    }
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
 * Result of scanning text for PII: matches found and the text with all
 * matches redacted in place.
 */
data class PiiDetectionResult(
    val hasPii: Boolean,
    val types: Set<PiiType>,
    val matches: List<PiiMatch>,
    val redactedText: String
) {
    val count: Int get() = matches.size
}

/**
 * Detects and redacts PII in text using regex patterns.
 *
 * Patterns cover the full Tier 1 basic vocabulary (10 types), ported
 * regex-source-verbatim from tork-js-sdk/src/pii.ts's `PII_PATTERNS`, in the
 * same declaration order (ssn, credit_card, email, phone, address,
 * ip_address, date_of_birth, passport, drivers_license, bank_account) so
 * that [detect]/[redact]'s sequential per-type redaction matches the
 * JS/Java/Go SDKs' behavior: later patterns (notably `bank_account`'s broad
 * `\d{8,17}`) only see text already redacted by earlier, more specific
 * patterns.
 *
 * Parity discipline (SDK-DECLARED-PII-TYPES-WITHOUT-PATTERNS-ACROSS-SDKS):
 * every [PiiType] constant MUST have a corresponding entry in [patterns].
 * See `PiiDetectorTest.every declared PiiType has a live pattern (parity)`.
 */
object PiiDetector {

    private val patterns: List<Pair<PiiType, Regex>> = listOf(
        PiiType.SSN to Regex("""\b\d{3}-\d{2}-\d{4}\b"""),
        PiiType.CREDIT_CARD to Regex("""\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"""),
        PiiType.EMAIL to Regex("""\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"""),
        PiiType.PHONE to Regex("""\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"""),
        PiiType.ADDRESS to Regex(
            """\b\d{1,5}\s+\w+(?:\s+\w+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b""",
            RegexOption.IGNORE_CASE
        ),
        PiiType.IP_ADDRESS to Regex(
            """\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"""
        ),
        PiiType.DATE_OF_BIRTH to Regex("""\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b"""),
        PiiType.PASSPORT to Regex("""\b[A-Z]{1,2}\d{6,9}\b"""),
        PiiType.DRIVERS_LICENSE to Regex("""\b[A-Z]\d{7,14}\b"""),
        PiiType.BANK_ACCOUNT to Regex("""\b\d{8,17}\b""")
    )

    /**
     * The live pattern table, keyed by [PiiType]. Exposed for parity testing
     * (every declared [PiiType] must have an entry here) and for reuse by
     * other on-device scanners (e.g. tool-result scanning) so there is
     * exactly one detector implementation, not a second copy of these
     * patterns.
     */
    fun getPatterns(): Map<PiiType, Regex> = patterns.toMap()

    /**
     * Detect all PII matches in the given text.
     *
     * Each pattern is matched against the original [text] independently, so
     * a substring that satisfies more than one pattern (e.g. a dash-free
     * card number that also fits [PiiType.BANK_ACCOUNT]) can be reported
     * under more than one type -- matching the JS/Java SDKs' behavior.
     */
    fun detect(text: String): List<PiiMatch> {
        val matches = mutableListOf<PiiMatch>()
        for ((type, regex) in patterns) {
            for (result in regex.findAll(text)) {
                matches.add(PiiMatch(type, "[REDACTED]", result.range))
            }
        }
        return matches
    }

    /**
     * Redact all PII in text, replacing matches with type-specific
     * placeholders. Patterns are applied sequentially in [patterns]
     * declaration order, so a broad later pattern never re-matches text a
     * more specific earlier pattern already redacted.
     */
    fun redact(text: String): String {
        var result = text
        for ((type, regex) in patterns) {
            result = regex.replace(result, type.redaction)
        }
        return result
    }

    /**
     * Detect PII and return a full detection result with redacted text, in
     * one call. Used by callers (e.g. tool-result scanning) that need both
     * the matches and the masked text for the same input.
     */
    fun detectAndRedact(text: String): PiiDetectionResult {
        val matches = detect(text)
        return PiiDetectionResult(
            hasPii = matches.isNotEmpty(),
            types = matches.map { it.type }.toSet(),
            matches = matches,
            redactedText = redact(text)
        )
    }
}
