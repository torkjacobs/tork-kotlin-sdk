package network.tork

import network.tork.governance.pii.PiiCountry

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
    val redactedText: String,
    /** Country-registry detections, kept separate from the ten L0 [types]. */
    val countryMatches: List<PiiCountry.CountryMatch> = emptyList(),
    /** Redaction labels of those matches, e.g. `NATIONAL_ID`. */
    val countryLabels: List<String> = emptyList(),
    /** Country profiles the text activated, in registry order. */
    val regions: List<String> = emptyList()
) {
    val count: Int get() = matches.size + countryMatches.size
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
    fun redact(text: String): String = detectAndRedact(text).redactedText

    /**
     * Detect PII and return a full detection result with redacted text, in
     * one call. Used by callers (e.g. tool-result scanning) that need both
     * the matches and the masked text for the same input.
     *
     * REDACTION IS ONE PASS. Until 0.2.0 [redact] applied each pattern in turn
     * over text a previous pattern had already rewritten, while [detect]
     * reported ranges into the ORIGINAL text. Two types matching overlapping
     * spans could leave half an identifier standing beside a redaction token --
     * digits exposed in output the caller had been told was redacted. Every
     * match is now collected against the original text, overlaps are resolved
     * before anything is rewritten, and the surviving spans are spliced right
     * to left in a single pass.
     *
     * @param regions forces a set of country profiles on, case-insensitive;
     *   null or empty infers them from the content.
     */
    @JvmOverloads
    fun detectAndRedact(text: String, regions: List<String>? = null): PiiDetectionResult {
        val l0 = detect(text)
        val kept = mutableListOf<PiiMatch>()

        val activeRegions = if (!regions.isNullOrEmpty()) {
            regions.map { it.uppercase() }
        } else {
            PiiCountry.inferRegions(text)
        }
        val countryMatches =
            PiiCountry.detect(text, PiiCountry.patternsForRegions(activeRegions))

        // Resolve overlaps before anything is rewritten. A country identifier
        // supersedes any L0 span it fully contains -- the cloud does the same,
        // which is how a Saudi national ID stops coming back as
        // [PHONE_REDACTED].
        val claimed = mutableListOf<Pair<Int, Int>>()
        val spans = mutableListOf<PiiCountry.RedactionSpan>()
        for (c in countryMatches) {
            claimed.add(c.startIndex to c.endIndex)
            spans.add(PiiCountry.RedactionSpan(c.startIndex, c.endIndex, c.redaction))
        }

        for (m in l0) {
            val start = m.range.first
            val end = m.range.last + 1
            val overlapping = claimed.filter { (rs, re) -> start < re && end > rs }
            if (overlapping.isNotEmpty()) {
                val swallowsAll = overlapping.all { (rs, re) ->
                    val (cs, ce) = PiiCountry.trimmedCore(text, rs, re)
                    start <= cs && end >= ce
                }
                if (!swallowsAll) continue
                // An L0 span that fully contains a country span still loses: the
                // country label is the more specific claim.
                val hitsCountry = overlapping.any { o ->
                    countryMatches.any { it.startIndex == o.first && it.endIndex == o.second }
                }
                if (hitsCountry) continue
                for (o in overlapping) {
                    claimed.remove(o)
                    spans.removeAll { it.startIndex == o.first && it.endIndex == o.second }
                }
            }
            claimed.add(start to end)
            spans.add(PiiCountry.RedactionSpan(start, end, m.type.redaction))
            kept.add(m)
        }

        val countryLabels = countryMatches.map { it.label }.distinct()

        return PiiDetectionResult(
            hasPii = kept.isNotEmpty() || countryMatches.isNotEmpty(),
            types = kept.map { it.type }.toSet(),
            matches = kept.sortedBy { it.range.first },
            redactedText = PiiCountry.applyRedactions(text, spans),
            countryMatches = countryMatches,
            countryLabels = countryLabels,
            regions = activeRegions
        )
    }
}
