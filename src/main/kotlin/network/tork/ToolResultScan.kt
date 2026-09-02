package network.tork

import java.util.IdentityHashMap

/**
 * Tool-result scanning (DECIDED-TACT2-V2-C), ported from
 * tork-js-sdk/src/tool-result-scan.ts (see also the Java port,
 * tork-java-sdk's `ToolResultScanner`/`ToolResultScanReceiptBlock`).
 *
 * A tool result returned by an MCP server -- or by any external system the
 * caller does not control -- is untrusted input that is about to be appended
 * to a model's context. [ToolResultScanner.scanToolResult] scans it BEFORE
 * that happens, on-device, for two things:
 *
 *   1. PII, using the SAME on-device detector as [Tork.govern] ([PiiDetector]).
 *      Nothing new was written for this: same patterns, same redaction
 *      labels, same zero-network guarantee. This file does not duplicate a
 *      single regex from [PiiDetector] -- it calls it.
 *   2. Prompt injection, using the conservative heuristic pattern set below.
 *      Every injection finding is labelled `heuristic:<type>` so no caller
 *      can mistake a regex hit for a verified determination.
 *
 * ZERO NETWORK. Every function here is pure and synchronous: no socket, no
 * file I/O, no clock read. The payload never leaves the machine.
 *
 * WHAT THIS IS NOT: this is a client-side control that the CALLER runs and
 * the caller attests to. It is not gateway-side enforcement -- a compromised
 * or simply careless caller can skip it entirely, and Tork cannot tell.
 * Enforcement at the gateway, where skipping is not an option, is a separate
 * and later control.
 *
 * PARITY TIER: this port matches Tier 1 of the JS SDK -- the 10-type basic
 * PII vocabulary (`ssn, credit_card, email, phone, address, ip_address,
 * date_of_birth, passport, drivers_license, bank_account`) with JS-identical
 * labels and redaction markers. It does NOT carry the Python SDK's
 * regional/industry pattern tier (AU/US/GB/EU/AE/... profiles) -- this SDK's
 * regional detection (see [GovernOptions]) is a separate, older mechanism
 * and is not wired into `scanToolResult`.
 *
 * ## Engine/language differences from the JS source (documented workarounds)
 *
 * - Kotlin's [Regex] wraps `java.util.regex`, the same engine the JVM's Java
 *   port uses, so there is no slash-delimiter escaping to undo (`https:\/\/`
 *   in a JS regex literal becomes plain `https://` here, same as the Java
 *   port) and no semantic change to any pattern.
 * - JS's `/gi` and `/gim` flags become [RegexOption.IGNORE_CASE] and
 *   [RegexOption.MULTILINE]; "global" match-all is just how
 *   [Regex.findAll] already behaves.
 * - JS's comment on `tool-result-scan.ts` notes it must build "a fresh regex
 *   per call" because a `/g` `RegExp` literal is stateful (`lastIndex`
 *   persists across calls). Kotlin's [Regex] is immutable, so the injection
 *   patterns below are compiled ONCE with no equivalent workaround needed.
 * - Kotlin's [Map] iteration order is not guaranteed to preserve insertion
 *   order the way a JS object does, so [walk] sorts a map's keys (stringified
 *   via `toString()`) before traversing -- the same reasoning as the Java
 *   port's key-sort discipline.
 * - Cycle/identity guarding uses [java.util.IdentityHashMap] as a set (the
 *   JVM has no built-in `IdentityHashSet`), matching the Java port and the
 *   JS source's `WeakSet`.
 * - [ToolResultScanInput]'s constructor puts `payload` before the optional
 *   `serverUri` (`toolName, payload, serverUri = null`), not `toolName,
 *   serverUri, payload` as in JS/Java -- a Kotlin-idiomatic reordering so the
 *   2-arg convenience call (`ToolResultScanInput(toolName, payload)`) works
 *   positionally with a trailing default parameter; not a semantic change.
 */

// ============================================================================
// Types
// ============================================================================

/** Either `pii` (a detector match) or `injection` (a heuristic pattern match). */
enum class ToolResultFindingKind(val code: String) {
    PII("pii"),
    INJECTION("injection")
}

/**
 * One (kind, type, location) match tally, produced while scanning a tool
 * result.
 *
 * @property type For kind PII, a [PiiType.code] ("ssn", "email", ...). For
 * kind INJECTION, always `heuristic:<name>` -- the prefix is part of the
 * value, not decoration, so a downstream reader of a receipt cannot mistake
 * a pattern hit for a verified determination.
 * @property count Number of matches of this (kind, type) at this location.
 * @property location JSON path of the string the matches were found in,
 * e.g. `$.content[0].text`.
 */
data class ToolResultFinding(
    val kind: ToolResultFindingKind,
    val type: String,
    val count: Int,
    val location: String
)

/**
 * Input to [ToolResultScanner.scanToolResult].
 *
 * @property toolName Name of the tool that produced this result. Recorded on the receipt.
 * @property payload The tool result itself. Any JSON-shaped value reachable via
 * [Map], [List], arrays, strings, numbers, booleans, and `null` -- it never leaves the machine.
 * @property serverUri URI of the MCP server (or other origin). Recorded on the receipt when present.
 */
data class ToolResultScanInput(
    val toolName: String,
    val payload: Any?,
    val serverUri: String? = null
)

/**
 * Optional parameters to [ToolResultScanner.scanToolResult].
 *
 * @property blockOnInjection Block the result when the injection heuristics fire. Default false:
 * detect and report, let the caller decide. When true and an injection pattern matches, the
 * result's `blocked` is true, `reason` is set, and `sanitized` is `null` -- there is deliberately
 * no masked payload to accidentally append.
 * @property customPatterns Extra redaction patterns, applied after the default PII detector's
 * redaction. NOTE (inherited from the JS/Java SDKs): custom patterns redact but are not counted,
 * so they can change `sanitized` without producing a finding.
 * @property maxDepth Maximum nesting depth to walk. Deeper values are passed through unscanned
 * and unmodified.
 */
data class ToolResultScanOptions(
    val blockOnInjection: Boolean = false,
    val customPatterns: Map<String, Regex>? = null,
    val maxDepth: Int = 32
)

/**
 * Result of [ToolResultScanner.scanToolResult].
 *
 * @property sanitized The payload with PII masked in place, structurally identical otherwise.
 * `null` when `blocked` is true. Sub-trees containing no PII keep their original object identity,
 * so a clean payload's containers come back as the same [Map]/[List] instances that were passed in.
 * @property reason Present only when `blocked` is true.
 */
data class ToolResultScanResult(
    val sanitized: Any?,
    val findings: List<ToolResultFinding>,
    val blocked: Boolean,
    val reason: String? = null
)

/**
 * The `tool_result_scan` block recorded on a receipt.
 *
 * Byte-identical contract (DECIDED-TACT2-V2-C): [toJson] emits snake_case
 * keys in alphabetical order, and OMITS `reason` and `server_uri` entirely
 * when absent rather than emitting them as `null` -- the same discipline as
 * the JS SDK's TORK-DNA-v2 canonical form. Every SDK mirroring this must
 * produce a byte-identical block for the same scan. Key order:
 * `attested_by, blocked, capture_mode, findings, injection_ruleset,
 * [reason], sdk_language, sdk_version, [server_uri], tool_name, totals`.
 *
 * It carries COUNTS ONLY. No payload, no matched substring, no location
 * path, no tool argument ever appears here.
 */
data class ToolResultScanReceiptBlock(
    val blocked: Boolean,
    /** Counts by type. Injection types keep their `heuristic:` prefix. */
    val injectionFindings: Map<String, Int>,
    val piiFindings: Map<String, Int>,
    /** Identifier of the injection ruleset that produced the injection counts. */
    val injectionRuleset: String,
    /** Present only when blocked. */
    val reason: String?,
    val sdkVersion: String,
    /** Present only when the caller supplied one. */
    val serverUri: String?,
    val toolName: String,
    val injectionTotal: Int,
    val piiTotal: Int
) {
    /** Always "client". This scan ran in the caller's process; Tork did not execute it. */
    val attestedBy: String get() = "client"

    /** Always "edge" -- the capture_mode this SDK's client-side work is recorded under. */
    val captureMode: String get() = "edge"

    /** Always "kotlin". */
    val sdkLanguage: String get() = "kotlin"

    /**
     * An ordered map view of this block: snake_case keys in the same
     * alphabetical order [toJson] emits, with `reason` and `server_uri`
     * omitted entirely when absent.
     */
    fun toOrderedMap(): Map<String, Any> {
        val map = LinkedHashMap<String, Any>()
        map["attested_by"] = attestedBy
        map["blocked"] = blocked
        map["capture_mode"] = captureMode
        map["findings"] = linkedMapOf(
            "injection" to injectionFindings.toSortedMap(),
            "pii" to piiFindings.toSortedMap()
        )
        map["injection_ruleset"] = injectionRuleset
        if (reason != null) map["reason"] = reason
        map["sdk_language"] = sdkLanguage
        map["sdk_version"] = sdkVersion
        if (serverUri != null) map["server_uri"] = serverUri
        map["tool_name"] = toolName
        map["totals"] = linkedMapOf("injection" to injectionTotal, "pii" to piiTotal)
        return map
    }

    /**
     * The canonical JSON form of this block: snake_case keys, alphabetical
     * order, `reason`/`server_uri` omitted (not nulled) when absent. This is
     * the byte-identical cross-SDK artifact.
     */
    fun toJson(): String {
        val sb = StringBuilder()
        sb.append('{')
        sb.append("\"attested_by\":\"").append(attestedBy).append('"').append(',')
        sb.append("\"blocked\":").append(blocked).append(',')
        sb.append("\"capture_mode\":\"").append(captureMode).append('"').append(',')
        sb.append("\"findings\":{")
        sb.append("\"injection\":")
        appendCounts(sb, injectionFindings)
        sb.append(',')
        sb.append("\"pii\":")
        appendCounts(sb, piiFindings)
        sb.append('}').append(',')
        sb.append("\"injection_ruleset\":\"").append(jsonEscape(injectionRuleset)).append('"').append(',')
        if (reason != null) {
            sb.append("\"reason\":\"").append(jsonEscape(reason)).append('"').append(',')
        }
        sb.append("\"sdk_language\":\"").append(sdkLanguage).append('"').append(',')
        sb.append("\"sdk_version\":\"").append(jsonEscape(sdkVersion)).append('"').append(',')
        if (serverUri != null) {
            sb.append("\"server_uri\":\"").append(jsonEscape(serverUri)).append('"').append(',')
        }
        sb.append("\"tool_name\":\"").append(jsonEscape(toolName)).append('"').append(',')
        sb.append("\"totals\":{\"injection\":").append(injectionTotal)
            .append(",\"pii\":").append(piiTotal).append('}')
        sb.append('}')
        return sb.toString()
    }

    override fun toString(): String = toJson()
}

/**
 * What [Tork.scanToolResult] returns: the pure scan result plus the receipt
 * recording it.
 *
 * @property receipt Carries the `tool_result_scan` block.
 */
data class GovernedToolResultScanResult(
    val sanitized: Any?,
    val findings: List<ToolResultFinding>,
    val blocked: Boolean,
    val reason: String?,
    val receipt: GovernanceReceipt
)

// ============================================================================
// JSON helpers shared by the receipt block and stableStringify
// ============================================================================

private fun appendCounts(sb: StringBuilder, counts: Map<String, Int>) {
    sb.append('{')
    var first = true
    for ((key, value) in counts.toSortedMap()) {
        if (!first) sb.append(',')
        first = false
        sb.append('"').append(jsonEscape(key)).append("\":").append(value)
    }
    sb.append('}')
}

private fun jsonEscape(s: String): String {
    val out = StringBuilder(s.length)
    for (c in s) {
        when (c) {
            '"' -> out.append("\\\"")
            '\\' -> out.append("\\\\")
            '\n' -> out.append("\\n")
            '\r' -> out.append("\\r")
            '\t' -> out.append("\\t")
            else -> if (c.code < 0x20) out.append("\\u%04x".format(c.code)) else out.append(c)
        }
    }
    return out.toString()
}

private fun jsonQuote(s: String): String {
    val out = StringBuilder(s.length + 2)
    out.append('"')
    for (c in s) {
        when (c) {
            '"' -> out.append("\\\"")
            '\\' -> out.append("\\\\")
            else -> out.append(c)
        }
    }
    out.append('"')
    return out.toString()
}

// ============================================================================
// Scanner
// ============================================================================

object ToolResultScanner {

    /**
     * Prefix on every injection finding's type. Not cosmetic: these
     * patterns are regexes over untrusted text, they carry false positives
     * and false negatives, and the label travels with the finding into the
     * receipt.
     */
    const val INJECTION_HEURISTIC_PREFIX = "heuristic:"

    /**
     * Identifies this exact pattern set in receipts. Bump when the patterns
     * change, so a receipt says which ruleset produced its counts. Every
     * SDK mirroring this implementation must emit the SAME value for the
     * same ruleset -- it is a shared identifier, not a per-language one.
     */
    const val INJECTION_RULESET = "tork-injection-heuristics-v1"

    private data class InjectionPattern(val type: String, val pattern: Regex)

    /**
     * Conservative on purpose. Each pattern targets a phrase that has no
     * plausible reason to appear in a legitimate tool result -- a database
     * row, a search hit, a file listing. Broader "suspicious language"
     * matching would fire on ordinary documentation and support tickets,
     * and an alert nobody believes is worse than no alert.
     *
     * Regex SOURCE STRINGS below are ported verbatim from
     * tork-js-sdk/src/tool-result-scan.ts's `INJECTION_PATTERNS`, modulo the
     * syntax adaptations documented in the file header.
     */
    private val INJECTION_PATTERNS: List<InjectionPattern> = listOf(
        // -- instruction override --------------------------------------------
        InjectionPattern(
            "instruction_override",
            Regex(
                """\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|earlier|above|preceding|all|any)\b[^.\n]{0,30}\b(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions|guideline|guidelines)\b""",
                RegexOption.IGNORE_CASE
            )
        ),
        InjectionPattern(
            "instruction_override",
            Regex(
                """\b(?:the\s+)?(?:instructions?|prompts?|rules?)\s+(?:above|below|before\s+this)\s+(?:are|is)\s+(?:now\s+)?(?:void|invalid|obsolete|outdated|no\s+longer\s+(?:valid|active|in\s+effect))\b""",
                RegexOption.IGNORE_CASE
            )
        ),
        InjectionPattern(
            "instruction_override",
            Regex(
                """\bdisregard\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|guidelines?)\b""",
                RegexOption.IGNORE_CASE
            )
        ),

        // -- role reassignment ------------------------------------------------
        InjectionPattern(
            "role_reassignment",
            Regex("""\byou\s+are\s+(?:now|no\s+longer)\s+(?:a|an|the)\b""", RegexOption.IGNORE_CASE)
        ),
        InjectionPattern(
            "role_reassignment",
            Regex(
                """\b(?:from\s+now\s+on|starting\s+now|for\s+the\s+rest\s+of\s+this\s+(?:conversation|session))\b[^.\n]{0,30}\byou\s+(?:are|will|must|should)\b""",
                RegexOption.IGNORE_CASE
            )
        ),
        InjectionPattern(
            "role_reassignment",
            Regex("""\bnew\s+(?:system\s+)?(?:instructions?|prompt|persona|role)\s*:""", RegexOption.IGNORE_CASE)
        ),
        InjectionPattern(
            "role_reassignment",
            Regex(
                """\b(?:enable|enter|activate|switch\s+to)\s+(?:developer|god|dan|jailbreak|unrestricted)\s+mode\b""",
                RegexOption.IGNORE_CASE
            )
        ),
        InjectionPattern(
            "role_reassignment",
            Regex(
                """\b(?:act|behave|respond|pretend\s+to\s+be)\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?(?:dan|unrestricted|unfiltered|uncensored|jailbroken)\b""",
                RegexOption.IGNORE_CASE
            )
        ),
        // A role header smuggled into content -- "system:" / "<|im_start|>system"
        // at the start of a line is a conversation-structure forgery, not prose.
        InjectionPattern(
            "role_reassignment",
            Regex(
                """^[ \t>*-]*(?:<\|im_start\|>\s*)?(?:system|assistant|developer)\s*(?::|\]|>)""",
                setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE)
            )
        ),

        // -- exfiltration -----------------------------------------------------
        // A markdown image/link whose URL carries the content out as a query
        // parameter -- the classic zero-click exfiltration shape.
        InjectionPattern(
            "exfiltration_url",
            Regex(
                """!?\[[^\]\n]*\]\(\s*https?://[^)\s]*[?&][^)\s]*(?:data|payload|prompt|content|text|secret|token|key|conversation|history)=[^)\s]*\)""",
                RegexOption.IGNORE_CASE
            )
        ),
        InjectionPattern(
            "exfiltration_url",
            Regex(
                """\bhttps?://\S*[?&](?:data|payload|secret|token|api[_-]?key|apikey|password|credential|conversation|history)=""",
                RegexOption.IGNORE_CASE
            )
        ),
        InjectionPattern(
            "exfiltration_url",
            Regex(
                """\b(?:send|post|upload|forward|transmit|exfiltrate|leak|report)\b[^.\n]{0,60}\bto\s+https?://\S+""",
                RegexOption.IGNORE_CASE
            )
        )
    )

    /** Distinct injection types the ruleset can emit, for documentation/tests. */
    val INJECTION_TYPES: List<String> = INJECTION_PATTERNS.map { it.type }.toSortedSet().toList()

    private const val DEFAULT_MAX_DEPTH = 32

    private val IDENTIFIER = Regex("""^[A-Za-z_$][A-Za-z0-9_$]*$""")

    private fun childPath(parent: String, key: String): String =
        if (IDENTIFIER.matches(key)) "$parent.$key" else "$parent[${jsonQuote(key)}]"

    /**
     * Scan one string: PII (via the shared [PiiDetector]) then injection
     * heuristics. Returns the masked string; findings are appended in
     * place, keyed to [location].
     */
    private fun scanString(
        text: String,
        location: String,
        customPatterns: Map<String, Regex>?,
        findings: MutableList<ToolResultFinding>
    ): String {
        val pii = PiiDetector.detectAndRedact(text)

        if (pii.count > 0) {
            // Counts per type, emitted in a stable (sorted-by-code) order so
            // two runs over the same payload produce identical findings.
            val perType = pii.matches.groupingBy { it.type.code }.eachCount()
            for (code in perType.keys.sorted()) {
                findings.add(ToolResultFinding(ToolResultFindingKind.PII, code, perType.getValue(code), location))
            }
        }

        val perInjectionType = mutableMapOf<String, Int>()
        for (ip in INJECTION_PATTERNS) {
            val count = ip.pattern.findAll(text).count()
            if (count > 0) {
                perInjectionType[ip.type] = (perInjectionType[ip.type] ?: 0) + count
            }
        }
        for (type in perInjectionType.keys.sorted()) {
            findings.add(
                ToolResultFinding(
                    ToolResultFindingKind.INJECTION,
                    INJECTION_HEURISTIC_PREFIX + type,
                    perInjectionType.getValue(type),
                    location
                )
            )
        }

        var redacted = pii.redactedText

        // Extra caller-supplied patterns, applied AFTER default detection
        // and redaction, for redaction only -- they never produce a
        // finding, matching the JS/Java SDKs' documented behavior. Applied
        // in sorted-name order for determinism.
        if (!customPatterns.isNullOrEmpty()) {
            for (name in customPatterns.keys.sorted()) {
                val pattern = customPatterns.getValue(name)
                redacted = pattern.replace(redacted, "[${name.uppercase()}_REDACTED]")
            }
        }

        return redacted
    }

    /**
     * Walk the payload, scanning every string. Returns a structure with PII
     * masked in place; sub-trees with nothing to mask keep their original
     * identity, so an untouched payload's containers come back as the same
     * [Map]/[List]/array instances that were passed in.
     *
     * Only strings are scanned. Numbers, booleans, and anything that is not
     * a [String], [Map], [List], or array passes through untouched -- a bank
     * account stored as a boxed number is NOT detected. Cycles
     * (self-referential maps/lists) are left as-is and not re-entered,
     * guarded by object identity (an [IdentityHashMap] used as a set,
     * matching the JS source's `WeakSet`).
     */
    private fun walk(
        value: Any?,
        location: String,
        depth: Int,
        maxDepth: Int,
        customPatterns: Map<String, Regex>?,
        findings: MutableList<ToolResultFinding>,
        seen: IdentityHashMap<Any, Boolean>
    ): Any? {
        if (value is String) {
            return scanString(value, location, customPatterns, findings)
        }

        if (depth >= maxDepth || value == null) {
            return value
        }

        if (value is Map<*, *>) {
            if (seen.containsKey(value)) return value
            seen[value] = true

            // Kotlin Map implementations don't guarantee iteration order the
            // way a JS object preserves key-insertion order, so keys are
            // sorted for determinism.
            val keys = value.keys.map { it.toString() }.sorted()
            val byKey = LinkedHashMap<String, Any?>()
            for (k in value.keys) byKey[k.toString()] = value[k]

            var changed = false
            val out = LinkedHashMap<String, Any?>()
            for (key in keys) {
                val item = byKey[key]
                val next = walk(item, childPath(location, key), depth + 1, maxDepth, customPatterns, findings, seen)
                if (next !== item) changed = true
                out[key] = next
            }
            return if (changed) out else value
        }

        if (value is List<*>) {
            if (seen.containsKey(value)) return value
            seen[value] = true

            var changed = false
            val out = ArrayList<Any?>(value.size)
            for ((index, item) in value.withIndex()) {
                val next = walk(item, "$location[$index]", depth + 1, maxDepth, customPatterns, findings, seen)
                if (next !== item) changed = true
                out.add(next)
            }
            return if (changed) out else value
        }

        if (value is Array<*>) {
            if (seen.containsKey(value)) return value
            seen[value] = true

            var changed = false
            val out = arrayOfNulls<Any?>(value.size)
            for (index in value.indices) {
                val item = value[index]
                val next = walk(item, "$location[$index]", depth + 1, maxDepth, customPatterns, findings, seen)
                if (next !== item) changed = true
                out[index] = next
            }
            return if (changed) out else value
        }

        return value
    }

    // ========================================================================
    // Public API
    // ========================================================================

    /**
     * Scan a tool result for PII and prompt injection before it is appended
     * to model context. Pure, synchronous, on-device: makes no network call
     * and mutates nothing reachable from [input].payload.
     *
     * For the receipt-linked form (`attested_by='client'`,
     * `capture_mode='edge'`), use [Tork.scanToolResult], which wraps this
     * and records the scan.
     */
    fun scanToolResult(input: ToolResultScanInput, options: ToolResultScanOptions = ToolResultScanOptions()): ToolResultScanResult {
        val findings = mutableListOf<ToolResultFinding>()
        val sanitized = walk(input.payload, "$", 0, options.maxDepth, options.customPatterns, findings, IdentityHashMap())

        val injectionCount = scanInjectionCount(findings)
        val blocked = options.blockOnInjection && injectionCount > 0

        if (blocked) {
            val types = findings
                .filter { it.kind == ToolResultFindingKind.INJECTION }
                .map { it.type }
                .toSortedSet()
            val reason = "Blocked: $injectionCount prompt-injection heuristic match(es) " +
                "[${types.joinToString(", ")}] in the result of tool \"${input.toolName}\". " +
                "These are heuristic pattern matches ($INJECTION_RULESET), not a verified determination. " +
                "sanitized is null so no masked copy can be appended to context by accident."
            return ToolResultScanResult(null, findings, true, reason)
        }

        return ToolResultScanResult(sanitized, findings, false, null)
    }

    // ========================================================================
    // Receipt block
    // ========================================================================

    private fun countsByType(findings: List<ToolResultFinding>, kind: ToolResultFindingKind): Map<String, Int> {
        val totals = sortedMapOf<String, Int>()
        for (f in findings) {
            if (f.kind != kind) continue
            totals[f.type] = (totals[f.type] ?: 0) + f.count
        }
        return totals
    }

    private fun sumCounts(counts: Map<String, Int>): Int = counts.values.sum()

    /**
     * Build the receipt block for a completed scan.
     *
     * @param toolName name of the tool that produced the scanned result
     * @param serverUri URI of the MCP server (or other origin); nullable
     * @param result the completed scan result
     * @param sdkVersion this SDK's version, as reported on the block
     */
    fun buildToolResultScanBlock(
        toolName: String,
        serverUri: String?,
        result: ToolResultScanResult,
        sdkVersion: String
    ): ToolResultScanReceiptBlock {
        val pii = countsByType(result.findings, ToolResultFindingKind.PII)
        val injection = countsByType(result.findings, ToolResultFindingKind.INJECTION)

        return ToolResultScanReceiptBlock(
            blocked = result.blocked,
            injectionFindings = injection,
            piiFindings = pii,
            injectionRuleset = INJECTION_RULESET,
            reason = result.reason,
            sdkVersion = sdkVersion,
            serverUri = serverUri,
            toolName = toolName,
            injectionTotal = sumCounts(injection),
            piiTotal = sumCounts(pii)
        )
    }

    /** Distinct PII types in a scan result, for the attestation canonical form. */
    fun scanPIITypes(findings: List<ToolResultFinding>): List<String> =
        findings.filter { it.kind == ToolResultFindingKind.PII }.map { it.type }.toSortedSet().toList()

    /** Total PII match count in a scan result. */
    fun scanPIICount(findings: List<ToolResultFinding>): Int =
        findings.filter { it.kind == ToolResultFindingKind.PII }.sumOf { it.count }

    /** Total injection match count in a scan result. */
    fun scanInjectionCount(findings: List<ToolResultFinding>): Int =
        findings.filter { it.kind == ToolResultFindingKind.INJECTION }.sumOf { it.count }

    // ========================================================================
    // Hashing support (Kotlin-specific; see Tork#scanToolResult)
    // ========================================================================

    /**
     * A deterministic, JSON-like text rendering of an arbitrary JSON-shaped
     * value, used only to compute `Receipt#inputHash`/`outputHash` for
     * [Tork.scanToolResult]. Map keys are sorted so the same logical value
     * hashes the same way regardless of the source map's iteration order
     * (matching [walk]'s own key-sort discipline).
     *
     * NOTE: this is a Kotlin-specific choice, not part of the
     * byte-identical `tool_result_scan` block contract -- only
     * [ToolResultScanReceiptBlock.toJson] is specified to match across
     * SDKs. This function exists solely so the wrapping receipt's hashes are
     * deterministic and non-reversible, the same property the JS/Java SDKs'
     * equivalent hashing has, without claiming byte-for-byte agreement with
     * either.
     */
    internal fun stableStringify(value: Any?): String {
        val sb = StringBuilder()
        stableStringify(value, sb)
        return sb.toString()
    }

    private fun stableStringify(value: Any?, sb: StringBuilder) {
        when (value) {
            null -> sb.append("null")
            is String -> sb.append(jsonQuote(value))
            is Boolean -> sb.append(value)
            is Number -> sb.append(value)
            is Map<*, *> -> {
                val keys = value.keys.map { it.toString() }.sorted()
                val byKey = LinkedHashMap<String, Any?>()
                for (k in value.keys) byKey[k.toString()] = value[k]
                sb.append('{')
                keys.forEachIndexed { i, key ->
                    if (i > 0) sb.append(',')
                    sb.append(jsonQuote(key)).append(':')
                    stableStringify(byKey[key], sb)
                }
                sb.append('}')
            }
            is List<*> -> {
                sb.append('[')
                value.forEachIndexed { i, item ->
                    if (i > 0) sb.append(',')
                    stableStringify(item, sb)
                }
                sb.append(']')
            }
            is Array<*> -> {
                sb.append('[')
                value.forEachIndexed { i, item ->
                    if (i > 0) sb.append(',')
                    stableStringify(item, sb)
                }
                sb.append(']')
            }
            else -> sb.append(jsonQuote(value.toString()))
        }
    }
}
