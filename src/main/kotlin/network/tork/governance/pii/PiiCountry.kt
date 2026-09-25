package network.tork.governance.pii

/**
 * The country layer: 24 country profiles, 51 patterns, 20 check digits.
 *
 * This implements the seven rules that `generated/sdk-registry/README.md` marks
 * **SDK**, from the bundle alone. Bundle 1.1.0 carries the data all seven need
 * -- the activation signals, the country map, the three windows, the whole-word
 * vocabulary, the near-miss policy, the table constants and the reference
 * labels -- so nothing here is hand-written registry data and no window is
 * hard-coded.
 *
 *  1. ACTIVATE   a country's patterns run only when one of its signals fires.
 *  2. MATCH      the regex, case-sensitively, globally.
 *  3. KEYWORD    whole-word (symmetric contextWindow) or column verdict or the
 *                ASYMMETRIC substring window (60 before, 40 after); then 7b may
 *                close the gate again.
 *  4. CHECKSUM   when required. Advisory checksums never reject.
 *  5. SUPERSEDE  a match containing every range it overlaps takes them.
 *  6. NEAR MISS  a checksum-failing identifier is redacted generically.
 *  7. COLUMN     in a delimited table a bare value cell is judged by its header.
 *  7b. NEAREST LABEL  a closer commercial label closes the gate.
 *
 * Still cloud-only, by design: the universal (L0) patterns, the slot, context,
 * gravity and name layers, industry profiles and org configuration.
 */
object PiiCountry {

    /** Characters before a match that count as nearby for the substring gate. */
    const val KEYWORD_WINDOW_BEFORE = PII_KEYWORD_WINDOW_BEFORE

    /** Characters after. Deliberately NOT the same number as before. */
    const val KEYWORD_WINDOW_AFTER = PII_KEYWORD_WINDOW_AFTER

    /** The symmetric window: whole-word keywords and the near-miss gate. */
    const val CONTEXT_WINDOW = PII_CONTEXT_WINDOW

    /** The bundle this SDK shipped. */
    const val REGISTRY_VERSION = PII_REGISTRY_VERSION

    /** The bundle content hash, which answers "did the data change". */
    const val CONTENT_HASH = PII_CONTENT_HASH

    /** One country identifier found in the content. */
    data class CountryMatch(
        /** Registry pattern name, or `national_id_near_miss` for a rule 6 span. */
        val name: String,
        /** ISO 3166-1 alpha-2, or `EU` for the bloc. Empty for a near miss. */
        val country: String,
        /** The shared redaction label. The receipt block hashes labels. */
        val label: String,
        val type: String,
        val redaction: String,
        val startIndex: Int,
        val endIndex: Int,
    )

    /** A span of the original text and the token that replaces it. */
    data class RedactionSpan(val startIndex: Int, val endIndex: Int, val redaction: String)

    /** Matches, plus the caller's own L0 ranges that rule 5 superseded. */
    data class Result(
        val matches: List<CountryMatch>,
        val supersededRanges: List<Pair<Int, Int>>,
    )

    private data class TableScope(
        val start: Int,
        val end: Int,
        val header: String,
        val rowStart: Int,
        val rowEnd: Int,
    )

    // ── compiled once ───────────────────────────────────────────────────────

    private val compiled: Map<String, Regex> =
        TORK_PII_PATTERNS.associate { it.name to Regex(it.regex) }

    private val byName: Map<String, TorkPiiPattern> = TORK_PII_PATTERNS.associateBy { it.name }

    // Rule 1a (README.md, bundle >= 1.2.0): alwaysOn patterns run on every
    // document regardless of region activation, before the activated country
    // patterns, so rule 5 can let an activated pattern supersede one of these.
    private val alwaysOnPatterns: List<TorkPiiPattern> = TORK_PII_PATTERNS.filter { it.alwaysOn }

    private val compiledSignals: List<Regex> = TORK_PII_SIGNALS.map {
        if (it.flags.contains("i")) Regex(it.regex, RegexOption.IGNORE_CASE) else Regex(it.regex)
    }

    private val signalOrder: List<String> = TORK_PII_SIGNALS.map { it.country }.distinct()

    private val countryPatterns: Map<String, List<String>> =
        TORK_PII_COUNTRIES.associate { it.code to it.patterns }

    private val genericSet: Set<String> = PII_GENERIC_ID_KEYWORDS.toSet()

    private val nationalIdKeywords: List<String> = PII_GENERIC_ID_KEYWORDS + PII_LOCAL_ID_KEYWORDS

    private fun Char.isAlnumAscii(): Boolean =
        this in 'a'..'z' || this in '0'..'9' || this in 'A'..'Z'

    /** A pattern's whole vocabulary: the substring keywords and the whole-word ones. */
    private fun allKeywordsOf(p: TorkPiiPattern): List<String> =
        if (p.wholeWordKeywords.isEmpty()) p.keywords else p.keywords + p.wholeWordKeywords

    /** The half of a vocabulary that names ONE country's identifier. */
    private fun specificKeywords(keywords: List<String>): List<String> =
        keywords.filterNot { it in genericSet }

    private fun window(content: String, lo: Int, hi: Int): String {
        val l = lo.coerceAtLeast(0)
        val h = hi.coerceAtMost(content.length)
        return if (h > l) content.substring(l, h).lowercase() else ""
    }

    /** Rule 3, substring half: ASYMMETRIC -- 60 before the match, 40 after it. */
    private fun hasNearbyContext(content: String, start: Int, end: Int, keywords: List<String>): Boolean {
        val before = window(content, start - KEYWORD_WINDOW_BEFORE, start)
        val after = window(content, end, end + KEYWORD_WINDOW_AFTER)
        return keywords.any { before.contains(it) || after.contains(it) }
    }

    /** Symmetric [CONTEXT_WINDOW] either side, substring. Used by rule 6. */
    private fun hasContextAround(content: String, start: Int, end: Int, keywords: List<String>): Boolean {
        val w = window(content, start - CONTEXT_WINDOW, end + CONTEXT_WINDOW)
        return keywords.any { w.contains(it) }
    }

    /**
     * Rule 3, whole-word half: symmetric [CONTEXT_WINDOW], a boundary each side,
     * a boundary being "not a letter or digit".
     *
     * This is the gate Indonesia needs: `nik` sits inside *teknik*, *elektronik*,
     * *klinik* and *pabrik*, so a substring test would open the gate on a ledger.
     */
    fun hasWholeWordContextAround(content: String, start: Int, end: Int, words: List<String>): Boolean {
        if (words.isEmpty()) return false
        val w = window(content, start - CONTEXT_WINDOW, end + CONTEXT_WINDOW)
        for (word in words) {
            var from = 0
            while (from <= w.length - word.length) {
                val i = w.indexOf(word, from)
                if (i < 0) break
                val beforeOk = i == 0 || !w[i - 1].isAlnumAscii()
                val j = i + word.length
                val afterOk = j >= w.length || !w[j].isAlnumAscii()
                if (beforeOk && afterOk) return true
                from = i + 1
            }
        }
        return false
    }

    private fun documentHasWholeWord(content: String, words: List<String>): Boolean =
        words.isNotEmpty() && hasWholeWordContextAround(content, 0, content.length, words)

    // ── rule 1: activation ──────────────────────────────────────────────────

    /** The countries this text activates, in the bundle's signal order. */
    fun inferRegions(content: String): List<String> {
        val regions = mutableListOf<String>()
        val lower = content.lowercase()
        for (code in signalOrder) {
            for ((i, s) in TORK_PII_SIGNALS.withIndex()) {
                if (s.country != code) continue
                if (!compiledSignals[i].containsMatchIn(content)) continue

                val bySubstring = s.keywords.isNotEmpty() && s.keywords.any { lower.contains(it) }
                val byWholeWord = documentHasWholeWord(content, s.wholeWordKeywords)
                // Both lists empty means the shape alone is distinctive enough.
                if ((s.keywords.isNotEmpty() || s.wholeWordKeywords.isNotEmpty()) &&
                    !bySubstring && !byWholeWord
                ) {
                    continue
                }
                val target = s.activates.ifEmpty { code }
                if (target !in regions) regions.add(target)
                break // one signal per country is enough
            }
        }
        return regions
    }

    /** The patterns those regions switch on, de-duplicated, in registry order. */
    fun patternsForRegions(regions: List<String>): List<TorkPiiPattern> {
        val out = mutableListOf<TorkPiiPattern>()
        val seen = mutableSetOf<String>()
        for (code in regions) {
            for (name in countryPatterns[code.uppercase()].orEmpty()) {
                if (!seen.add(name)) continue
                byName[name]?.let { out.add(it) }
            }
        }
        return out
    }

    // ── rule 7: the column is the context ───────────────────────────────────

    private val headerHasLetter = Regex("[A-Za-z\\u00C0-\\uFFFF]")
    private val headerAllNumeric = Regex("^\\+?[\\d\\s.\\-/]+$")
    private val headerSentence = Regex("[.?!]")
    private val whitespaceRun = Regex("\\s+")

    private fun looksLikeHeader(cells: List<String>, delimiter: String): Boolean {
        val minimum = if (delimiter == ",") PII_TABLE_MIN_COMMA_COLUMNS else 2
        if (cells.size < minimum) return false
        return cells.all { cell ->
            val t = cell.trim()
            t.isNotEmpty() &&
                t.length <= PII_TABLE_MAX_HEADER_LENGTH &&
                headerHasLetter.containsMatchIn(t) &&
                !headerAllNumeric.matches(t) &&
                !headerSentence.containsMatchIn(t) &&
                t.split(whitespaceRun).size <= PII_TABLE_MAX_HEADER_WORDS
        }
    }

    /** True when the content parses as a delimited table with a header row. */
    fun isTable(content: String): Boolean = tableScopes(content).isNotEmpty()

    private fun tableScopes(content: String): List<TableScope> {
        val lines = content.split("\n")
        if (lines.size < PII_TABLE_MIN_ROWS) return emptyList()

        val offsets = IntArray(lines.size)
        var at = 0
        for (i in lines.indices) {
            offsets[i] = at
            at += lines[i].length + 1
        }

        for (delimiter in PII_TABLE_DELIMITERS) {
            val headerCells = lines[0].split(delimiter)
            if (!looksLikeHeader(headerCells, delimiter)) continue
            val width = headerCells.size

            val dataRows = mutableListOf<Int>()
            for (i in 1 until lines.size) {
                if (lines[i].isBlank()) continue
                if (lines[i].split(delimiter).size != width) return emptyList()
                dataRows.add(i)
            }
            if (dataRows.size < PII_TABLE_MIN_ROWS - 1) continue

            val scopes = mutableListOf<TableScope>()
            for (row in dataRows) {
                val cells = lines[row].split(delimiter)
                val rowStart = offsets[row]
                val rowEnd = rowStart + lines[row].length
                var cellStart = rowStart
                for (col in 0 until width) {
                    scopes.add(
                        TableScope(
                            start = cellStart,
                            end = cellStart + cells[col].length,
                            header = headerCells[col].trim().lowercase(),
                            rowStart = rowStart,
                            rowEnd = rowEnd,
                        )
                    )
                    cellStart += cells[col].length + delimiter.length
                }
            }
            return scopes
        }
        return emptyList()
    }

    /** A whole-word match, not a substring. */
    private fun headerNames(header: String, keywords: List<String>): Boolean {
        for (kw in keywords) {
            val i = header.indexOf(kw)
            if (i < 0) continue
            val beforeOk = i == 0 || !header[i - 1].isAlnumAscii()
            val j = i + kw.length
            val afterOk = j >= header.length || !header[j].isAlnumAscii()
            if (beforeOk && afterOk) return true
        }
        return false
    }

    /** null when the window should be consulted as usual. */
    private fun columnVerdict(
        content: String,
        scopes: List<TableScope>,
        start: Int,
        end: Int,
        all: List<String>,
        specific: List<String>,
    ): Boolean? {
        if (scopes.isEmpty()) return null
        val cell = scopes.firstOrNull { start >= it.start && end <= it.end } ?: return null
        // A cell whose own row names the identifier is prose in a delimited block.
        val rowText = window(content, cell.rowStart, cell.rowEnd)
        if (all.any { rowText.contains(it) }) return null
        return specific.isNotEmpty() && headerNames(cell.header, specific)
    }

    // ── rule 7b: nearest label wins ─────────────────────────────────────────

    private fun closestBefore(before: String, keywords: List<String>): Int? {
        var best: Int? = null
        for (kw in keywords) {
            val i = before.lastIndexOf(kw)
            if (i < 0) continue
            val d = before.length - (i + kw.length)
            if (best == null || d < best!!) best = d
        }
        return best
    }

    private fun closestAfter(after: String, keywords: List<String>): Int? {
        var best: Int? = null
        for (kw in keywords) {
            val i = after.indexOf(kw)
            if (i < 0) continue
            if (best == null || i < best!!) best = i
        }
        return best
    }

    /**
     * Whether the number is labelled as a commercial reference more closely than
     * as an identifier. It can only ever close a gate, never open one.
     */
    fun labelledAsReference(
        content: String,
        start: Int,
        end: Int,
        identifierKeywords: List<String>,
    ): Boolean {
        val before = window(content, start - PII_LABEL_WINDOW, start)
        val reference = closestBefore(before, PII_REFERENCE_LABELS) ?: return false
        if (reference > PII_LABEL_REACH) return false
        if (identifierKeywords.isEmpty()) return true

        closestBefore(before, identifierKeywords)?.let { if (it <= reference) return false }
        val after = window(content, end, end + PII_LABEL_WINDOW)
        closestAfter(after, identifierKeywords)?.let { if (it <= reference) return false }
        return true
    }

    // ── the pass ────────────────────────────────────────────────────────────

    /** The span with leading and trailing non-alphanumeric characters removed. */
    fun trimmedCore(content: String, start: Int, end: Int): Pair<Int, Int> {
        var s = start
        var e = end
        while (s < e && !content[s].isAlnumAscii()) s++
        while (e > s && !content[e - 1].isAlnumAscii()) e--
        return if (s == e) start to end else s to e
    }

    /** Country matches for [content], de-overlapped and ordered by position. */
    fun detect(content: String, patterns: List<TorkPiiPattern>? = null): List<CountryMatch> =
        detectWithRanges(content, patterns).matches

    /** The full pass. Pass your own L0 spans so rule 5 can supersede them. */
    fun detectWithRanges(
        content: String,
        patterns: List<TorkPiiPattern>? = null,
        existingRanges: List<Pair<Int, Int>> = emptyList(),
    ): Result {
        val active = patterns ?: run {
            val seen = mutableSetOf<String>()
            (alwaysOnPatterns + patternsForRegions(inferRegions(content))).filter { seen.add(it.name) }
        }
        if (active.isEmpty()) return Result(emptyList(), emptyList())

        val tables = tableScopes(content)
        val activeExisting = existingRanges.toMutableList()
        val superseded = mutableListOf<Pair<Int, Int>>()
        val claimed = mutableListOf<Pair<Int, Int>>()
        val found = mutableListOf<CountryMatch>()
        val nearMisses = mutableListOf<Pair<Int, Int>>()

        for (pattern in active) {
            val re = compiled[pattern.name] ?: continue
            for (m in re.findAll(content)) {
                if (m.value.isEmpty()) continue
                val start = m.range.first
                val end = m.range.last + 1

                // Rules 3, 7 and 7b.
                if (pattern.requiresKeyword && pattern.keywords.isNotEmpty()) {
                    val all = allKeywordsOf(pattern)
                    var ok = hasWholeWordContextAround(content, start, end, pattern.wholeWordKeywords)
                    if (!ok) {
                        val column = columnVerdict(content, tables, start, end, all, specificKeywords(all))
                        ok = column ?: hasNearbyContext(content, start, end, pattern.keywords)
                    }
                    if (!ok) continue
                    if (labelledAsReference(content, start, end, pattern.keywords)) continue
                }

                // Rule 4, and rule 6's candidate.
                if (pattern.checksumRequired && pattern.checksum != null) {
                    val fn = PiiChecksums.functions[pattern.checksum]
                    if (fn != null && !fn(m.value)) {
                        if (pattern.nearMissFallback) {
                            val extra = pattern.nearMissKeywords.ifEmpty { pattern.keywords }
                            val vocabulary = nationalIdKeywords + extra
                            if (hasContextAround(content, start, end, vocabulary)) {
                                nearMisses.add(start to end)
                            }
                        }
                        continue
                    }
                }

                // Rule 5.
                val overlapping = (activeExisting + claimed).filter { start < it.second && end > it.first }
                if (overlapping.isNotEmpty()) {
                    val supersedesAll = overlapping.all { (rs, re2) ->
                        val (cs, ce) = trimmedCore(content, rs, re2)
                        start <= cs && end >= ce
                    }
                    if (!supersedesAll) continue
                    for (o in overlapping) {
                        if (activeExisting.remove(o)) superseded.add(o)
                        claimed.remove(o)
                        found.removeAll { it.startIndex == o.first && it.endIndex == o.second }
                    }
                }

                claimed.add(start to end)
                found.add(
                    CountryMatch(
                        name = pattern.name,
                        country = pattern.country,
                        label = pattern.label,
                        type = pattern.type,
                        redaction = pattern.redaction,
                        startIndex = start,
                        endIndex = end,
                    )
                )
            }
        }

        // Rule 6, last: a near miss can only ever fill a hole.
        val taken = (activeExisting + claimed).toMutableList()
        for (c in nearMisses) {
            if (taken.any { c.first < it.second && c.second > it.first }) continue
            taken.add(c)
            found.add(
                CountryMatch(
                    name = PII_NEAR_MISS_TYPE,
                    country = "",
                    label = "NATIONAL_ID",
                    type = PII_NEAR_MISS_TYPE,
                    redaction = PII_NEAR_MISS_REDACTION,
                    startIndex = c.first,
                    endIndex = c.second,
                )
            )
        }

        return Result(found.sortedBy { it.startIndex }, superseded)
    }

    /** Turn country matches into redaction spans. */
    fun redactionSpansOf(matches: List<CountryMatch>): List<RedactionSpan> =
        matches.map { RedactionSpan(it.startIndex, it.endIndex, it.redaction) }

    /**
     * Replace every span with its redaction, right to left.
     *
     * Right to left is what keeps the earlier indices valid, and splicing whole
     * spans in one pass is what guarantees no partial redaction: a digit can
     * never be left standing beside a redaction token, because nothing is ever
     * matched against text a previous replacement has already rewritten.
     */
    fun applyRedactions(text: String, spans: List<RedactionSpan>): String {
        if (spans.isEmpty()) return text
        var out = text
        for (s in spans.sortedByDescending { it.startIndex }) {
            out = out.substring(0, s.startIndex) + s.redaction + out.substring(s.endIndex)
        }
        return out
    }
}
