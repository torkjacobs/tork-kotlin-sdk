package network.tork.governance.pii

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Country-layer parity tests.
 *
 * The fixtures are generated from the cloud's own evidence, not written here:
 *
 *   `pii_unit_cases.json`  one valid sample per registry pattern, a
 *                          checksum-broken variant for each pattern whose
 *                          checksum is a gate, and the Indonesian boundary cases.
 *   `pii_vectors.json`     all 2,092 inputs of the cloud's golden snapshot:
 *                          every country-corpus sentence for all 249 ISO
 *                          jurisdictions, and the whole 1,523-line business
 *                          false-positive corpus.
 *
 * `expectedOutput` is the COUNTRY LAYER alone. Where the cloud's own output
 * differs, the case carries `cloudOutput` and a `divergence` naming the cause.
 */
class PiiCountryTest {

    private data class UnitCase(
        val pattern: String,
        val label: String,
        val redaction: String,
        val input: String,
        val sample: String,
        val expectDetected: Boolean,
        val note: String? = null,
    )

    private data class Vector(
        val id: String,
        val kind: String,
        val input: String,
        val expectedOutput: String,
        val expectedRegions: List<String>,
        val expectedLabels: List<String>,
        val expectedNames: List<String>,
        val cloudOutput: String? = null,
        val divergence: String? = null,
    )

    private data class VectorFile(
        val bundleVersion: String,
        val contentHash: String,
        val cases: List<Vector>,
    )

    private companion object {
        const val NIK = "3171010101900001"
        val gson = Gson()

        fun read(name: String): String =
            PiiCountryTest::class.java.getResourceAsStream("/$name")!!.bufferedReader().readText()

        val vectors: VectorFile = gson.fromJson(read("pii_vectors.json"), VectorFile::class.java)
        val units: List<UnitCase> =
            gson.fromJson(read("pii_unit_cases.json"), object : TypeToken<List<UnitCase>>() {}.type)
        val corpus = vectors.cases.filter { it.kind != "business-fp" }
        val business = vectors.cases.filter { it.kind == "business-fp" }
    }

    private fun redact(s: String): String =
        PiiCountry.applyRedactions(s, PiiCountry.redactionSpansOf(PiiCountry.detect(s)))

    // ── the bundle ──────────────────────────────────────────────────────────

    @Test
    fun `is the version and content the fixtures were generated from`() {
        assertEquals(vectors.bundleVersion, PII_REGISTRY_VERSION)
        assertEquals(vectors.contentHash, PII_CONTENT_HASH)
    }

    @Test
    fun `carries 54 patterns across 24 profiles with 51 activation signals`() {
        // Bundle 1.2.0 adds au_tfn, au_abn and au_medicare as alwaysOn patterns
        // (they run on keyword alone, not on a region signal), so the pattern
        // count grows by three while the country and signal counts do not.
        assertEquals(54, TORK_PII_PATTERNS.size)
        assertEquals(24, TORK_PII_COUNTRIES.size)
        assertEquals(51, TORK_PII_SIGNALS.size)
    }

    @Test
    fun `covers Indonesia, added in 1_1_0`() {
        val id = TORK_PII_COUNTRIES.firstOrNull { it.code == "ID" }
        assertNotNull(id, "Indonesia is missing from the bundle")
        assertTrue("id_nik" in id.patterns)
        val nik = TORK_PII_PATTERNS.first { it.name == "id_nik" }
        assertEquals("NIK", nik.label)
        assertTrue("nik" in nik.wholeWordKeywords)
    }

    @Test
    fun `reads its windows from the bundle, and they are not all the same number`() {
        assertEquals(60, PiiCountry.KEYWORD_WINDOW_BEFORE)
        assertEquals(40, PiiCountry.KEYWORD_WINDOW_AFTER)
        assertEquals(60, PiiCountry.CONTEXT_WINDOW)
        assertFalse(PiiCountry.KEYWORD_WINDOW_BEFORE == PiiCountry.KEYWORD_WINDOW_AFTER)
    }

    @Test
    fun `names a checksum function for every pattern that declares one`() {
        for (p in TORK_PII_PATTERNS) {
            val c = p.checksum ?: continue
            assertNotNull(PiiChecksums.functions[c], "${p.name} -> $c")
        }
    }

    @Test
    fun `uses only the portable regex subset`() {
        val forbidden = listOf(
            "(?=" to "lookahead", "(?!" to "negative lookahead",
            "(?<=" to "lookbehind", "(?<!" to "negative lookbehind",
            "\\p{" to "unicode property escape", "(?>" to "atomic group",
        )
        val sources = TORK_PII_PATTERNS.map { it.regex } + TORK_PII_SIGNALS.map { it.regex }
        for (src in sources) {
            for ((bad, why) in forbidden) assertFalse(src.contains(bad), "$src uses $why")
        }
    }

    // ── per-pattern unit cases ──────────────────────────────────────────────

    @Test
    fun `per-pattern unit cases detect or reject as the cloud does`() {
        assertTrue(units.isNotEmpty())
        val byName = TORK_PII_PATTERNS.associateBy { it.name }
        for (c in units) {
            val p = byName[c.pattern]
            assertNotNull(p, "${c.pattern} is not in the bundle")
            val hit = PiiCountry.detect(c.input, listOf(p)).firstOrNull { it.name == c.pattern }
            if (c.expectDetected) {
                assertNotNull(hit, "expected ${c.pattern} to match ${c.input}")
                assertEquals(c.sample, c.input.substring(hit.startIndex, hit.endIndex))
                assertEquals(c.redaction, hit.redaction)
            } else {
                assertNull(hit, "expected ${c.pattern} NOT to match ${c.input}")
            }
        }
    }

    // ── golden-snapshot parity ──────────────────────────────────────────────

    @Test
    fun `reproduces the cloud on every corpus vector`() {
        assertTrue(corpus.size > 500)
        val failures = mutableListOf<String>()
        for (c in corpus) {
            val matches = PiiCountry.detect(c.input)
            val out = PiiCountry.applyRedactions(c.input, PiiCountry.redactionSpansOf(matches))
            if (PiiCountry.inferRegions(c.input) != c.expectedRegions) failures += "${c.id} activation"
            if (out != c.expectedOutput) failures += "${c.id} redaction"
            if (matches.map { it.label }.distinct() != c.expectedLabels) failures += "${c.id} labels"
            if (matches.map { it.name }.distinct() != c.expectedNames) failures += "${c.id} names"
        }
        assertEquals(emptyList(), failures)
    }

    @Test
    fun `adds no false positive to the business corpus`() {
        assertTrue(business.size > 1500)
        assertEquals(emptyList(), business.filter { PiiCountry.detect(it.input).isNotEmpty() }.map { it.id })
        assertEquals(
            emptyList(),
            business.filter { PiiCountry.inferRegions(it.input) != it.expectedRegions }.map { it.id },
        )
    }

    @Test
    fun `diverges from the cloud for L0 reasons only - the AU bundle gap is closed`() {
        val diverged = vectors.cases.filter { it.divergence != null }
        for (c in diverged) {
            assertTrue(
                c.divergence!!.startsWith("L0:") || c.divergence.startsWith("BUNDLE GAP:"),
                "${c.id}: unexplained divergence",
            )
        }
        // Bundle 1.2.0 ships au_tfn, au_abn and au_medicare as alwaysOn patterns,
        // so the "BUNDLE GAP" cause measured against 1.1.0 no longer applies.
        val gaps = diverged.filter { it.divergence!!.startsWith("BUNDLE GAP:") }
            .map { it.id.split("/")[1] }.distinct().sorted()
        assertEquals(emptyList<String>(), gaps)
    }

    @Test
    fun `nothing is ever partially redacted`() {
        val bad = Regex("""\d\[[A-Z_]+_REDACTED\]|\[[A-Z_]+_REDACTED\]\d""")
        for (c in vectors.cases) {
            val matches = PiiCountry.detect(c.input)
            val out = PiiCountry.applyRedactions(c.input, PiiCountry.redactionSpansOf(matches))
            assertFalse(bad.containsMatchIn(out), "${c.id}: $out")
            for (m in matches) {
                val raw = c.input.substring(m.startIndex, m.endIndex)
                assertFalse(out.contains(raw), "${c.id}: $raw survived")
            }
        }
    }

    // ── Indonesia, the rule 1.1.0 added ─────────────────────────────────────

    @Test
    fun `detects the short spelling, which is a whole-word keyword only`() {
        val s = "NIK $NIK untuk pendaftaran rekening di Jakarta, Indonesia."
        assertEquals(listOf("ID"), PiiCountry.inferRegions(s))
        assertEquals("NIK [NIK_REDACTED] untuk pendaftaran rekening di Jakarta, Indonesia.", redact(s))
    }

    @Test
    fun `detects the long spelling, which is an ordinary substring keyword`() {
        assertTrue(redact("Nomor Induk Kependudukan $NIK untuk pendaftaran.").contains("[NIK_REDACTED]"))
    }

    @Test
    fun `does NOT open the gate on nik inside an ordinary Indonesian word`() {
        for (word in listOf("teknik", "elektronik", "klinik", "pabrik", "piknik")) {
            assertTrue(
                PiiCountry.detect("Faktur $word $NIK untuk pelanggan.").isEmpty(),
                "$word opened the gate",
            )
        }
    }

    @Test
    fun `a bare NIK with no label is not redacted`() {
        assertTrue(PiiCountry.detect(NIK).isEmpty())
    }

    // ── the rules 1.1.0 added to the SDK half of the contract ───────────────

    @Test
    fun `rule 6 - a checksum-failing identifier is redacted generically`() {
        val out = redact("South African ID number 8001015009088 for the FICA check.")
        assertFalse(out.contains("8001015009088"))
        assertTrue(out.contains("[NATIONAL_ID_REDACTED]"))
    }

    @Test
    fun `rule 7 - a column header is the context for a bare value cell`() {
        val csv = listOf(
            "Name,CNIC,City", "Ali,42201-1234567-1,Karachi",
            "Sana,42201-7654321-2,Lahore", "Omar,42201-1111111-3,Multan",
        ).joinToString("\n")
        assertTrue(PiiCountry.isTable(csv))
        assertFalse(redact(csv).contains("42201-1234567-1"))
    }

    @Test
    fun `rule 7 - a generic header does NOT act as context`() {
        val csv = listOf(
            "Name,Order ID Number,City", "Ali,42201-1234567-1,Karachi",
            "Sana,42201-7654321-2,Lahore", "Omar,42201-1111111-3,Multan",
        ).joinToString("\n")
        assertTrue(PiiCountry.detect(csv).isEmpty())
    }

    @Test
    fun `rule 7b - a closer commercial label closes the gate`() {
        val s = "Please do not send your CNIC. Use the job number 4220112345671."
        val at = s.indexOf("4220112345671")
        assertTrue(PiiCountry.labelledAsReference(s, at, at + 13, listOf("cnic")))
        assertTrue(redact(s).contains("4220112345671"))
    }

    @Test
    fun `rule 7b can only ever close a gate, never open one`() {
        assertTrue(PiiCountry.detect("Order 12345678901234 with no identifier word anywhere.").isEmpty())
    }

    @Test
    fun `rule 5 - a country match supersedes a wider L0 range it contains`() {
        val s = "CPF 529.982.247-25 para a nota fiscal no Brasil."
        val at = s.indexOf("529.982.247-25")
        val res = PiiCountry.detectWithRanges(s, null, listOf((at - 1) to (at + 14)))
        assertTrue(res.matches.any { it.name == "br_cpf" })
        assertEquals(1, res.supersededRanges.size)
    }

    // ── AU alwaysOn patterns, added to the bundle in 1.2.0 ──────────────────

    @Test
    fun `detects a valid AU TFN with its keyword and redacts it`() {
        val s = "My tax file number is 876 543 210 for the ATO return."
        assertEquals("My tax file number is [TFN_REDACTED] for the ATO return.", redact(s))
        assertEquals(listOf("au_tfn"), PiiCountry.detect(s).map { it.name })
    }

    @Test
    fun `detects a valid AU ABN with its keyword and redacts it`() {
        val s = "Supplier ABN 51 824 753 556 appears on the Australian invoice."
        assertEquals("Supplier ABN [ABN_REDACTED] appears on the Australian invoice.", redact(s))
        assertEquals(listOf("au_abn"), PiiCountry.detect(s).map { it.name })
    }

    @Test
    fun `detects a valid AU Medicare number with its keyword and redacts it`() {
        val s = "Patient Medicare number 2123 45670 1 for the bulk-billed visit."
        assertEquals("Patient Medicare number [MEDICARE_REDACTED] for the bulk-billed visit.", redact(s))
        assertEquals(listOf("au_medicare"), PiiCountry.detect(s).map { it.name })
    }

    @Test
    fun `a checksum-failing TFN falls back to the generic near miss, not a false negative`() {
        val out = redact("My tax file number is 876 543 211 for the ATO return.")
        assertFalse(out.contains("876 543 211"))
        assertTrue(out.contains("[NATIONAL_ID_REDACTED]"))
    }

    @Test
    fun `a checksum-failing ABN is a hard reject - au_abn has no near-miss fallback`() {
        // Unlike au_tfn, au_abn's checksum is required with nearMissFallback = false in
        // the bundle: checksum.json marks it "requiredBy", but a failing check digit
        // drops the match entirely rather than degrading to a near miss.
        val s = "Supplier ABN 51 824 753 557 appears on the Australian invoice."
        assertTrue(PiiCountry.detect(s).isEmpty())
        assertEquals(s, redact(s))
    }

    @Test
    fun `a checksum-failing Medicare number is still redacted - its checksum is advisory only`() {
        val s = "Patient Medicare number 2123 45671 1 for the bulk-billed visit."
        assertEquals("Patient Medicare number [MEDICARE_REDACTED] for the bulk-billed visit.", redact(s))
        assertEquals(listOf("au_medicare"), PiiCountry.detect(s).map { it.name })
    }

    @Test
    fun `whole-word matching respects a boundary at each end`() {
        assertTrue(PiiCountry.hasWholeWordContextAround("nik 123", 4, 7, listOf("nik")))
        assertFalse(PiiCountry.hasWholeWordContextAround("teknik 123", 7, 10, listOf("nik")))
    }
}
