package network.tork.governance.pii

/**
 * Check digits for the country registry.
 *
 * The SDK bundle NAMES twenty algorithms and gives weights and a modulus for
 * the eleven that reduce to them; the other nine are marked `kind: "custom"`
 * and carry no specification, so they are ported here by hand from the cloud's
 * `lib/pii/checksums.ts` -- the single implementation the cloud and the country
 * corpus both use. Keeping the arithmetic identical is what makes a receipt
 * block from this SDK byte-identical to one from the JavaScript SDK.
 *
 * Every function is pure: a String in, a Boolean out. No I/O, no clock.
 */
object PiiChecksums {

    private fun digitsOf(s: String): String = s.filter { it in '0'..'9' }

    /** Remainder of a long decimal digit string modulo [m], digit by digit. */
    private fun modDigits(digits: String, m: Int): Int {
        var r = 0
        for (ch in digits) r = (r * 10 + (ch - '0')) % m
        return r
    }

    private fun allSameDigit(d: String): Boolean = d.isNotEmpty() && d.all { it == d[0] }

    private fun stripWhitespaceUpper(s: String): String =
        s.filterNot { it.isWhitespace() }.uppercase()

    /** Luhn / ISO-IEC 7812-1 mod-10. */
    fun luhn(input: String): Boolean {
        val d = digitsOf(input)
        if (d.length < 2) return false
        var sum = 0
        var dbl = false
        for (i in d.length - 1 downTo 0) {
            var n = d[i] - '0'
            if (dbl) {
                n *= 2
                if (n > 9) n -= 9
            }
            sum += n
            dbl = !dbl
        }
        return sum % 10 == 0
    }

    private val VERHOEFF_MUL = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
        intArrayOf(1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
        intArrayOf(2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
        intArrayOf(3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
        intArrayOf(4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
        intArrayOf(5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
        intArrayOf(6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
        intArrayOf(7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
        intArrayOf(8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
        intArrayOf(9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
    )

    private val VERHOEFF_PERM = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
        intArrayOf(1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
        intArrayOf(5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
        intArrayOf(8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
        intArrayOf(9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
        intArrayOf(4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
        intArrayOf(2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
        intArrayOf(7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
    )

    /** Verhoeff, the Aadhaar check digit (UIDAI Circular No. 1 of 2018). */
    fun verhoeff(input: String): Boolean {
        val d = digitsOf(input)
        var c = 0
        for (i in d.indices) {
            val digit = d[d.length - 1 - i] - '0'
            c = VERHOEFF_MUL[c][VERHOEFF_PERM[i % 8][digit]]
        }
        return c == 0
    }

    /** Australian TFN (ATO): weights 1,4,3,7,5,8,6,9,10, sum mod 11 == 0. */
    fun auTfn(input: String): Boolean {
        val d = digitsOf(input)
        if (d.length != 9) return false
        val w = intArrayOf(1, 4, 3, 7, 5, 8, 6, 9, 10)
        return (0 until 9).sumOf { (d[it] - '0') * w[it] } % 11 == 0
    }

    /** Australian ABN (ABR): subtract 1 from the first digit, weights 10,1,3..19, mod 89. */
    fun auAbn(input: String): Boolean {
        val d = digitsOf(input)
        if (d.length != 11) return false
        val w = intArrayOf(10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19)
        var sum = (d[0] - '0' - 1) * w[0]
        for (i in 1 until 11) sum += (d[i] - '0') * w[i]
        return sum % 89 == 0
    }

    /** Australian Medicare card number (Services Australia). */
    fun auMedicare(input: String): Boolean {
        val d = digitsOf(input)
        if (d.length < 10) return false
        if (d[0] !in "23456") return false
        val w = intArrayOf(1, 3, 7, 9, 1, 3, 7, 9)
        return (0 until 8).sumOf { (d[it] - '0') * w[it] } % 10 == d[8] - '0'
    }

    /** UK NHS number (NHS Data Model and Dictionary): weights 10..2, check = 11 - (sum mod 11). */
    fun ukNhs(input: String): Boolean {
        val d = digitsOf(input)
        if (d.length != 10) return false
        val sum = (0 until 9).sumOf { (d[it] - '0') * (10 - it) }
        var check = 11 - (sum % 11)
        if (check == 11) check = 0
        if (check == 10) return false
        return check == d[9] - '0'
    }

    /** Brazil CPF (Receita Federal): two sequential mod-11 check digits. */
    fun brCpf(input: String): Boolean {
        val d = digitsOf(input)
        if (d.length != 11 || allSameDigit(d)) return false
        fun calc(len: Int): Int {
            val sum = (0 until len).sumOf { (d[it] - '0') * (len + 1 - it) }
            val r = (sum * 10) % 11
            return if (r == 10) 0 else r
        }
        return calc(9) == d[9] - '0' && calc(10) == d[10] - '0'
    }

    /** Brazil CNPJ (Receita Federal): two mod-11 check digits with different weight vectors. */
    fun brCnpj(input: String): Boolean {
        val d = digitsOf(input)
        if (d.length != 14 || allSameDigit(d)) return false
        fun calc(weights: IntArray): Int {
            val sum = weights.indices.sumOf { (d[it] - '0') * weights[it] }
            val r = sum % 11
            return if (r < 2) 0 else 11 - r
        }
        return calc(intArrayOf(5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)) == d[12] - '0' &&
            calc(intArrayOf(6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)) == d[13] - '0'
    }

    /** Japan My Number (MIC Ordinance No. 85 of 2014). */
    fun jpMyNumber(input: String): Boolean {
        val d = digitsOf(input)
        if (d.length != 12) return false
        var sum = 0
        for (n in 1..11) {
            val p = d[11 - n] - '0'
            val q = if (n <= 6) n + 1 else n - 5
            sum += p * q
        }
        val r = sum % 11
        val check = if (r <= 1) 0 else 11 - r
        return check == d[11] - '0'
    }

    private val CN_SHAPE = Regex("""^\d{17}[\dX]$""")

    /** China resident ID (GB 11643-1999): ISO 7064 MOD 11-2, check character may be X. */
    fun cnResidentId(input: String): Boolean {
        val s = stripWhitespaceUpper(input)
        if (!CN_SHAPE.matches(s)) return false
        val w = intArrayOf(7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
        val sum = (0 until 17).sumOf { (s[it] - '0') * w[it] }
        return "10X98765432"[sum % 11] == s[17]
    }

    /**
     * Korea RRN, for numbers issued before 20 Oct 2020.
     *
     * ADVISORY ONLY, never a gate: numbers issued from 20 Oct 2020 are randomly
     * assigned and carry no check digit.
     */
    fun krRrn(input: String): Boolean {
        val d = digitsOf(input)
        if (d.length != 13) return false
        val w = intArrayOf(2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)
        val sum = (0 until 12).sumOf { (d[it] - '0') * w[it] }
        return (11 - (sum % 11)) % 10 == d[12] - '0'
    }

    private val SG_SHAPE = Regex("""^[STFGM]\d{7}[A-Z]$""")

    /** Singapore NRIC/FIN (ICA): weights 2,7,6,5,4,3,2 and a prefix-dependent letter table. */
    fun sgNric(input: String): Boolean {
        val s = stripWhitespaceUpper(input)
        if (!SG_SHAPE.matches(s)) return false
        val w = intArrayOf(2, 7, 6, 5, 4, 3, 2)
        var sum = (0 until 7).sumOf { (s[1 + it] - '0') * w[it] }
        val prefix = s[0]
        if (prefix == 'T' || prefix == 'G') sum += 4
        if (prefix == 'M') sum += 3
        val table = when {
            prefix == 'S' || prefix == 'T' -> "JZIHGFEDCBA"
            prefix == 'M' -> "KLJNPQRTUWX"
            else -> "XWUTRQPNMLK"
        }
        return table[sum % 11] == s[8]
    }

    private val CF_ODD: Map<Char, Int> = buildMap {
        val digitValues = intArrayOf(1, 0, 5, 7, 9, 13, 15, 17, 19, 21)
        "0123456789".forEachIndexed { i, c -> put(c, digitValues[i]) }
        val letterValues = intArrayOf(
            1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18,
            20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23,
        )
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ".forEachIndexed { i, c -> put(c, letterValues[i]) }
    }

    private val CF_SHAPE = Regex("""^[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]$""")

    /** Italy codice fiscale (Agenzia delle Entrate): odd/even tables, mod 26, check letter. */
    fun itCodiceFiscale(input: String): Boolean {
        val s = stripWhitespaceUpper(input)
        if (!CF_SHAPE.matches(s)) return false
        var sum = 0
        for (i in 0 until 15) {
            val c = s[i]
            sum += when {
                i % 2 == 0 -> CF_ODD.getValue(c)
                c in '0'..'9' -> c - '0'
                else -> c - 'A'
            }
        }
        return ('A' + (sum % 26)) == s[15]
    }

    private val NIR_SHAPE = Regex("""^[12]\d{2}\d{2}(\d{2}|2A|2B)\d{3}\d{3}\d{2}$""")

    /** France NIR (Insee): 97-complement, Corsican 2A/2B mapped to 19/18 first. */
    fun frNir(input: String): Boolean {
        var s = stripWhitespaceUpper(input)
        if (!NIR_SHAPE.matches(s)) return false
        s = s.replaceFirst("2A", "19").replaceFirst("2B", "18")
        val body = s.substring(0, 13)
        val key = s.substring(13).toInt()
        return 97 - modDigits(body, 97) == key
    }

    /** Germany Steuer-IdNr (BZSt): ISO 7064 MOD 11,10 over 10 digits. */
    fun deSteuerId(input: String): Boolean {
        val d = digitsOf(input)
        if (d.length != 11 || d[0] == '0') return false
        var product = 10
        for (i in 0 until 10) {
            var sum = (d[i] - '0' + product) % 10
            if (sum == 0) sum = 10
            product = (sum * 2) % 11
        }
        var check = 11 - product
        if (check == 10) check = 0
        return check == d[10] - '0'
    }

    /** Thailand national ID (DOPA): weights 13..2, check = (11 - sum mod 11) mod 10. */
    fun thNationalId(input: String): Boolean {
        val d = digitsOf(input)
        if (d.length != 13) return false
        val sum = (0 until 12).sumOf { (d[it] - '0') * (13 - it) }
        return (11 - (sum % 11)) % 10 == d[12] - '0'
    }

    /** Canada SIN (Service Canada): Luhn over 9 digits. Advisory -- community-sourced. */
    fun caSin(input: String): Boolean = digitsOf(input).length == 9 && luhn(input)

    /** South Africa ID (SARS PAYE BRS Appendix B 8.3): Luhn over 13 digits. */
    fun zaId(input: String): Boolean = digitsOf(input).length == 13 && luhn(input)

    /** UAE Emirates ID (ICP): Luhn over 15 digits starting 784. Advisory. */
    fun aeEmiratesId(input: String): Boolean {
        val d = digitsOf(input)
        return d.length == 15 && d.startsWith("784") && luhn(d)
    }

    /** Saudi national ID / iqama: Luhn over 10 digits starting 1 or 2. Advisory. */
    fun saNationalId(input: String): Boolean {
        val d = digitsOf(input)
        return d.length == 10 && (d[0] == '1' || d[0] == '2') && luhn(d)
    }

    /** Keyed by the bundle's `checksum` field. */
    val functions: Map<String, (String) -> Boolean> = mapOf(
        "luhn" to ::luhn,
        "verhoeff" to ::verhoeff,
        "au_tfn" to ::auTfn,
        "au_abn" to ::auAbn,
        "au_medicare" to ::auMedicare,
        "uk_nhs" to ::ukNhs,
        "br_cpf" to ::brCpf,
        "br_cnpj" to ::brCnpj,
        "jp_my_number" to ::jpMyNumber,
        "cn_resident_id" to ::cnResidentId,
        "kr_rrn" to ::krRrn,
        "sg_nric" to ::sgNric,
        "it_codice_fiscale" to ::itCodiceFiscale,
        "fr_nir" to ::frNir,
        "de_steuer_id" to ::deSteuerId,
        "th_national_id" to ::thNationalId,
        "ca_sin" to ::caSin,
        "za_id" to ::zaId,
        "ae_emirates_id" to ::aeEmiratesId,
        "sa_national_id" to ::saNationalId,
    )
}
