package network.tork

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PiiDetectorTest {

    @Test
    fun `detects SSN pattern`() {
        val matches = PiiDetector.detect("SSN: 123-45-6789")
        assertEquals(1, matches.size)
        assertEquals(PiiType.SSN, matches[0].type)
        assertEquals("[REDACTED]", matches[0].match)
    }

    @Test
    fun `detects email pattern`() {
        val matches = PiiDetector.detect("Email: john.doe@example.com")
        assertEquals(1, matches.size)
        assertEquals(PiiType.EMAIL, matches[0].type)
    }

    @Test
    fun `detects various email formats`() {
        val emails = listOf(
            "simple@example.com",
            "very.common@example.com",
            "disposable.style.email.with+symbol@example.com",
            "user.name+tag@example.co.uk"
        )
        for (email in emails) {
            val matches = PiiDetector.detect(email)
            assertTrue(matches.isNotEmpty(), "Should detect: $email")
            assertEquals(PiiType.EMAIL, matches[0].type)
        }
    }

    @Test
    fun `detects phone number patterns`() {
        val phones = listOf(
            "555-123-4567",
            "(555) 123-4567",
            "555.123.4567",
            "+1 555-123-4567",
            "1-555-123-4567"
        )
        for (phone in phones) {
            assertTrue(PiiDetector.detect(phone).any { it.type == PiiType.PHONE }, "Should detect phone: $phone")
        }
    }

    @Test
    fun `detects credit card patterns`() {
        val cards = listOf(
            "4111-1111-1111-1111",
            "4111 1111 1111 1111",
            "4111111111111111"
        )
        for (card in cards) {
            assertTrue(PiiDetector.detect(card).any { it.type == PiiType.CREDIT_CARD }, "Should detect card: $card")
        }
    }

    @Test
    fun `detects IP address`() {
        val matches = PiiDetector.detect("Server IP: 192.168.1.1")
        assertEquals(1, matches.size)
        assertEquals(PiiType.IP_ADDRESS, matches[0].type)
    }

    @Test
    fun `detects street address`() {
        val matches = PiiDetector.detect("Ship to 123 Main Street please")
        assertTrue(matches.any { it.type == PiiType.ADDRESS })
    }

    @Test
    fun `detects date of birth`() {
        val matches = PiiDetector.detect("DOB: 12/25/1990")
        assertEquals(1, matches.size)
        assertEquals(PiiType.DATE_OF_BIRTH, matches[0].type)
    }

    @Test
    fun `detects passport number`() {
        val matches = PiiDetector.detect("Passport AB1234567")
        assertTrue(matches.any { it.type == PiiType.PASSPORT })
    }

    @Test
    fun `detects drivers license number`() {
        val matches = PiiDetector.detect("License D1234567")
        assertTrue(matches.any { it.type == PiiType.DRIVERS_LICENSE })
    }

    @Test
    fun `detects bank account number`() {
        val matches = PiiDetector.detect("Account 12345678901234")
        assertTrue(matches.any { it.type == PiiType.BANK_ACCOUNT })
    }

    @Test
    fun `detects multiple PII types`() {
        val text = "Contact: john@example.com, SSN: 123-45-6789, Phone: 555-123-4567"
        val matches = PiiDetector.detect(text)

        assertTrue(matches.size >= 3)
        assertTrue(matches.any { it.type == PiiType.EMAIL })
        assertTrue(matches.any { it.type == PiiType.SSN })
        assertTrue(matches.any { it.type == PiiType.PHONE })
    }

    @Test
    fun `no PII in clean text`() {
        val matches = PiiDetector.detect("This is a clean text with no personally identifiable information.")
        assertTrue(matches.isEmpty())
    }

    @Test
    fun `redacts PII in text`() {
        val text = "Email: test@example.com, SSN: 123-45-6789"
        val redacted = PiiDetector.redact(text)

        assertEquals("Email: [EMAIL_REDACTED], SSN: [SSN_REDACTED]", redacted)
        assertFalse(redacted.contains("test@example.com"))
        assertFalse(redacted.contains("123-45-6789"))
    }

    @Test
    fun `detectAndRedact returns full result`() {
        val text = "Card: 4111-1111-1111-1111, Email: user@test.com"
        val result = PiiDetector.detectAndRedact(text)

        assertTrue(result.hasPii)
        assertEquals(2, result.count)
        assertTrue(result.types.contains(PiiType.CREDIT_CARD))
        assertTrue(result.types.contains(PiiType.EMAIL))
        assertTrue(result.redactedText.contains("[CARD_REDACTED]"))
        assertTrue(result.redactedText.contains("[EMAIL_REDACTED]"))
    }

    @Test
    fun `empty string returns no matches`() {
        assertTrue(PiiDetector.detect("").isEmpty())
    }

    /**
     * Parity test for SDK-DECLARED-PII-TYPES-WITHOUT-PATTERNS-ACROSS-SDKS
     * (P1): every [PiiType] this SDK declares MUST have a live pattern in
     * [PiiDetector.getPatterns]. Every other SDK checked before this one
     * (JS, Java, and others) had declared types with no backing pattern -- a
     * type that would silently pass through detection unmasked. This test
     * fails the build the moment that regresses here, for any type, present
     * or future.
     */
    @Test
    fun `every declared PiiType has a live pattern (parity)`() {
        val patterns = PiiDetector.getPatterns()
        val missing = PiiType.entries.filter { !patterns.containsKey(it) }
        assertTrue(missing.isEmpty(), "PiiType constant(s) declared without a corresponding pattern: $missing")
    }

    /**
     * Confirms this SDK carries the full Tier 1 basic vocabulary (10 types)
     * shared with the JS/Java SDKs, with JS-identical string codes.
     */
    @Test
    fun `declares the JS Tier 1 basic vocabulary with identical codes`() {
        val expected = setOf(
            "ssn", "credit_card", "email", "phone", "address",
            "ip_address", "date_of_birth", "passport", "drivers_license", "bank_account"
        )
        val actual = PiiType.entries.map { it.code }.toSet()
        assertEquals(expected, actual)
    }
}
