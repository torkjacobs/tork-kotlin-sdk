package network.tork

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class TorkTest {

    @Test
    fun `clean text passes through`() {
        val tork = Tork()
        val result = tork.govern("Hello, world!")

        assertEquals(GovernanceAction.ALLOW, result.action)
        assertEquals("Hello, world!", result.output)
        assertTrue(result.piiDetected.isEmpty())
    }

    @Test
    fun `detects SSN`() {
        val tork = Tork()
        val result = tork.govern("My SSN is 123-45-6789")

        assertEquals(GovernanceAction.REDACT, result.action)
        assertTrue(result.output.contains("[SSN_REDACTED]"))
        assertFalse(result.output.contains("123-45-6789"))
        assertTrue(result.piiDetected.any { it.type == PiiType.SSN })
    }

    @Test
    fun `detects email`() {
        val tork = Tork()
        val result = tork.govern("Contact john@example.com for details")

        assertEquals(GovernanceAction.REDACT, result.action)
        assertTrue(result.output.contains("[EMAIL_REDACTED]"))
        assertFalse(result.output.contains("john@example.com"))
        assertTrue(result.piiDetected.any { it.type == PiiType.EMAIL })
    }

    @Test
    fun `redacts multiple PII types`() {
        val tork = Tork()
        val result = tork.govern("SSN: 123-45-6789, email: admin@secret.com")

        assertEquals(GovernanceAction.REDACT, result.action)
        assertTrue(result.output.contains("[SSN_REDACTED]"))
        assertTrue(result.output.contains("[EMAIL_REDACTED]"))
        assertFalse(result.output.contains("123-45-6789"))
        assertFalse(result.output.contains("admin@secret.com"))
        assertTrue(result.piiDetected.size >= 2)
    }

    @Test
    fun `generates receipt with SHA256 hash`() {
        val tork = Tork()
        val result = tork.govern("My SSN is 123-45-6789")

        assertTrue(result.receipt.receiptId.startsWith("rcpt_"))
        assertTrue(result.receipt.inputHash.startsWith("sha256:"))
        assertTrue(result.receipt.outputHash.startsWith("sha256:"))
        assertTrue(result.receipt.inputHash != result.receipt.outputHash)
        assertTrue(result.receipt.piiCount > 0)
        assertEquals(GovernanceAction.REDACT, result.receipt.action)
        assertTrue(result.receipt.timestamp.isNotEmpty())
    }
}
