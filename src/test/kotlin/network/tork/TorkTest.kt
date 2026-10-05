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

    @Test
    fun `agent telemetry fields pass through govern when set`() {
        val ctx = SessionContext(agentId = "agent-7", agentRole = "planner", sessionId = "sess-1", sessionTurn = 3)
        val result = Tork().govern("hello", ctx)
        assertEquals(ctx, result.sessionContext)
        assertEquals(
            mapOf("agent_id" to "agent-7", "agent_role" to "planner", "session_id" to "sess-1", "session_turn" to 3),
            result.sessionContext!!.toWireMap()
        )
    }

    @Test
    fun `agent telemetry fields pass through GovernOptions`() {
        val ctx = SessionContext(agentId = "a", sessionTurn = 1)
        val result = Tork().govern("hello", GovernOptions(sessionContext = ctx))
        assertEquals(ctx, result.sessionContext)
    }

    @Test
    fun `agent telemetry fields are omitted when not set`() {
        assertEquals(null, Tork().govern("hello").sessionContext)
        assertEquals(emptyMap(), SessionContext().toWireMap())
        assertEquals("{}", SessionContext().toWireJson())
        val partial = SessionContext(sessionId = "s")
        assertEquals(mapOf("session_id" to "s"), partial.toWireMap())
        assertFalse(partial.toWireJson().contains("agent_id"))
    }

    @Test
    fun `session turn is an integer on the wire and strings are escaped`() {
        val json = SessionContext(agentId = "a\"b", sessionTurn = 2).toWireJson()
        assertEquals("{\"agent_id\":\"a\\\"b\",\"session_turn\":2}", json)
    }
}
