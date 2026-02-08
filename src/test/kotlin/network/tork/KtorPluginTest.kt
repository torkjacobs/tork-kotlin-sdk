package network.tork

import network.tork.adapters.TorkHttpRequest
import network.tork.adapters.TorkHttpResponse
import network.tork.adapters.TorkKtorInterceptor
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class MockRequest(
    override val method: String,
    override val path: String,
    override val bodyString: String?
) : TorkHttpRequest

class MockResponse(
    override var bodyString: String? = null,
    override var statusCode: Int = 200
) : TorkHttpResponse

class KtorPluginTest {

    @Test
    fun `governs POST body with PII`() {
        val tork = Tork()
        val interceptor = TorkKtorInterceptor(tork)

        val request = MockRequest("POST", "/chat", "My SSN is 123-45-6789")
        val response = MockResponse()

        val receipt = interceptor.intercept(request, response)

        assertNotNull(receipt)
        assertTrue(receipt.receiptId.startsWith("rcpt_"))
        assertTrue(receipt.piiCount > 0)
        assertNotNull(response.bodyString)
        assertTrue(response.bodyString!!.contains("[SSN_REDACTED]"))
    }

    @Test
    fun `skips GET requests`() {
        val tork = Tork()
        val interceptor = TorkKtorInterceptor(tork)

        val request = MockRequest("GET", "/chat", "My SSN is 123-45-6789")
        val response = MockResponse()

        val receipt = interceptor.intercept(request, response)

        assertNull(receipt)
        assertNull(response.bodyString)
    }

    @Test
    fun `returns receipt with correct piiCount`() {
        val tork = Tork()
        val interceptor = TorkKtorInterceptor(tork)

        val request = MockRequest("POST", "/api", "SSN: 123-45-6789, email: test@example.com")
        val response = MockResponse()

        val receipt = interceptor.intercept(request, response)

        assertNotNull(receipt)
        assertTrue(receipt.piiCount >= 2)
        assertEquals(GovernanceAction.REDACT, receipt.action)
    }
}
