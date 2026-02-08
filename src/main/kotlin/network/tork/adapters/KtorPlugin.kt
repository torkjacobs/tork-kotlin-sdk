package network.tork.adapters

import network.tork.GovernanceReceipt
import network.tork.Tork

/**
 * Minimal HTTP request interface for Ktor integration.
 *
 * Implement this interface to bridge Ktor's request type.
 */
interface TorkHttpRequest {
    val method: String
    val path: String
    val bodyString: String?
}

/**
 * Minimal HTTP response interface for Ktor integration.
 *
 * Implement this interface to bridge Ktor's response type.
 */
interface TorkHttpResponse {
    var bodyString: String?
    var statusCode: Int
}

/**
 * Tork governance interceptor for Ktor.
 *
 * Intercepts HTTP requests and applies PII governance to request bodies.
 *
 * ```kotlin
 * val tork = Tork()
 * val interceptor = TorkKtorInterceptor(tork)
 *
 * // In your Ktor plugin:
 * val receipt = interceptor.intercept(request, response)
 * ```
 */
class TorkKtorInterceptor(
    private val tork: Tork,
    private val skipPaths: List<String> = emptyList()
) {

    /**
     * Intercept a request and apply governance to its body.
     *
     * Returns a [GovernanceReceipt] if governance was applied, or `null`
     * if the request was skipped (GET/HEAD/OPTIONS or skip path).
     */
    fun intercept(request: TorkHttpRequest, response: TorkHttpResponse): GovernanceReceipt? {
        // Skip non-mutating methods
        val method = request.method.uppercase()
        if (method in listOf("GET", "HEAD", "OPTIONS")) {
            return null
        }

        // Skip configured paths
        for (skip in skipPaths) {
            if (request.path.startsWith(skip)) {
                return null
            }
        }

        // Get body
        val body = request.bodyString
        if (body.isNullOrBlank()) {
            return null
        }

        // Govern
        val result = tork.govern(body)

        // Set governed body on response if PII was detected
        if (result.piiDetected.isNotEmpty()) {
            response.bodyString = result.output
        }

        return result.receipt
    }
}
