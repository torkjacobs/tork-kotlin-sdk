# Tork Governance Kotlin SDK

On-device AI governance with PII detection, redaction, and cryptographic receipts for Kotlin and Ktor applications.

## Installation

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("network.tork:tork-governance:0.1.0")
}
```

### Gradle (Groovy)

```groovy
dependencies {
    implementation 'network.tork:tork-governance:0.1.0'
}
```

### Maven

```xml
<dependency>
    <groupId>network.tork</groupId>
    <artifactId>tork-governance</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Quick Start

```kotlin
import network.tork.Tork

val tork = Tork()

val result = tork.govern("My SSN is 123-45-6789")
println(result.action)               // REDACT
println(result.output)               // "My SSN is [SSN_REDACTED]"
println(result.piiDetected)          // [PiiMatch(type=SSN, ...)]
println(result.receipt.receiptId)    // "rcpt_..."
```

## PII Detection

```kotlin
import network.tork.PiiDetector

val matches = PiiDetector.detect("Email: john@example.com, SSN: 123-45-6789")
// [PiiMatch(type=SSN, ...), PiiMatch(type=EMAIL, ...)]

val redacted = PiiDetector.redact("SSN: 123-45-6789")
// "SSN: [SSN_REDACTED]"
```

### Supported PII Types

| Type | Example | Redaction |
|------|---------|-----------|
| SSN | 123-45-6789 | [SSN_REDACTED] |
| Credit Card | 4111-1111-1111-1111 | [CARD_REDACTED] |
| Email | john@example.com | [EMAIL_REDACTED] |
| Phone | 555-123-4567 | [PHONE_REDACTED] |
| IP Address | 192.168.1.1 | [IP_REDACTED] |

## Ktor Integration

```kotlin
import network.tork.Tork
import network.tork.adapters.TorkKtorInterceptor

val tork = Tork()
val interceptor = TorkKtorInterceptor(tork)

// In your Ktor application:
install(createApplicationPlugin("TorkGovernance") {
    onCall { call ->
        val request = KtorRequestAdapter(call.request)
        val response = KtorResponseAdapter(call.response)
        val receipt = interceptor.intercept(request, response)
        if (receipt != null) {
            call.attributes.put(TorkReceiptKey, receipt)
        }
    }
})
```

## Cryptographic Receipts

Every governance operation generates a verifiable receipt:

```kotlin
val result = tork.govern("Sensitive data")

println(result.receipt.receiptId)    // Unique ID
println(result.receipt.timestamp)    // ISO 8601 timestamp
println(result.receipt.inputHash)    // SHA-256 of input
println(result.receipt.outputHash)   // SHA-256 of output
println(result.receipt.piiCount)     // Number of PII detected
println(result.receipt.action)       // REDACT
```

## Configuration

```kotlin
import network.tork.Tork
import network.tork.TorkConfig
import network.tork.GovernanceAction

val tork = Tork(TorkConfig(
    policyVersion = "2.0.0",
    defaultAction = GovernanceAction.DENY
))
```

## License

MIT
