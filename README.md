# Tork Governance Kotlin SDK

On-device AI governance with PII detection, redaction, and cryptographic receipts for Kotlin and Ktor applications.

## Installation

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("network.tork:tork-governance:0.3.0")
}
```

### Gradle (Groovy)

```groovy
dependencies {
    implementation 'network.tork:tork-governance:0.3.0'
}
```

### Maven

```xml
<dependency>
    <groupId>network.tork</groupId>
    <artifactId>tork-governance</artifactId>
    <version>0.3.0</version>
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

## Country PII detection

23 country profiles, 50 patterns and 20 check digits, generated from Tork's own
country registry (bundle `1.0.0`) and computed entirely on-device.

Countries: AU, US, GB, EU, AE, SA, NG, IN, JP, CN, KR, BR, CA, ZA, GH, IT, KE,
MU, MX, MY, PK, SG, TH.

A country's patterns switch on when the text activates that country — the same
content signals the cloud uses — so ordinary business text is not measured
against 50 national-identifier patterns it could never contain. On the
1,159-line business corpus this SDK is tested against, nothing is redacted.

```kotlin
import network.tork.PiiDetector

val r = PiiDetector.detectAndRedact(
    "South African ID number 8001015009087 for the FICA check."
)
r.regions        // ["ZA"]
r.countryLabels  // ["ZA_ID"]
r.redactedText   // "South African ID number [ZA_ID_REDACTED] for the FICA check."
```

Force profiles on when you already know the jurisdiction:

```kotlin
val forced = PiiDetector.detectAndRedact(
    "Documento 529.982.247-25 arquivado.", listOf("br")
)
// forced.redactedText == "Documento [CPF_REDACTED] arquivado."
```

Three gates keep the false-positive rate down, and all three must pass:

1. **Activation** — one of the country's content signals fires.
2. **Keyword** — for 18 of the 24 national, tax and health identifiers, one of
   the identifier's keywords must appear within 60 characters before the match
   or 40 after.
3. **Check digit** — for the 10 identifiers whose issuing authority publishes
   the algorithm, a number of the right shape that fails its check digit is not
   that country's identifier. Where the algorithm is community-sourced rather
   than authority-published (`ca_sin`, `emirates_id`, `de_tax_id`, `kr_rrn`,
   `sa_national_id`) the checksum is advisory and never rejects a match.

Still cloud-only, and not in this SDK: the near-miss fallback, the slot,
context, gravity and name layers, industry profiles, and org configuration.

## PII Detection

```kotlin
import network.tork.PiiDetector

val matches = PiiDetector.detect("Email: john@example.com, SSN: 123-45-6789")
// [PiiMatch(type=SSN, ...), PiiMatch(type=EMAIL, ...)]

val redacted = PiiDetector.redact("SSN: 123-45-6789")
// "SSN: [SSN_REDACTED]"
```

### Supported PII Types

Tier 1 basic vocabulary (10 types), shared with the JS/Java SDKs with identical string codes. This SDK does not carry the Python SDK's regional/industry pattern tier (AU/US/GB/EU/AE/... profiles) as part of this vocabulary — see [Regional PII Detection](#regional-pii-detection-v11) for that separate, older mechanism.

| Type | Code | Example | Redaction |
|------|------|---------|-----------|
| SSN | `ssn` | 123-45-6789 | [SSN_REDACTED] |
| Credit Card | `credit_card` | 4111-1111-1111-1111 | [CARD_REDACTED] |
| Email | `email` | john@example.com | [EMAIL_REDACTED] |
| Phone | `phone` | 555-123-4567 | [PHONE_REDACTED] |
| Address | `address` | 123 Main Street | [ADDRESS_REDACTED] |
| IP Address | `ip_address` | 192.168.1.1 | [IP_REDACTED] |
| Date of Birth | `date_of_birth` | 01/15/1990 | [DOB_REDACTED] |
| Passport | `passport` | AB1234567 | [PASSPORT_REDACTED] |
| Driver's License | `drivers_license` | D1234567 | [DL_REDACTED] |
| Bank Account | `bank_account` | 12345678901234 | [ACCOUNT_REDACTED] |

## Scanning tool results

A tool result returned by an MCP server — or any external system you do not control — is untrusted input that is about to be appended to a model's context. `tork.scanToolResult()` scans it first, on-device, for PII and prompt injection:

```kotlin
import network.tork.Tork
import network.tork.ToolResultScanInput
import network.tork.ToolResultScanOptions

val tork = Tork()
val scan = tork.scanToolResult(
    ToolResultScanInput(
        toolName = "lookup_customer",
        payload = toolResult,           // whatever the server returned
        serverUri = "mcp://crm.internal/customers"
    ),
    ToolResultScanOptions(blockOnInjection = true)
)

if (scan.blocked) {
    println(scan.reason)                // do not append anything
} else {
    appendToContext(scan.sanitized)     // PII masked in place
}

scan.findings
// [ToolResultFinding(kind=PII, type=email, count=1, location=$.content[0].text),
//  ToolResultFinding(kind=INJECTION, type=heuristic:instruction_override, count=1, location=$.content[0].text)]
```

There is also a standalone `ToolResultScanner.scanToolResult(input, options)` with the same signature that returns `ToolResultScanResult(sanitized, findings, blocked, reason?)` and produces no receipt.

- **PII uses the same on-device detector as `govern()`** — same patterns, same redaction labels. Matches are masked in place; the payload structure is otherwise unchanged, and a clean payload comes back untouched (same object identity).
- **Injection detection is heuristic.** A conservative pattern set (`tork-injection-heuristics-v1`) covering instruction-override phrases, role reassignment, and exfiltration URLs. Every injection finding is typed `heuristic:<name>` because that is exactly what it is: a regex match over untrusted text, with false positives and false negatives, not a verified determination. Without `blockOnInjection`, matches are reported and the result is still returned; with it, `sanitized` is `null` so no masked copy can be appended by accident.
- **Zero network calls.** The scan is pure and synchronous — no socket, no I/O, no clock read.
- **Recorded on the receipt as counts only.** `receipt.toolResultScan` carries `attested_by: "client"`, `capture_mode: "edge"`, the tool name and server URI, counts by kind and type, the blocked flag, and the SDK version. It never carries the payload, a matched value, or a location path.

**This is a client-side, client-attested control.** The scan runs in your process, and the receipt says so: Tork did not execute it and cannot verify it ran at all. **Gateway-side enforcement, where a caller cannot skip the scan, is a separate and later control.** Do not read a `tool_result_scan` block as proof that every tool result reaching a model was scanned; read it as a record of the scans a caller chose to run and report.

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
