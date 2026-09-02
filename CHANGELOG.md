# Changelog

## 0.2.0 - 2026-09-03

### Added
- feat: `Tork#scanToolResult` / `ToolResultScanner.scanToolResult` — on-device tool-result scanning for PII and prompt-injection heuristics before a tool result is appended to model context (DECIDED-TACT2-V2-C), with a `tool_result_scan` receipt block byte-identical (snake_case, alphabetical keys) to the JS/Java SDKs
- feat: `PiiDetector` now carries the full Tier 1 basic vocabulary (10 types: ssn, credit_card, email, phone, address, ip_address, date_of_birth, passport, drivers_license, bank_account), up from 5, with JS-identical string codes and redaction labels
- test: parity test asserting every declared `PiiType` has a live pattern (SDK-DECLARED-PII-TYPES-WITHOUT-PATTERNS-ACROSS-SDKS)

### Changed
- `PiiType` enum constants now carry a `code` (JS-identical string) and `redaction` label
- `GovernanceReceipt` gained an optional `toolResultScan` field, present only on receipts produced by `scanToolResult`

## 0.1.2 - 2026-03-09

### Added
- feat: agent/session context fields (agent_id, agent_role, session_id, session_turn)
