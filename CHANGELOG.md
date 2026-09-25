# Changelog

## 0.3.0 - 2026-09-25

### Added
- **PII registry bundle 1.2.0 (24 countries, incl. AU TFN/ABN/Medicare).**
  Patterns, keywords, redaction labels and checksum gates are generated from
  Tork's own country registry and consumed verbatim from the SDK bundle
  (`Registry-Version: 1.2.0`, content `cfd4f61ebaf45e74`). Countries: AU, US, GB, EU, AE, SA, NG, IN, JP,
  CN, KR, BR, CA, ZA, GH, IT, KE, MU, MX, MY, PK, SG, TH, ID. Bundle 1.2.0 adds
  `au_tfn`, `au_abn` and `au_medicare` as `alwaysOn` patterns — they run on
  every document, gated only by their own keyword, not by region activation —
  closing the "AU bundle gap" that left Australia catching only an ACN and a
  +61 phone number. `au_tfn` and `au_abn` have required checksums (`au_tfn`
  falls back to a generic near-miss redaction on a failing check digit;
  `au_abn` has no near-miss fallback and is dropped outright); `au_medicare`'s
  checksum is advisory and never blocks detection.
- New package `network.tork.governance.pii`: `TORK_PII_PATTERNS` (the bundle's
  54 patterns), `TORK_PII_SIGNALS` and `TORK_PII_COUNTRY_PATTERNS` (the 51
  activation signals and the country map), `PiiChecksums` (20 algorithms) and
  `PiiCountry` (the matcher). All pure and local: no network, no clock.
- `PiiDetectionResult` gains `countryMatches`, `countryLabels` and `regions`,
  all defaulting to empty, so the existing four-argument construction still
  compiles. `PiiDetector.detectAndRedact(text, regions)` forces a set of
  country profiles on; the single-argument overload is unchanged and is kept
  callable from Java via `@JvmOverloads`.
- **Nine check digits ported by hand.** The bundle names twenty algorithms and
  specifies the eleven that reduce to a weight vector and a modulus; the other
  nine (`br_cpf`, `br_cnpj`, `cn_resident_id`, `de_steuer_id`, `fr_nir`,
  `it_codice_fiscale`, `jp_my_number`, `kr_rrn`, `sg_nric`) are ported from the
  cloud's `lib/pii/checksums.ts`, each tested against the issuing authority's
  own worked example where one is published.
- Gson at test scope only, to read the parity fixtures. The published artifact
  gains no new dependency.

### Fixed
- **SDK-KOTLIN-PARTIAL-REDACTION.** Until 0.2.0 `redact` applied each pattern in
  turn over text a previous pattern had already rewritten, while `detect`
  reported ranges into the *original* text. Two types matching overlapping spans
  could leave half an identifier standing beside a redaction token -- digits
  exposed in output the caller had been told was redacted. Every match is now
  collected against the original text, overlaps are resolved before anything is
  rewritten, and the surviving spans are spliced right to left in one pass.
  `nothing is ever partially redacted` asserts the invariant across all 268
  vectors. `redact` now delegates to `detectAndRedact`, so there is one
  implementation of the redaction rules.

### Notes
- **PUBLISHING: this artifact has never been published, and its coordinate is
  not deployable as it stands.** `network.tork` is not a verified namespace on
  Maven Central, and nothing under it exists there. The Java SDK's coordinate
  was corrected this release to `io.github.torkjacobs:tork-governance`, which
  IS published (0.1.0) -- so this module must NOT simply move to
  `io.github.torkjacobs:tork-governance` or it would clobber the Java artifact.
  A distinct artifactId (for example `tork-governance-kotlin`) is needed. Left
  unchanged here because it is a naming decision, not a defect to fix silently.
- **The bundle now states the whole contract, and this SDK implements it.**
  Bundle 1.0.0's README documented three rules; measured against the cloud's
  golden snapshot they disagreed with it on 14 of 86 country-corpus cases, so
  this SDK carried two more of its own. Bundle **1.1.0 documents seven**, marks
  each SDK or cloud-only, and ships the data all seven need in every language
  file -- the activation signals, the country map, the asymmetric 60/40 window,
  the symmetric 60 context window, the whole-word vocabulary, the near-miss
  policy, the table constants and the reference labels. So the locally generated
  activation layer is **deleted**, no window is hard-coded any more, and rules 6
  (near miss), 7 (column header) and 7b (nearest label) are implemented here for
  the first time. Every rule now reads its data off the placed bundle.
- Advisory checksums never reject a match: `ca_sin`, `emirates_id`,
  `de_tax_id`, `kr_rrn`, `sa_national_id`. Korea stopped issuing check digits on
  20 Oct 2020.
- Not ported, and still cloud-only: the slot, context,
  gravity and name layers, industry profiles, and org configuration.
- **Indonesia is the country 1.1.0 added, and it is the one that proves the
  whole-word rule.** `id_nik`'s only short spellings -- NIK, KTP, NPWP -- are
  `wholeWordKeywords`, not ordinary keywords, because `nik` sits inside
  *teknik*, *elektronik*, *klinik* and *pabrik*. Matching them by substring
  would open the gate on an Indonesian sales ledger; matching them on a word
  boundary catches "NIK 3171010101900001" and leaves *teknik* alone. An SDK that
  merged the two lists would be shipping a false-positive bug, so the boundary
  test is implemented rather than the shortcut, and four unit cases assert both
  halves.
- **RESOLVED in bundle 1.2.0 (was: FLAGGED upstream in 1.1.0) — Australia's
  TFN, ABN and Medicare number are now detected.** Bundle 1.1.0 shipped
  `checksums.json` entries for `au_tfn`/`au_abn`/`au_medicare` with no matching
  pattern (the AU profile carried only `au_acn` and `au_phone_intl`), so the
  activation signals switched Australia on for identifiers the bundle had no
  pattern to catch — a recall gap no SDK could close on its own. 1.2.0 ships
  the three as `alwaysOn` patterns (README.md rule 1a), and `PiiCountry`
  (this SDK's engine, not the bundle) now runs `alwaysOn` patterns on every
  document ahead of region-activated ones, per that rule, so an unactivated
  case like the ABN's own corpus sentence — "Supplier ABN 51 824 753 556
  appears on the Australian invoice.", which triggers no AU region signal —
  still gets caught. The eleven parity cases this closes are no longer
  recorded as `BUNDLE GAP` in the fixture; the AU bundle gap cause is 0.

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
