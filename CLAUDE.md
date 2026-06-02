# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

PHP library (yaac) for obtaining Let's Encrypt SSL/TLS certificates via ACME V2 protocol (RFC 8555). Returns certificate data as objects — does not write to the filesystem directly. Only the LE account key is persisted via Flysystem.

## Setup

```bash
composer install
```

No test suite, linter, CI, or static analysis is configured.

## Architecture

**Namespace**: `Jason\Acme\` (PSR-4, maps to `src/`)

**Dependencies**: PHP 8.3+, `ext-openssl`, `ext-json`, `guzzlehttp/guzzle ^7.0`, `league/flysystem ^3.0`

### Certificate Lifecycle (Client.php)

1. `new Client($config)` — takes `fs` (Flysystem instance), `username`, `mode` (MODE_LIVE / MODE_STAGING). Fetches LE directory, loads or generates RSA account key, agrees to ToS.
2. `createOrder(array $domains)` → `Order`
3. `authorize(Order)` → `Authorization[]` (each holds `Challenge[]`)
4. `selfTest(Authorization, type)` — pre-validation check (HTTP fetches the token URL; DNS queries Cloudflare DoH)
5. `validate(Challenge)` — tells LE to validate, polls until `valid`
6. `getCertificate(Order)` — generates EC P-384 key + CSR with SAN, finalizes order, returns `Certificate`

### Key Design Decisions

- **Two JWS signing modes**: `signPayloadJWK()` for account creation (includes full JWK), `signPayloadKid()` for all subsequent requests (uses account URL as `kid`).
- **Nonce management**: caches `replay-nonce` from each response; fetches fresh via HEAD when needed.
- **Account keys**: RSA 4096-bit, stored at `{basePath}/{user}/account.pem` via Flysystem.
- **CSR keys**: EC P-384 (`secp384r1`), generated fresh per certificate request.

### Data Objects (src/Data/)

Simple DTOs with constructor injection and getters: `Account`, `Order`, `Authorization`, `Challenge`, `Certificate`, `File` (HTTP challenge), `Record` (DNS TXT record).

### Helper (src/Helper.php)

Static utilities: PEM↔DER conversion, key generation (RSA + EC), CSR creation with SAN, base64url encoding, certificate chain splitting.
