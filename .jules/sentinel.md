## 2024-05-15 - [Fixed: Disabled SSL Peer Verification for Downloads]
**Vulnerability:** SSL peer verification was explicitly disabled (`'verify_peer' => false`, `'verify_peer_name' => false`) in stream context creation when downloading the CA certificate bundle (`cacert.pem`) in `ClamavService` and `WafSyncService`. This allows Man-in-the-Middle (MitM) attacks.
**Learning:** Disabling SSL verification to bootstrap trust (downloading a CA bundle to establish secure connections) creates a Catch-22 and exposes the application to MitM attacks where a malicious CA bundle could be injected.
**Prevention:** Bundle a known-good CA certificate bundle within the application repository itself rather than attempting to download it insecurely at runtime. When the certificate is missing, "fail closed" (throw an exception) instead of falling back to disabling TLS verification. Note: The bundled `resources/certs/cacert.pem` should be updated periodically from the official source (`https://curl.se/ca/cacert.pem`) to ensure trust stores remain current.

## 2024-05-15 - [Unauthenticated Endpoints Executing Shell Commands]
**Vulnerability:** Several endpoints in `routes/api.php` (`/api/system/update`, `/api/system/version`, `/api/system/restart`, `/api/rules/update`) exposed functionality to trigger OS-level commands (like `git pull` or `supervisorctl restart all`) completely unauthenticated. Authentication was only applied inline within one specific route (`/api/settings/sync`).
**Learning:** Due to a lack of shared middleware for the `api` route group, new API endpoints were added sequentially without considering global authentication. Security logic was duplicated and omitted on dangerous operational endpoints.
**Prevention:** Implement group-level authentication middleware for related protected endpoints. Ensure that all routes executing high-privilege operations or modifying global state require strict authentication tokens. Avoid applying authentication only inside route closures where it can be easily missed on subsequent additions.

## 2025-02-28 - Insecure Token Comparison (Timing Attack)
**Vulnerability:** API routes protecting agent updates and settings were secured with `!==` string comparison on `AGENT_TOKEN`, which opens a side-channel for timing attacks.
**Learning:** Checking secure tokens with standard operators (`==` or `===`) stops comparison on the first mismatched character, leading to timing variations that can be measured and exploited to extract a token.
**Prevention:** Always use `hash_equals()` for token or password verification and cast values to strings beforehand.

## 2025-03-10 - OS Command Injection via Unsanitized User Inputs in Shell Execution
**Vulnerability:** Unsanitized system variables (like `$consoleUser` and `$user`) derived from dynamic system states were directly interpolated into string commands passed to `exec()` functions (e.g., `exec("sudo dscl . -delete /Users/{$user} ...")`).
**Learning:** Any variable that is incorporated into a shell command, even if originating from a seemingly trustworthy system query (such as listing user accounts), poses a command injection risk or syntax error risk if the data contains spaces, quotes, or shell metacharacters.
**Prevention:** Always use `escapeshellarg()` on any dynamic variable before inserting it into a shell command executed via `exec()`, `shell_exec()`, or `system()`.