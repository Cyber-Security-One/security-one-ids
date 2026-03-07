## 2024-05-15 - [Unauthenticated Endpoints Executing Shell Commands]
**Vulnerability:** Several endpoints in `routes/api.php` (`/api/system/update`, `/api/system/version`, `/api/system/restart`, `/api/rules/update`) exposed functionality to trigger OS-level commands (like `git pull` or `supervisorctl restart all`) completely unauthenticated. Authentication was only applied inline within one specific route (`/api/settings/sync`).
**Learning:** Due to a lack of shared middleware for the `api` route group, new API endpoints were added sequentially without considering global authentication. Security logic was duplicated and omitted on dangerous operational endpoints.
**Prevention:** Implement group-level authentication middleware for related protected endpoints. Ensure that all routes executing high-privilege operations or modifying global state require strict authentication tokens. Avoid applying authentication only inside route closures where it can be easily missed on subsequent additions.

## 2026-03-07 - Secure Token Comparison
**Vulnerability:** API endpoints in `routes/api.php` verified authentication tokens using simple string comparison (`!==`), which is vulnerable to timing attacks.
**Learning:** String comparison returns immediately on the first mismatched character, allowing an attacker to theoretically guess tokens character-by-character by measuring response times.
**Prevention:** Always use `hash_equals()` for secure, constant-time token or password verification to prevent timing attacks. Ensure variables are cast to strings before comparison and check for empty values to prevent bypasses.
