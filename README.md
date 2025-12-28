# Auth & Login (FastAPI + MongoDB + JWT)

Simple authentication module for a FastAPI app using:

- **Password hashing**: PBKDF2-HMAC (default `sha512`, 100,000 iterations, 64-byte derived key)
- **JWT auth**: **EdDSA** signed tokens (RSA key files stored on disk)
- **MongoDB-backed token invalidation**: per-device/per-session token sequence tracking
- **Optional MFA enforcement**: based on roles + public IP mismatch or explicit MFA requirement
- **Password recovery via SMS (Twilio)**

---

## Files

### `authentication.py`
Provides helper utilities:

- `create_pass(plain_pw, hash_function="sha512", salt=None)`  
  Creates a salted PBKDF2 hash object suitable for MongoDB storage.
- `check_pass(plain_pw, secret, salt, digest)`  
  Recomputes PBKDF2 and compares with stored secret.
- `sign_token(payload, needs_mfa_verification, public_ip=None)`  
  Creates a JWT and stores/bumps a per-`uniqueId` token `sequence` in MongoDB (`accounts.token_sequences`).
- `verify_token(token, public_ip=None)`  
  Verifies JWT signature/expiration and checks `token_sequences` to prevent replay.
  If expired, attempts to automatically rotate (issue a new token) unless MFA is required.
- `validate_and_extract_payload(token, response, public_ip=None)`  
  Wrapper around `verify_token` that raises `401` on failure and sets `X-New-Token` header when rotated.
- `get_client_ip(request)`  
  Best-effort IP extraction (`X-Forwarded-For`, `X-Real-IP`, `cf-connecting-ip`, fallback to socket IP).

### `login.py`
Defines FastAPI routes:

- `GET /api/login_banner`  
  Returns `config.LOGIN_PAGE_BANNER`.
- `GET /api/user/login`  
  Login using **email or phone + password**, returns JWT + roles.
- `POST /api/auth/logout`  
  Logs out from current device/session or all devices by unsetting `token_sequences`.
- `POST /api/user/recovery/initialize`  
  Generates a 6-digit recovery code and sends it via Twilio SMS.
- `POST /api/user/recovery/newpassword`  
  Validates recovery code and updates the password.

---

## How it works

### Password storage
Passwords are stored in MongoDB in a structure like:

```json
{
  "password": {
    "secret": "<bytes>",
    "salt": "<bytes>",
    "digest": "sha512"
  }
}
```

> MongoDB stores `secret` and `salt` as BSON binary. If returned via API, Pydantic may base64 encode bytes.

### JWT + token sequence tracking (logout / invalidation)
Each token includes:
- `userId`
- `uniqueId` (short random ID per device/session)
- `sequence` (monotonically increasing integer)

MongoDB stores:
- `accounts.token_sequences.<uniqueId> = <sequence>`

A token is considered valid only if the sequence in MongoDB matches the sequence inside the JWT. Logging out deletes the relevant sequence entry (or all of them).

This enables:
- “logout this device”
- “logout all devices”
- invalidation of older tokens for the same `uniqueId`

---

## Requirements

Typical dependencies (not exhaustive):

- `fastapi`, `starlette`
- `pyjwt` (JWT with EdDSA support)
- `pydantic`
- `motor` or async MongoDB driver (your `mongo_db` wrapper)
- `bson` / `pymongo`
- `httpx` (Twilio request)

---

## Configuration & keys

### JWT keys
Keys are loaded from disk:

```
<project>/jwt_keys/1/private_key.pem
<project>/jwt_keys/1/public_key.pem
```

The `"kid"` header is used to select a public key for verification.

### Expected config values
Used fields include:

- `config.JWT_EXPIRATION_SECONDS`
- `config.LOGIN_PAGE_BANNER`
- `config.LEGAL_LOCK_MSG`
- `config.APP_NAME`
- `config.TWILIO[...]` values:
  - account SID
  - auth token
  - sending phone number
- `config.PAYLOAD_ENCRYPTION_CHECKSUM_KEY` (used to decide checksum enforcement)

---

## API notes

### Authentication header
Endpoints that require auth (e.g. logout) expect:

```
Authorization: Bearer <jwt>
```

### Token rotation header
If an expired token is rotated automatically, the new token may be returned via:

- Response header: `X-New-Token: <token>`

Clients should watch for this and replace the stored token.

---

## Limitations / considerations

- **Trusting client IP headers** (`X-Forwarded-For`) is safe only behind a trusted proxy/load balancer.
- Token sequences are capped: if more than **15** `uniqueId` entries exist, the code clears all sequences to avoid unbounded growth.
- MFA behavior depends on:
  - user roles (e.g. role `type == "vet"` sets `ask_for_mfa`)
  - `publicIP` mismatch and the `needs_mfa_verification` flag
- Twilio SMS errors are swallowed (`except: pass`) in recovery initialization—delivery failure may not be reported.

---

## Quick local testing ideas

1. Ensure MongoDB is configured and `accounts` collection contains a user with a stored `password` object.
2. Place EdDSA keys under `jwt_keys/1/`.
3. Run the FastAPI app and call:
   - `GET /api/user/login?email=...&password=...`
   - Use returned token for `POST /api/auth/logout`

