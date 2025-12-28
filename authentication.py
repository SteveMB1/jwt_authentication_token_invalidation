# auth_utils.py
from __future__ import annotations

import hashlib
import os
import random
import string
import uuid
from datetime import timedelta
from typing import Dict, Any, Optional
from typing import Union

import jwt
from bson import ObjectId
from fastapi import HTTPException, status, Request
from fastapi.openapi.models import Response

from common import current_utc_timestamp
from config import config
from database import mongo_db

# ──────────────────────────────────────────────────────────────────────────────────────────────
# Load RSA keys (EdDSA) from disk just as in NodeJS
# ──────────────────────────────────────────────────────────────────────────────────────────────

_current_dir = os.path.dirname(os.path.abspath(__file__))

# Build the path to jwt_keys/1/…
_keys = {
    "1": {
        "private": open(
            os.path.join(_current_dir, "jwt_keys", "1", "private_key.pem"),
            "r",
            encoding="utf-8"
        ).read(),
        "public": open(
            os.path.join(_current_dir, "jwt_keys", "1", "public_key.pem"),
            "r",
            encoding="utf-8"
        ).read(),
    }
}


# ──────────────────────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────────────────────

def generate_random_string(length: int) -> str:
    """
    generateRandomString: picks from [A-Za-z0-9].
    """
    characters = string.ascii_letters + string.digits
    return "".join(random.choice(characters) for _ in range(length))


async def create_pass(
        plain_pw: str,
        hash_function: str = "sha512",
        salt: Union[bytes, str] = None
) -> dict:
    """
    Generate a random salt (UUID4) if none provided;
    then PBKDF2‐SHA512 with 100k iterations, outputting raw bytes.
    Returns {
        "secret": <bytes>,
        "salt": <bytes>,
        "digest": <str>  # typically "sha512"
    }.

    When storing in MongoDB, both `secret` and `salt` will be stored as binary (BSON) fields.
    When returned in a FastAPI response, Pydantic will base64‐encode these bytes automatically.
    """

    # If caller didn’t pass in a salt, create a new random UUID4 salt (16 bytes).
    if salt is None:
        new_uuid = uuid.uuid4()
        salt_bytes = new_uuid.bytes
    else:
        # If salt was loaded from DB as a string, interpret as raw bytes
        if isinstance(salt, str):
            # Treat the stored string as a hex‐encoded salt string:
            try:
                salt_bytes = bytes.fromhex(salt)
            except ValueError:
                # If it isn’t valid hex, assume it’s plain text UTF‐8
                salt_bytes = salt.encode("utf-8")
        else:
            # Already bytes
            salt_bytes = salt

    # Derive a 64‐byte key using PBKDF2‐HMAC‐SHA512
    dk = hashlib.pbkdf2_hmac(
        hash_name=hash_function,
        password=plain_pw.encode("utf-8"),
        salt=salt_bytes,
        iterations=100_000,
        dklen=64
    )

    return {
        "secret": dk,  # raw bytes of the derived key
        "salt": salt_bytes,  # raw bytes of the salt
        "digest": hash_function
    }


async def check_pass(
        plain_pw: str,
        secret: Union[bytes, str],
        salt: Union[bytes, str],
        digest: str
) -> bool:
    """
    Re‐derive the key and compare to the stored secret.
    Accepts `secret` and `salt` as either raw bytes or strings:
      - If `salt` is a string, we first try hex-decoding it; if that fails, we UTF‑8 encode.
      - If `secret` is a string, we compare against its hex form; otherwise, compare raw bytes.
    """
    # Normalize salt → bytes
    if isinstance(salt, str):
        try:
            salt_bytes = bytes.fromhex(salt)
        except ValueError:
            # Not valid hex, assume plain UTF‑8
            salt_bytes = salt.encode("utf-8")
    else:
        salt_bytes = salt

    # Derive 64‑byte key with PBKDF2‐HMAC
    derived = hashlib.pbkdf2_hmac(
        hash_name=digest,
        password=plain_pw.encode("utf-8"),
        salt=salt_bytes,
        iterations=100000,
        dklen=64
    )

    # Compare against stored secret
    if isinstance(secret, str):
        # Assume stored secret is hex‐encoded
        return derived.hex() == secret
    else:
        # raw bytes comparison
        return derived == secret


# ──────────────────────────────────────────────────────────────────────────────────────────────
# JWT Signing / Verification
# ──────────────────────────────────────────────────────────────────────────────────────────────

async def sign_token(payload: dict, needs_mfa_verification: bool, public_ip: str = None) -> dict[str, Any]:
    """
    - payload must include "userId" (a string or ObjectId).
      If token=False, payload must also include "uniqueId" and "sequence".
    - If token=True, we generate a fresh uniqueId & sequence=0.
      Otherwise, we verify old (uniqueId, sequence), bump it, and re‐sign.
    - When there are >15 entries, we clear them all to avoid unbounded growth.
    """
    try:
        # 1) Ensure `userId` is an ObjectId
        raw_id = payload.get("userId")

        # 2) Pick the highest numeric `kid` for signing
        key_ids = sorted(_keys.keys(), key=lambda k: int(k))
        last_kid = key_ids[-1]

        # 3) Fetch only the nested `token_sequences` map
        doc = await mongo_db["accounts"].find_one(
            {"_id": ObjectId(raw_id)}
        )
        if not doc:
            return {"error": "User not found."}

        token_sequences = doc.get("token_sequences", {}) or {}

        # 4) If >15 outstanding UIDs, clear all
        if len(token_sequences) > 15:
            await mongo_db["accounts"].update_one(
                {"_id": ObjectId(raw_id)},
                {"$unset": {"token_sequences": ""}}
            )
            token_sequences = {}

        # 5) Determine UID and bump-only-the-sequence
        existing_uid = payload.get("uniqueId")

        if existing_uid is None:
            # very first issuance for this device/user
            uid = generate_random_string(4)
            while uid in token_sequences:
                uid = generate_random_string(4)
            sequence = 0
        else:
            # reuse the same UID each time
            uid = existing_uid
            if uid not in token_sequences:
                return {"error": "Authentication error; please sign out and sign in again."}
            sequence = token_sequences[uid] + 1

        payload["uniqueId"] = uid
        payload["sequence"] = sequence

        # 6) Persist just the bumped sequence under the same UID
        nested_field = f"token_sequences.{uid}"
        await mongo_db["accounts"].update_one(
            {"_id": ObjectId(raw_id)},
            [
                # ensure token_sequences exists
                {"$set": {"token_sequences": {"$ifNull": ["$token_sequences", {}]}}},
                # update only this UID’s sequence
                {"$set": {nested_field: sequence}}
            ],
            upsert=True
        )

        # 8) Prepare JWT payload
        #    Remove any old exp/iat, then set fresh ones
        payload.pop("exp", None)
        payload.pop("iat", None)
        payload["userId"] = str(raw_id)
        payload["publicIP"] = str(public_ip)
        payload['ask_for_mfa'] = False
        payload["needs_mfa_verification"] = {}
        payload["needs_mfa_verification"]['result'] = needs_mfa_verification
        payload["needs_mfa_verification"]['userId'] = payload["userId"]
        issued = current_utc_timestamp()
        expiry = issued + timedelta(seconds=int(config.JWT_EXPIRATION_SECONDS))

        for user_roles in doc.get("roles", []):
            if user_roles.get("type", {}) == "vet":
                payload['ask_for_mfa'] = True

        jwt_payload = {**payload, "iat": issued, "exp": expiry}

        # 9) Sign with EdDSA
        token = jwt.encode(
            payload=jwt_payload,
            key=_keys[last_kid]["private"],
            algorithm="EdDSA",
            headers={"kid": last_kid}
        )

        return {"userId": payload["userId"],
                "token": token,
                "needs_mfa_verification": payload["needs_mfa_verification"]
                }

    except Exception as e:
        print("Error in sign_token:", e)
        return {"error": "An error occurred while signing the token."}


# (Assume _keys is a dict mapping 'kid' → { "public": <public_key> })
# and sign_token(payload: Dict[str, Any], token: bool) is defined elsewhere.

async def verify_token(token: str, public_ip: str = None) -> Dict[str, Any]:
    """
    - Decode the JWT using the public key (EdDSA).
    - If valid & unexpired: return the payload.
    - If expired: decode again (verify_exp=False), rotate via sign_token(), and return an error + token.
    - On other failures: return an error.
    """
    # 1) Read the unverified header for `kid`
    try:
        unverified = jwt.get_unverified_header(token)
    except jwt.DecodeError:
        return {"error": "Invalid token (cannot parse header)."}

    kid = unverified.get("kid")
    if not kid or kid not in _keys:
        return {"error": "Unknown key ID in token header."}

    pub = _keys[kid]["public"]

    # 2) Try normal decode (verifies signature & expiration)
    try:
        payload = jwt.decode(
            token,
            key=pub,
            algorithms=["EdDSA"],
            options={"require_exp": True}
        )

        if ((payload.get("needs_mfa_verification", {}).get("result") is True or payload.get("publicIP") != public_ip)
                and payload['ask_for_mfa']):
            return {
                "ok": False,
                "payload": payload,
                "error": "MFA is required.",
                "needs_mfa_verification": {
                    "result": True
                }
            }

        # 3) Verify that the stored sequence matches
        user_oid = ObjectId(payload["userId"])
        uid = payload["uniqueId"]
        seq = payload["sequence"]

        # This filter matches both _id and the nested sequence in one go
        exists = await mongo_db["accounts"].find_one({
            "_id": user_oid,
            f"token_sequences.{uid}": seq
        })

        if not exists:
            return {"error": "Token is expired; mismatched sequence."}

        return payload

    except jwt.ExpiredSignatureError:
        # Expired: decode without exp check to get userId/uniqueId/sequence
        payload_no_exp = jwt.decode(
            token,
            key=pub,
            algorithms=["EdDSA"],
            options={"verify_exp": False}
        )

        if payload_no_exp['ask_for_mfa']:
            return {
                "ok": False,
                "payload": payload_no_exp,
                "error": "MFA is required.",
                "needs_mfa_verification": {
                    "result": True
                }
            }

        # 4) Rotate via sign_token()
        try:
            new_jwt = await sign_token(payload_no_exp,
                                       needs_mfa_verification=False,
                                       public_ip=public_ip)
        except Exception as e:
            return {"error": f"Failed to rotate expired token: {e}"}

        # Otherwise tell the caller we rotated
        return {
            "error": "Token expired; issued a rotated token automatically.",
            **new_jwt
        }



    except jwt.InvalidAlgorithmError:
        return {"error": "Token uses an invalid algorithm."}
    except jwt.InvalidSignatureError:
        return {"error": "Invalid token signature."}
    except jwt.InvalidTokenError:
        return {"error": "Expired token could not be decoded to extract payload."}
    except Exception as e:
        return {"error": f"Unexpected error during token verification: {e}"}


async def validate_and_extract_payload(
        token: str,
        response: Response,
        public_ip: str = None
) -> Dict[str, Any]:
    result = await verify_token(token=token, public_ip=public_ip)

    # if it failed, we still want to surface a token header if one was issued
    if not isinstance(result, dict) or result.get("error") is not None:
        new_token = result.get("token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result,
            headers={"X-New-Token": new_token} if new_token else None
        )

    # on success, if we got a rotation/token marker, return it in a header
    if "token" in result:
        response.headers["X-New-Token"] = result["token"]
    if "error" in result:
        raise result
    return result


def get_client_ip(req: Request) -> Optional[str]:
    """
    Best-effort client IP extraction with proxy awareness.
    Order matters: prefer X-Forwarded-For (left-most), then X-Real-IP, then connection host.
    NOTE: Trust X-Forwarded-For only if your deployment controls the proxy (e.g., behind a known LB).
    """
    # Normalize header access (Starlette headers are case-insensitive)
    xff = req.headers.get("x-forwarded-for")
    if xff:
        # Could be a comma-separated list: client, proxy1, proxy2 ...
        # We take the first non-empty trimmed token.
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[0]

    xri = req.headers.get("x-real-ip")
    if xri:
        return xri.strip()

    # Cloudflare / other CDNs sometimes provide these:
    cf_ip = req.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip.strip()

    # Fallback to connection peer info
    if req.client and req.client.host:
        return req.client.host

    return None
