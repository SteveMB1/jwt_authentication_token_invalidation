# File: src/routes/auth.py
from __future__ import annotations

import base64
import random
import re
from datetime import datetime
from typing import Any
from typing import Optional

import httpx
from bson import ObjectId
from fastapi import Depends, HTTPException, status, Response
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from pydantic import field_validator
from starlette.requests import Request

from authentication import check_pass, create_pass, sign_token, validate_and_extract_payload, get_client_ip
from common import validate_and_normalize_phone, checksum_dep, ChecksumModel, body_with_checksum
from config import config, TWILIO
from database import mongo_db
from main import router, bearer_scheme


# ────────────────────────────────────────────────────────────────────────────────
# GET /api/login_banner
# ────────────────────────────────────────────────────────────────────────────────
@router.get("/api/login_banner", status_code=status.HTTP_200_OK)
async def login_banner() -> dict:
    """
    Return the configured login page banner (static content from config).
    """
    return {"banner": config.LOGIN_PAGE_BANNER}


# ────────────────────────────────────────────────────────────────────────────────
# GET /api/user/login
# ────────────────────────────────────────────────────────────────────────────────
class LoginResponse(ChecksumModel):
    token: str
    roles: list[str]


class LoginQuery(ChecksumModel):
    """Query-string schema for /api/user/login."""
    email: Optional[EmailStr] = Field(
        None, description="User email (lower-case)")
    phone: Optional[str] = Field(
        None, description="User phone (digits, no '+')")
    password: str = Field(
        ..., description="Plain-text password")


@router.get(
    "/api/user/login",
    response_model=LoginResponse,
    status_code=status.HTTP_201_CREATED,
)
async def user_login(
        request: LoginQuery = Depends(),
        checksum_ok: bool = Depends(checksum_dep(LoginQuery)),
) -> dict[str, dict | str | list[Any] | Any]:
    """
    Authenticate a user by email or phone + password.
    On success, return a JWT token and list of roles.
    """

    if not checksum_ok:
        raise HTTPException(status_code=400, detail="Invalid data checksum.")

    # Ensure password is provided
    if not request.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The values you entered are incorrect.",
        )

    # Build filter: either by email or phone
    if request.email:
        filter_query = {"email": request.email.lower().strip()}
    elif request.phone:
        filter_query = {"phone": int(validate_and_normalize_phone(str(request.phone)))}

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The values you entered are incorrect.",
        )

    try:
        user_record = await mongo_db["accounts"].find_one(filter_query)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not fulfill request.",
        )

    if not user_record:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid phone number.",
        )

    # Verify password
    passwd_ok = await check_pass(
        request.password,
        user_record["password"]["secret"],
        user_record["password"]["salt"],
        user_record["password"]["digest"],
    )
    if not passwd_ok:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid password.",
        )

    # Check legalLock
    if user_record.get("legalLock", False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=config.LEGAL_LOCK_MSG,
        )

    # Generate new JWT
    token = await sign_token({"userId": user_record["_id"]}, True)
    return {"token": token, "roles": user_record.get("roles", [])}


# ────────────────────────────────────────────────────────────────────────────────
# DELETE /api/profiles/logout/
# ────────────────────────────────────────────────────────────────────────────────
class LogOut(ChecksumModel):
    all_devices: bool


@router.post('/api/auth/logout')
async def verify_mfa(
        request: Request,
        response: Response,
        checksum_data=Depends(body_with_checksum(LogOut)),

        credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    try:
        body, checksum_ok = checksum_data
        if not checksum_ok:
            raise HTTPException(status_code=400, detail="Invalid data checksum.")

        raw_token = credentials.credentials

        req_data = await validate_and_extract_payload(
            token=raw_token,
            response=response,
            public_ip=get_client_ip(request)
        )

        user_id_str = req_data["userId"]

        if body.all_devices:
            await mongo_db['accounts'].update_one(
                {"_id": ObjectId(user_id_str)},
                {"$unset": {
                    f"token_sequences": "",
                }}
            )

        else:
            await mongo_db['accounts'].update_one(
                {"_id": ObjectId(user_id_str)},
                {"$unset": {
                    f"token_sequences.{req_data['uniqueId']}": "",
                }}
            )

        # 11) On success, return confirmation
        return {
            "ok": True
        }

    except Exception as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not fulfill authentication request.",
        )


# ────────────────────────────────────────────────────────────────────────────────
# POST /api/user/recovery/initialize
# ────────────────────────────────────────────────────────────────────────────────
class RecoveryInitRequest(ChecksumModel):
    phone: str = Field(..., description="Phone number used to register account.")


@router.post("/api/user/recovery/initialize", status_code=status.HTTP_200_OK)
async def recovery_initialize(
        checksum_data=Depends(body_with_checksum(RecoveryInitRequest)),
) -> dict:
    """
    Generate a recovery code and upsert it into passwordRecovery for the given phone,
    then send an SMS with that code.
    """

    request, checksum_ok = checksum_data

    if not checksum_ok:
        raise HTTPException(status_code=400, detail="Invalid data checksum.")

    # Normalize phone: digits only, expect 11 digits (e.g. '1XXXXXXXXXX')
    digits = re.sub(r"\D", "", validate_and_normalize_phone(request.phone))
    if len(digits) != 11:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The values you entered are incorrect.",
        )

    # Generate 6-digit recovery code
    recovery_code = random.randint(100000, 999999)

    # Find account by phone
    try:
        find_account = await mongo_db["accounts"].find_one({"phone": int(digits)})
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not fulfill request.",
        )

    if not find_account:
        return {"error": "We are unable to find an account with that phone number."}

    # Upsert into passwordRecovery
    try:
        await mongo_db["passwordRecovery"].update_one(
            {"_id": find_account["_id"]},
            {
                "$set": {
                    "createdAt": datetime.utcnow(),
                    "recoveryCode": int(recovery_code),
                    "phone": int(find_account["phone"]),
                }
            },
            upsert=True,
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Recovery attempt has failed.",
        )

    # If update_one succeeded (acknowledged), send SMS via Twilio
    try:
        account_sid = config.TWILIO[TWILIO.account_sid]
        auth_token = config.TWILIO[TWILIO.auth_token]
        basic_token = base64.b64encode(f"{account_sid}:{auth_token}".encode()).decode()

        sms_data = {
            "To": f"+{find_account['phone']}",
            "From": config.TWILIO[TWILIO.phone_number],
            "Body": f"{config.APP_NAME} login code is: {recovery_code}",
        }

        async with httpx.AsyncClient() as client:
            await client.post(
                f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json",
                data=sms_data,
                headers={
                    "Authorization": f"Basic {basic_token}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
    except Exception:
        pass

    return {"success": "Please check your text messages for login code."}


# ────────────────────────────────────────────────────────────────────────────────
# POST /api/user/recovery/newpassword
# ────────────────────────────────────────────────────────────────────────────────
class RecoveryNewPasswordRequest(BaseModel):
    phone: int
    code: int
    password: str

    @field_validator("phone")
    def validate_and_normalize_phone_api(cls, v: str) -> str:
        return validate_and_normalize_phone(str(v))


@router.post("/api/user/recovery/newpassword", status_code=status.HTTP_200_OK)
async def recovery_new_password(
        checksum_data=Depends(body_with_checksum(RecoveryNewPasswordRequest)),
) -> dict:
    """
    Validate phone + recovery code, then update the user's password.
    """
    request, checksum_ok = checksum_data

    if config.PAYLOAD_ENCRYPTION_CHECKSUM_KEY is not None and not checksum_ok:
        raise HTTPException(status_code=400, detail="Invalid data checksum.")

    # Lookup account and recovery record
    try:
        find_account = await mongo_db["accounts"].find_one({"phone": int(request.phone)})
        find_recovery = await mongo_db["passwordRecovery"].find_one(
            {"phone": int(request.phone), "recoveryCode": int(request.code)}
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not fulfill request.",
        )

    if not find_account or not find_recovery or str(find_account["_id"]) != str(find_recovery["_id"]):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="We are unable to find an account with that phone number and confirmation code.",
        )

    # Update password in profiles
    try:
        new_pass_entry = await create_pass(request.password)
        await mongo_db["accounts"].update_one(
            {"_id": find_account["_id"]},
            {"$set": {"password": new_pass_entry}},
        )
        # Delete any existing recovery records
        await mongo_db["passwordRecovery"].delete_many(
            {"phone": int(request.phone), "recoveryCode": int(request.code)}
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed.",
        )

    return {"success": "Password successfully changed!"}
