import base64
import json

from webauthn import verify_authentication_response

from webauthn import generate_authentication_options
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from webauthn import verify_registration_response
from webauthn.helpers import options_to_json

from water_refilling_system.firebase_admin import (
    db,
    auth,
)

from .utils import create_registration_options


@csrf_exempt
@require_POST
def begin_registration(request):
    body = json.loads(request.body)

    firebase_uid = body["firebaseUid"]
    email = body["email"]
    display_name = body.get(
        "displayName",
        "Administrator",
    )

    options = create_registration_options(
        firebase_uid,
        email,
        display_name,
    )

    request.session["registration_challenge"] = options.challenge.hex()
    request.session["firebase_uid"] = firebase_uid

    return JsonResponse(
        json.loads(
            options_to_json(options)
        )
    )


@csrf_exempt
@require_POST
def finish_registration(request):
    body = json.loads(request.body)

    firebase_uid = request.session["firebase_uid"]
    challenge = request.session["registration_challenge"]

    verification = verify_registration_response(
        credential=body,
        expected_challenge=bytes.fromhex(challenge),
        expected_origin="https://kenjie.pythonanywhere.com",
        expected_rp_id="kenjie.pythonanywhere.com",
        require_user_verification=True,
    )

    db.collection("webauthn_credentials").document(firebase_uid).set(
        {
            "credential_id": base64.b64encode(
                verification.credential_id
            ).decode(),

            "public_key": base64.b64encode(
                verification.credential_public_key
            ).decode(),

            "sign_count": verification.sign_count,
        }
    )

    request.session.pop("registration_challenge", None)
    request.session.pop("firebase_uid", None)

    return JsonResponse({
        "success": True
    })


@csrf_exempt
@require_POST
def begin_authentication(request):

    allow_credentials = []

    for doc in db.collection("webauthn_credentials").stream():

        data = doc.to_dict()

        allow_credentials.append(

            PublicKeyCredentialDescriptor(

                id=base64.b64decode(
                    data["credential_id"]
                )

            )

        )

    options = generate_authentication_options(

        rp_id="kenjie.pythonanywhere.com",

        allow_credentials=allow_credentials,

    )

    request.session["authentication_challenge"] = (
        options.challenge.hex()
    )

    return JsonResponse(

        json.loads(

            options_to_json(options)

        )

    )


@csrf_exempt
@require_POST
def finish_authentication(request):

    body = json.loads(request.body)

    challenge = request.session.get(
        "authentication_challenge"
    )

    if not challenge:

        return JsonResponse(

            {
                "success": False,
                "message": "Authentication expired."
            },

            status=400,

        )

    credential_id = body["id"]

    firebase_uid = None
    credential = None

    for doc in db.collection(
        "webauthn_credentials"
    ).stream():

        data = doc.to_dict()

        if data["credential_id"] == credential_id:

            firebase_uid = doc.id
            credential = data

            break

    if credential is None:

        return JsonResponse(

            {
                "success": False,
                "message": "Credential not found."
            },

            status=404,

        )

    verification = verify_authentication_response(

        credential=body,

        expected_challenge=bytes.fromhex(challenge),

        expected_origin="https://kenjie.pythonanywhere.com",

        expected_rp_id="kenjie.pythonanywhere.com",

        credential_public_key=base64.b64decode(

            credential["public_key"]

        ),

        credential_current_sign_count=

            credential["sign_count"],

        require_user_verification=True,

    )

    db.collection(

        "webauthn_credentials"

    ).document(firebase_uid).update(

        {

            "sign_count":

                verification.new_sign_count

        }

    )

    request.session.pop(

        "authentication_challenge",

        None

    )

    custom_token = auth.create_custom_token(
    firebase_uid
)
    
    return JsonResponse(
    {
        "success": True,
        "token": custom_token.decode("utf-8"),
    }
)
    