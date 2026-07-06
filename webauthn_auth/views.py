import json
import base64

from webauthn.helpers import options_to_json

from .utils import create_registration_options

from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt

from webauthn import verify_registration_response
from water_refilling_system.firebase_admin import db

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

    request.session["registration_challenge"] = (
        options.challenge.hex()
    )

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

    db.collection("webauthn_credentials").document(firebase_uid).set({
        "credential_id": base64.b64encode(
            verification.credential_id
        ).decode(),

        "public_key": base64.b64encode(
            verification.credential_public_key
        ).decode(),

        "sign_count": verification.sign_count,
    })

    return JsonResponse({
        "success": True
    })


@csrf_exempt
@require_POST
def begin_authentication(request):
    return JsonResponse({
        "success": True
    })


@csrf_exempt
@require_POST
def finish_authentication(request):
    return JsonResponse({
        "success": True
    })