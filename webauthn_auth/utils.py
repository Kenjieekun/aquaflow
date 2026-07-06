from django.conf import settings

from webauthn import generate_registration_options
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


def create_registration_options(firebase_uid, email, display_name):
    """
    Generate WebAuthn registration options for passkey/biometric enrollment.
    """

    return generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        rp_name=settings.WEBAUTHN_RP_NAME,

        user_id=firebase_uid.encode("utf-8"),
        user_name=email,
        user_display_name=display_name,

        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )