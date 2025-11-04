from django.core import signing
from django.core.mail import EmailMessage
from django.conf import settings
from django.utils import timezone
from .tasks import send_verification_email


SALT = 'email-verification-salt'
DEFAULT_EXPIRY_SECONDS = 60 * 60 * 24  # 24 hours


def generate_verification_token(user):
    """Return a time-stamped signed token for the given user."""
    payload = {
        'user_id': str(user.id),
        'ts': int(timezone.now().timestamp()),
    }
    token = signing.dumps(payload, salt=SALT)
    return token


def verify_verification_token(token, max_age=DEFAULT_EXPIRY_SECONDS):
    """Verify and return payload if token is valid. Raises BadSignature/SignatureExpired on failure."""
    try:
        payload = signing.loads(token, salt=SALT, max_age=max_age)
        return payload
    except Exception:
        raise


def build_verification_url(token) -> str:
    """Build a full verification URL using SITE_URL from settings (falls back to localhost)."""
    site = getattr(settings, 'SITE_URL', 'http://localhost:8000')
    site = site.rstrip('/')
    return f"{site}/auth/verify-email/?token={token}"


def send_verification_to_user(user):
    """Construct verification email and enqueue sending via Celery task.

    This function only enqueues the sending task; the actual send is performed in `core.tasks.send_verification_email`.
    """
    token = generate_verification_token(user)
    link = build_verification_url(token)
    subject = 'Verify your email address'
    body = (
        f"Hi {user.first_name or ''},\n\n"
        "Thanks for signing up. Please verify your email address by clicking the link below:\n\n"
        f"{link}\n\n"
        "If you did not create an account, you can ignore this message.\n\n"
        "Thanks,\nThe Team"
    )

    # Enqueue email send via Celery
    try:
        send_verification_email.delay(subject, body, user.email)
    except Exception:
        # As a fallback, try synchronous send so registration flow can still proceed in dev envs
        try:
            email = EmailMessage(subject=subject, body=body, to=[user.email])
            email.send()
        except Exception:
            # swallow here; calling code should handle or log as needed
            pass


