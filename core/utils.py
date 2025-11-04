from django.core.mail import EmailMessage
import threading
from .task import send_verification_email

class utils:
    @staticmethod
    def send_email(subject, body, recipient):
        
        send_verification_email.delay(subject, body, recipient)


