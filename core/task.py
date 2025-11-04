from celery import shared_task
from django.core.mail import EmailMessage

@shared_task
def send_verification_email(self , subject, body , recipient):
    try:
       email = EmailMessage(
        subject = subject,
        body = body,
        to=[recipient],
       )
       email.send()
       return " Email sent successfully"
    except Exception as e:
       
       self.retry(exc=e, countdown=10)
