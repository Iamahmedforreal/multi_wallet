from celery import shared_task
from django.core.mail import EmailMessage

@shared_task(bind=True , max_retries=3)
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
