import smtplib
from email.mime.text import MIMEText
from email.header import Header
import os
from dotenv import load_dotenv

load_dotenv()

FROM_EMAIL = os.getenv("FROM_EMAIL")
BCC_EMAIL = os.getenv("BCC_EMAIL")
PASSWORD = os.getenv("PASSWORD")

class SendEmail:

    def __init__(self):
        pass

    def send_email(self, inquiry):
        recipient_name = inquiry["name"]
        recipient_email = inquiry["email"]
        category = inquiry["category"]
        message = inquiry["message"]
        subject = f"[WAY]Sent a message successfully!"
        body = f'''
Hi {recipient_name},

Thank you for reaching out to us!

Your email address:
{recipient_email}

Your message:
[{category}]
{message}

I am actively looking into this, I will get back to you at the earliest, appreciate your patience.

---
Who Are You Team
'''
        with smtplib.SMTP("smtp.gmail.com", 587) as connection:
            connection.starttls()
            connection.login(user=FROM_EMAIL, password=PASSWORD)
            msg = MIMEText(body.encode('utf-8'), _subtype='plain', _charset='utf-8')
            msg['Subject'] = Header(subject.encode('utf-8'), 'utf-8')
            msg['From'] = FROM_EMAIL
            msg['To'] = recipient_email
            msg['Bcc'] = BCC_EMAIL
            connection.send_message(msg)
            print("Email sent successfully!")