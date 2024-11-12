import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from config.email_config import EMAIL_HOST, EMAIL_PORT, EMAIL_ADDRESS, EMAIL_PASSWORD, ACCOUNTADMIN_EMAIL


def send_request_email(username, request_type, request_details, app_url):
    """Send an email to the AccountAdmin when a new request is submitted."""
    subject = f"New Request from {username}: {request_type}"
    body = f"User '{username}' has submitted a request of type '{request_type}' with details:\n\n{request_details}\n\n" \
           f"Please review this request on the approval panel: <a href='{app_url}'><u>Snowflake Request Management System</u></a>"

    send_email(ACCOUNTADMIN_EMAIL, subject, body)


def send_user_notification_email(username, request_type, request_details, approved):
    """Send an email to the user notifying them of the approval or rejection."""
    subject = f"Your Request for {request_type} has been {'Approved' if approved else 'Rejected'}"
    body = f"Hello {username},\n\nYour request for '{request_type}' with the following details:\n\n{request_details}\n\n" \
           f"has been {'approved' if approved else 'rejected'}.\n\nThank you,\nAccountAdmin Team"

    send_email(EMAIL_ADDRESS, subject, body)


def send_email(to_address, subject, body):
    """Send an email using SMTP."""
    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_address
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
