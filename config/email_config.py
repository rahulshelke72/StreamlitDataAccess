import os
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = os.getenv("EMAIL_PORT")
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# Recipient email
ACCOUNTADMIN_EMAIL = os.getenv("ACCOUNTADMIN_EMAIL")
