import os
from dotenv import load_dotenv
from snowflake.snowpark import Session

# Load environment variables from the .env file
load_dotenv()

def create_snowflake_session():
    # Define Snowflake connection parameters from environment variables
    snowflake_conn_params = {
        "user": os.getenv("SNOWFLAKE_USER"),
        "password": os.getenv("SNOWFLAKE_PASSWORD"),
        "account": os.getenv("SNOWFLAKE_ACCOUNT"),
        "warehouse": os.getenv("SNOWFLAKE_WAREHOUSE"),
        "database": os.getenv("SNOWFLAKE_DATABASE"),
        "schema": os.getenv("SNOWFLAKE_SCHEMA")
    }

    # Create and return a Snowflake session
    session = Session.builder.configs(snowflake_conn_params).create()
    return session

# Initialize the Snowflake session for use in other files
session = create_snowflake_session()
