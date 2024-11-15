import os
import snowflake
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


# Create and return a Snowflake connector connection for administrative queries
def create_snowflake_connector_connection():
    # Define Snowflake connection parameters from environment variables
    snowflake_conn_params = {
        "user": os.getenv("SNOWFLAKE_USER"),
        "password": os.getenv("SNOWFLAKE_PASSWORD"),
        "account": os.getenv("SNOWFLAKE_ACCOUNT"),
        "warehouse": os.getenv("SNOWFLAKE_WAREHOUSE"),
        "database": os.getenv("SNOWFLAKE_DATABASE"),
        "schema": os.getenv("SNOWFLAKE_SCHEMA")
    }

    # Create and return a Snowflake connector connection
    connection = snowflake.connector.connect(**snowflake_conn_params)
    return connection

# Initialize the Snowflake session for use in other files
session = create_snowflake_session()

# Optionally initialize the Snowflake connector connection for administrative tasks
connector_connection = create_snowflake_connector_connection()

