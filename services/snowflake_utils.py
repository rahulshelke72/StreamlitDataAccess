from config.snowflake_connection import session
import streamlit as st


def get_user_role(username: str) -> str:
    """Get the primary role of the user from the account usage grants view."""
    try:
        sql = f"""
        SELECT DEFAULT_ROLE AS ROLE
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
        WHERE NAME = '{username}'
        LIMIT 1;
        """
        result = session.sql(sql).collect()[0][0]
        if result:
            return result
        else:
            st.error(f"No roles found for user {username}.")
            return None
    except Exception as e:
        st.error(f"Failed to retrieve role for user {username}: {e}")
        return None

def check_user_role():
    """Check current user's role."""
    current_role = session.sql("SELECT CURRENT_ROLE()").collect()[0][0]
    return current_role

def get_available_databases():
    """Fetch a list of available databases for selection."""
    try:
        result = session.sql("SHOW DATABASES").collect()
        return [row['name'] for row in result]
    except Exception as e:
        st.error(f"Failed to fetch databases: {e}")
        return []

def get_available_schemas(database_name: str):
    """Fetch a list of available schemas for a specific database."""
    try:
        sql = f"SHOW SCHEMAS IN DATABASE {database_name}"
        result = session.sql(sql).collect()
        return [row['name'] for row in result]
    except Exception as e:
        st.error(f"Failed to fetch schemas for database {database_name}: {e}")
        return []

def get_available_tables(database_name: str, schema_name: str):
    """Fetch a list of available tables for a specific schema in a database."""
    try:
        sql = f"SHOW TABLES IN SCHEMA {database_name}.{schema_name}"
        result = session.sql(sql).collect()
        return [row['name'] for row in result]
    except Exception as e:
        st.error(f"Failed to fetch tables for schema {schema_name} in database {database_name}: {e}")
        return []