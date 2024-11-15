from config.snowflake_connection import session,connector_connection
import streamlit as st


def get_user_role(username: str, connector_connection):
    try:
        username_upper = username.upper()
        query = f"SHOW GRANTS TO USER {username_upper}"

        # Execute the query using the Snowflake connector connection
        cursor = connector_connection.cursor()
        cursor.execute(query)

        # Fetch and process the results
        grants = cursor.fetchall()

        # Check if any grants are returned
        if grants:
            # Return the first role (assuming only one role is granted to the user)
            role = grants[0][1].strip()  # Stripping any leading/trailing spaces
            cursor.close()
            return role
        else:
            cursor.close()
            return None  # Return None if no grants are found

    except Exception as e:
        print(f"An error occurred while retrieving grants for user {username}: {e}")
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