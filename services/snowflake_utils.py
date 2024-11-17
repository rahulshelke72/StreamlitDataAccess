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

def fetch_users(connector_connection):
    try:
        query = "SHOW USERS"

        # Execute the query using the Snowflake connector connection
        cursor = connector_connection.cursor()
        cursor.execute(query)

        # Fetch and process the results
        users = cursor.fetchall()

        # Extract column headers
        columns = [col[0] for col in cursor.description]

        # Convert the data to a list of dictionaries for better usability
        user_list = [dict(zip(columns, row)) for row in users]

        cursor.close()
        return user_list  # Return the list of users

    except Exception as e:
        print(f"An error occurred while fetching users: {e}")
        return []

def fetch_role_names():
    """Fetch all role names from Snowflake."""
    sql = "SELECT NAME FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES ORDER BY NAME ASC"
    roles = session.sql(sql).collect()
    return [role.NAME for role in roles]


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

def fetch_users_from_accounts(conn):
    """
    Fetch the list of users from the user_accounts table.
    :param conn: Snowflake connection object
    :return: List of users
    """
    query = """
    SELECT username AS name FROM user_accounts
    WHERE role IN ('USER', 'SYSADMIN', 'ACCOUNTADMIN');
    """
    try:
        with conn.cursor() as cur:
            cur.execute(query)
            users = cur.fetchall()
        return [{"name": user[0]} for user in users]
    except Exception as e:
        raise Exception(f"Error fetching users: {str(e)}")


def fetch_roles_from_accounts(conn):
    """
    Fetch the list of roles from the user_accounts table.
    :param conn: Snowflake connection object
    :return: List of roles
    """
    query = """
    SELECT DISTINCT role AS name FROM user_accounts
    WHERE role IS NOT NULL;
    """
    try:
        with conn.cursor() as cur:
            cur.execute(query)
            roles = cur.fetchall()
        return [{"name": role[0]} for role in roles]
    except Exception as e:
        raise Exception(f"Error fetching roles: {str(e)}")
