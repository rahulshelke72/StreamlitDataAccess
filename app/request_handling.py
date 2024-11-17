from services.snowflake_utils import session,get_user_role,connector_connection
import streamlit as st
from services.email_utils import send_request_email, send_user_notification_email
import re


def submit_request(username, request_type, request_details):
    # Insert request into database with initial NULL values for approval columns
    sql = f"""
    INSERT INTO REQUESTS (USERNAME, REQUEST_TYPE, REQUEST_DETAILS, STATUS, REQUEST_DATE, ACCOUNTADMIN_APPROVAL, SYSADMIN_APPROVAL)
    VALUES ('{username}', '{request_type}', '{request_details}', 'PENDING', CURRENT_TIMESTAMP(), NULL, NULL);
    """
    session.sql(sql).collect()
    st.success(f"Request of type '{request_type}' submitted successfully.")

    # Send email notification to AccountAdmin
    try:
        app_url = "http://localhost:8501"
        send_request_email(username, request_type, request_details, app_url)
        st.info("Notification email sent to AccountAdmin.")
    except Exception as e:
        st.error(f"Request submitted, but failed to send email notification: {e}")

def show_pending_requests():
    """Fetch all requests with their statuses and approval columns for the admin panel"""
    sql = """
    SELECT REQUEST_ID, USERNAME, REQUEST_TYPE, REQUEST_DETAILS, REQUEST_DATE, STATUS, ACCOUNTADMIN_APPROVAL, SYSADMIN_APPROVAL
    FROM REQUESTS 
    ORDER BY REQUEST_DATE DESC;
    """
    return session.sql(sql).collect()

def update_approval_status(request_id: int, approved: bool, role: str, rejection_reason: str = None):
    """Update approval status for the specified role and evaluate the overall request status."""

    # Determine which columns to update based on the role
    if role == "ACCOUNTADMIN":
        approval_column = "ACCOUNTADMIN_APPROVAL"
        reason_column = "ACCOUNTADMIN_REJECTION_REASON"
    elif role == "SYSADMIN":
        approval_column = "SYSADMIN_APPROVAL"
        reason_column = "SYSADMIN_REJECTION_REASON"
    else:
        raise ValueError("Invalid role specified")

    # Update the respective approval and reason columns
    sql_update_approval = f"""
    UPDATE REQUESTS
    SET {approval_column} = {approved},
        {reason_column} = '{rejection_reason}'  -- If rejection, store the reason
    WHERE REQUEST_ID = {request_id};
    """
    session.sql(sql_update_approval).collect()

    # Retrieve current approval statuses for the request
    approval_status = session.sql(f"""
        SELECT ACCOUNTADMIN_APPROVAL, SYSADMIN_APPROVAL, ACCOUNTADMIN_REJECTION_REASON, SYSADMIN_REJECTION_REASON
        FROM REQUESTS
        WHERE REQUEST_ID = {request_id};
    """).collect()[0]
    accountadmin_approval, sysadmin_approval, accountadmin_rejection_reason, sysadmin_rejection_reason = approval_status

    # Determine final status based on both approvals
    if accountadmin_approval is False or sysadmin_approval is False:
        final_status = "REJECTED"
        rejection_reason = accountadmin_rejection_reason if accountadmin_approval is False else sysadmin_rejection_reason
    elif accountadmin_approval is True and sysadmin_approval is True:
        final_status = "APPROVED"
    else:
        final_status = "PENDING"  # One approval is still pending

    # Update the request status based on final decision
    sql_update_status = f"""
    UPDATE REQUESTS
    SET STATUS = '{final_status}'
    WHERE REQUEST_ID = {request_id};
    """
    session.sql(sql_update_status).collect()

    st.info(f"Request {request_id} has been updated to {final_status}.")

    request_details = session.sql(f"""
        SELECT USERNAME, REQUEST_TYPE, REQUEST_DETAILS 
        FROM REQUESTS 
        WHERE REQUEST_ID = {request_id};
    """).collect()[0]
    print(request_details)
    # # Send email notification to the user if the final status is no longer pending
    # if final_status in ["APPROVED", "REJECTED"]:
    #     send_user_notification_email(
    #         request_details['USERNAME'],
    #         request_details['REQUEST_TYPE'],
    #         request_details['REQUEST_DETAILS'],
    #         approved=(final_status == "APPROVED")
    #     )

    # Grant access if fully approved
    if final_status == "APPROVED":
        grant_access(
            request_details['USERNAME'],
            request_details['REQUEST_TYPE'],
            request_details['REQUEST_DETAILS']
        )


def parse_request_details(request_details: str, request_type: str) -> dict:
    """Extract database, schema, and table information based on request type."""
    parsed_details = {"database": None, "schema": None, "table": None}
    lines = request_details.strip().splitlines()

    # Assume first line is always database/schema/table information
    details = lines[0].strip()

    # Split the details by '.' to extract database, schema, and table names
    parts = details.split('.')

    if len(parts) >= 1:
        parsed_details["database"] = parts[0].strip()
    if len(parts) >= 2:
        parsed_details["schema"] = parts[1].strip()
    if len(parts) >= 3:
        parsed_details["table"] = parts[2].strip()

    # Handle cases for different request types
    if request_type == "SCHEMA_ACCESS" and len(parts) > 1:
        parsed_details["schema"] = parts[1].strip()
    elif request_type == "TABLE_ACCESS" and len(parts) > 2:
        parsed_details["schema"] = parts[1].strip()
        parsed_details["table"] = parts[2].strip()

    # If there are extra lines with comments, handle them (e.g., Additional Comments)
    additional_comments = "\n".join(lines[1:]).strip() if len(lines) > 1 else ""
    if additional_comments:
        parsed_details["comments"] = additional_comments

    return parsed_details


def grant_database_access(role_name: str, database: str):
    """Grant usage access on the database to the specified role."""
    database = database.strip()

    try:
        # Grant usage on the database (this grants the ability to access the database)
        sql_grant_db = f"GRANT USAGE ON DATABASE {database} TO ROLE {role_name};"
        print(sql_grant_db)
        session.sql(sql_grant_db).collect()

        st.success(f"Database access granted on '{database}' to role '{role_name}'.")
    except Exception as e:
        st.error(f"Failed to grant database access: {str(e)}")

def grant_schema_access(role_name: str, database: str, schema: str):
    """Grant usage on the database, usage on the schema (if not system schema), and privileges on tables within the schema."""
    database = database.strip()
    schema = schema.strip()

    system_schemas = ['INFORMATION_SCHEMA', 'PUBLIC']  # Add any other system schemas here if needed

    try:
        # Grant USAGE on the database
        sql_grant_db_usage = f"GRANT USAGE ON DATABASE {database} TO ROLE {role_name};"
        session.sql(sql_grant_db_usage).collect()

        # Skip granting USAGE on system schemas
        if schema not in system_schemas:
            # Grant USAGE on the schema if it's not a system schema
            sql_grant_schema_usage = f"GRANT USAGE ON SCHEMA {database}.{schema} TO ROLE {role_name};"
            session.sql(sql_grant_schema_usage).collect()

        # Grant ALL privileges on all tables in the schema
        sql_grant_all_privileges = f"GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA {database}.{schema} TO ROLE {role_name};"
        session.sql(sql_grant_all_privileges).collect()

        # # Grant default privileges for future tables in the schema
        # sql_grant_future_privileges = f"ALTER DEFAULT PRIVILEGES IN SCHEMA {database}.{schema} GRANT ALL PRIVILEGES ON TABLES TO ROLE {role_name};"
        # session.sql(sql_grant_future_privileges).collect()

        # Inform the user
        st.success(f"Schema access granted on '{database}.{schema}' to role '{role_name}', including all tables.")
    except Exception as e:
        st.error(f"Failed to grant schema access: {str(e)}")


def grant_table_access(role_name: str, database: str, schema: str, table: str):
    """Grant select access on the specified table to the role, ensuring usage on database and schema."""
    database = database.strip()
    schema = schema.strip()
    table = table.strip()
    try:
        # Ensure USAGE privilege on the database and schema
        sql_grant_db_usage = f"GRANT USAGE ON DATABASE {database} TO ROLE {role_name};"
        sql_grant_schema_usage = f"GRANT USAGE ON SCHEMA {database}.{schema} TO ROLE {role_name};"

        # Grant SELECT on the table
        sql_grant_table = f"GRANT SELECT ON TABLE {database}.{schema}.{table} TO ROLE {role_name};"

        print(sql_grant_db_usage)
        print(sql_grant_schema_usage)
        print(sql_grant_table)

        # Execute grants in order
        session.sql(sql_grant_db_usage).collect()
        session.sql(sql_grant_schema_usage).collect()
        session.sql(sql_grant_table).collect()

        st.success(f"Table access granted on '{database}.{schema}.{table}' to role '{role_name}'.")
    except Exception as e:
        st.error(f"Failed to grant table access: {str(e)}")


# Example usage of functions within main grant_access function
def grant_access(username: str, request_type: str, request_details: str):
    """Main function to grant access based on request type."""
    role_name = get_user_role(username,connector_connection)
    print("Role Name:", role_name, "\nRequest Type:", request_details)

    if not role_name:
        st.error(f"No role found for user '{username}'. Access grant aborted.")
        return

    try:
        # Parse request details into a dictionary
        details = parse_request_details(request_details, request_type)
        database = details.get("database")
        schema = details.get("schema")
        table = details.get("table")
        comments = details.get("comments")
        print(f"Database: {database}, Schema: {schema}, Table: {table}, Comments: {comments}")

        # Grant full access to the database if no schema or table is specified
        if request_type == "DATABASE_ACCESS" and database:
            if not schema and not table:
                # Grant full database access
                grant_database_access(role_name, database)
            else:
                st.warning(
                    "Only database access is allowed, but schema or table details were provided. Access grant aborted.")

        # Grant access to a specific schema if schema is provided and no table is specified
        elif request_type == "SCHEMA_ACCESS" and database and schema:
            if not table:
                # Grant schema access
                grant_schema_access(role_name, database, schema)
            else:
                st.warning("Only schema access is allowed, but table details were provided. Access grant aborted.")

        # Grant access to a specific table if all details (database, schema, table) are provided
        elif request_type == "TABLE_ACCESS" and database and schema and table:
            # Grant table access
            grant_table_access(role_name, database, schema, table)

        else:
            st.warning("Incomplete request details. Access grant not processed.")

    except Exception as e:
        st.error(f"Failed to grant access: {str(e)}")


def get_user_requests(username):
    """Fetch all requests for a specific user."""
    sql = f"""
    SELECT REQUEST_ID, REQUEST_TYPE, REQUEST_DETAILS, REQUEST_DATE, STATUS
    FROM REQUESTS 
    WHERE USERNAME = '{username}'
    ORDER BY REQUEST_DATE DESC;
    """
    return session.sql(sql).collect()


def show_roles():
    """Display all roles in the Snowflake account with their details."""
    sql = """
    SELECT 
        ROLE_ID AS "Role ID",
        NAME AS "Role Name",
        COMMENT AS "Comment",
        OWNER AS "Owner",
        ROLE_TYPE AS "Role Type",
        ROLE_DATABASE_NAME AS "Database Name",
        ROLE_INSTANCE_ID AS "Instance ID",
        OWNER_ROLE_TYPE AS "Owner Role Type",
        CREATED_ON AS "Created On",
        DELETED_ON AS "Deleted On"
    FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
    ORDER BY ROLE_ID ASC;
    """
    return session.sql(sql).collect()


def fetch_role_names():
    """Fetch all role names from Snowflake."""
    sql = "SELECT NAME FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES ORDER BY NAME ASC"
    roles = session.sql(sql).collect()
    return [role.NAME for role in roles]


def create_role(role_name: str, comment: str = ""):
    """Create a new role with an optional comment."""
    try:
        sql = f"CREATE ROLE {role_name}"
        if comment:
            sql += f" COMMENT = '{comment}'"
        session.sql(sql).collect()

        # Log role creation in your requests table
        log_request(
            username=st.session_state.username,
            request_type="CREATE_ROLE",
            request_details=f"Created role: {role_name}",
            status="APPROVED"  # Since this is direct creation
        )
    except Exception as e:
        raise Exception(f"Failed to create role: {str(e)}")


def create_user(username: str, password: str, default_role: str):
    """Create a new user with a default role."""
    try:
        sql = f"CREATE USER {username} PASSWORD = '{password}' DEFAULT_ROLE = '{default_role}'"
        session.sql(sql).collect()

        # Log user creation in your requests table
        log_request(
            username=st.session_state.username,
            request_type="CREATE_USER",
            request_details=f"Created user: {username} with default role: {default_role}",
            status="APPROVED"  # Since this is direct creation
        )
    except Exception as e:
        raise Exception(f"Failed to create user: {str(e)}")


def grant_role(user: str, role: str):
    """Grant a specified role to a user."""
    try:
        sql = f"GRANT ROLE {role} TO USER {user}"
        session.sql(sql).collect()

        # Log role grant in your requests table
        log_request(
            username=st.session_state.username,
            request_type="GRANT_ROLE",
            request_details=f"Granted role {role} to user {user}",
            status="APPROVED"  # Since this is direct grant
        )
    except Exception as e:
        raise Exception(f"Failed to grant role: {str(e)}")


def revoke_role(user: str, role: str):
    """Revoke a specified role from a user."""
    try:
        sql = f"REVOKE ROLE {role} FROM USER {user}"
        session.sql(sql).collect()

        # Log role revocation in your requests table
        log_request(
            username=st.session_state.username,
            request_type="REVOKE_ROLE",
            request_details=f"Revoked role {role} from user {user}",
            status="APPROVED"  # Since this is direct revocation
        )
    except Exception as e:
        raise Exception(f"Failed to revoke role: {str(e)}")


def log_request(username: str, request_type: str, request_details: str, status: str):
    """Log requests in your requests table."""
    sql = f"""
    INSERT INTO YOUR_REQUESTS_TABLE (
        USERNAME, REQUEST_TYPE, REQUEST_DETAILS, STATUS, REQUEST_DATE
    ) VALUES (
        '{username}', '{request_type}', '{request_details}', '{status}', CURRENT_TIMESTAMP()
    )
    """
    session.sql(sql).collect()

