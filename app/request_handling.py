from services.snowflake_utils import session, get_user_role
import streamlit as st
from services.email_utils import send_request_email, send_user_notification_email

def submit_request(username, request_type, request_details):
    # Insert request into database
    sql = f"""
    INSERT INTO REQUESTS (USERNAME, REQUEST_TYPE, REQUEST_DETAILS, STATUS, REQUEST_DATE, ACCOUNTADMIN_APPROVAL)
    VALUES ('{username}', '{request_type}', '{request_details}', 'PENDING', CURRENT_TIMESTAMP(), FALSE);
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
    """Fetch all requests (PENDING, APPROVED, REJECTED) for the admin panel"""
    sql = """
    SELECT REQUEST_ID, USERNAME, REQUEST_TYPE, REQUEST_DETAILS, REQUEST_DATE, STATUS, ACCOUNTADMIN_APPROVAL
    FROM REQUESTS 
    ORDER BY REQUEST_DATE DESC;
    """
    return session.sql(sql).collect()


def update_approval_status(request_id: int, approved: bool):
    """Update approval status for the accountadmin and grant access if approved."""
    request_details = session.sql(f"""
        SELECT USERNAME, REQUEST_TYPE, REQUEST_DETAILS 
        FROM REQUESTS 
        WHERE REQUEST_ID = {request_id};
    """).collect()[0]

    username = request_details['USERNAME']
    request_type = request_details['REQUEST_TYPE']
    request_details_text = request_details['REQUEST_DETAILS']

    # Update approval status in the database
    sql = f"""
    UPDATE REQUESTS
    SET ACCOUNTADMIN_APPROVAL = {approved}
    WHERE REQUEST_ID = {request_id};
    """
    session.sql(sql).collect()

    # Update the overall request status
    status = "approved" if approved else "rejected"
    sql_check = f"""
    UPDATE REQUESTS
    SET STATUS = '{status}'
    WHERE REQUEST_ID = {request_id};
    """
    session.sql(sql_check).collect()

    st.info(f"Request {request_id} has been {status} by AccountAdmin.")

    # Send email notification to the user about the decision
    try:
        send_user_notification_email(username, request_type, request_details_text, approved)
    except Exception as e:
        st.error(f"Failed to send user notification email: {e}")

    # Grant access if approved
    if approved:
        grant_access(username, request_type, request_details_text)

def grant_access(username: str, request_type: str, request_details: str):
    role_name = get_user_role(username)
    if not role_name:
        st.error(f"No role found for user '{username}'. Access grant aborted.")
        return

    try:
        # Grant access based on request type
        if request_type == "DATABASE_ACCESS":
            sql_grant = f"GRANT USAGE ON DATABASE {request_details} TO ROLE {role_name};"
            access_type = "Database"
        elif request_type == "SCHEMA_ACCESS":
            sql_grant = f"GRANT USAGE ON SCHEMA {request_details} TO ROLE {role_name};"
            access_type = "Schema"
        elif request_type == "TABLE_ACCESS":
            sql_grant = f"GRANT SELECT ON TABLE {request_details} TO ROLE {role_name};"
            access_type = "Table"
        elif request_type == "ROLE_ASSIGNMENT":
            sql_grant = f"GRANT ROLE {request_details} TO ROLE {role_name};"
            access_type = "Role Assignment"
        elif request_type == "PERMISSION_CHANGE":
            sql_grant = f"GRANT {request_details} TO ROLE {role_name};"
            access_type = "Permission Change"
        else:
            st.warning("Unknown request type. Access grant not processed.")
            return

        session.sql(sql_grant).collect()
        st.success(f"{access_type} access granted to role '{role_name}' for '{request_details}'.")
        st.info(f"Successfully executed: {sql_grant}")

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
