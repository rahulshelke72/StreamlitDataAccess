import streamlit as st
import pandas as pd
from services.snowflake_utils import (
    get_available_databases, get_available_schemas, get_available_tables,
    check_user_role, fetch_users, fetch_role_names, fetch_role_names_all_fields
)
from app.request_handling import (
    submit_request, show_pending_requests, update_approval_status,
    get_user_requests, create_role, create_user, grant_role, revoke_role
)
from config.snowflake_connection import connector_connection, session

ACCOUNTADMIN_ROLE = 'ACCOUNTADMIN'
SYSADMIN_ROLE = 'SYSADMIN'

def render_request_form():
    """Render the form for users to submit requests"""
    st.subheader("Submit a Request")

    username = st.session_state.get("username", "Guest")
    request_type = st.selectbox("Select Request Type", ["DATABASE_ACCESS", "SCHEMA_ACCESS", "TABLE_ACCESS"])

    request_details = ""

    # Request-specific UI
    if request_type == "DATABASE_ACCESS":
        databases = get_available_databases()
        if databases:
            selected_database = st.selectbox("Select a Database", databases)
            request_details = selected_database
        else:
            st.warning("No databases available for selection.")
            request_details = None

    elif request_type == "SCHEMA_ACCESS":
        databases = get_available_databases()
        if databases:
            selected_database = st.selectbox("Select a Database", databases)
            schemas = get_available_schemas(selected_database)
            if schemas:
                selected_schema = st.selectbox("Select a Schema", schemas)
                request_details = f"{selected_database}.{selected_schema}"
            else:
                st.warning("No schemas available for the selected database.")
                request_details = None

    elif request_type == "TABLE_ACCESS":
        databases = get_available_databases()
        if databases:
            selected_database = st.selectbox("Select a Database", databases)
            schemas = get_available_schemas(selected_database)
            if schemas:
                selected_schema = st.selectbox("Select a Schema", schemas)
                tables = get_available_tables(selected_database, selected_schema)
                if tables:
                    selected_table = st.selectbox("Select a Table", tables)
                    request_details = f"{selected_database}.{selected_schema}.{selected_table}"
                else:
                    st.warning("No tables available for the selected schema.")
                    request_details = None
            else:
                st.warning("No schemas available for the selected database.")
                request_details = None

    # Additional Comments
    additional_comments = st.text_area("Additional Comments (optional)")
    if request_details and additional_comments:
        request_details += f"\n\nAdditional Comments: {additional_comments}"

    # Submit Request
    if st.button("Submit Request"):
        if username and request_type and request_details:
            submit_request(username, request_type, request_details)
            st.success("Request submitted successfully.")
        else:
            st.warning("Please provide all required information.")

def render_approval_panel():
    """Render the approval panel for admins to review requests."""
    st.subheader("Request Approval Panel")

    current_role = st.session_state.get("role")
    if current_role not in [ACCOUNTADMIN_ROLE, SYSADMIN_ROLE]:
        st.warning("You must be an Admin to approve/reject requests.")
        return

    # Initialize the status filter if not set
    if 'status_filter_admin' not in st.session_state:
        st.session_state.status_filter_admin = 'PENDING'

    # Initialize pending requests if not already loaded
    if 'pending_requests' not in st.session_state:
        st.session_state.pending_requests = show_pending_requests()

    # Filter by status buttons
    st.write("Filter by status:")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("🕒 Pending", key="filter_pending_admin"):
            st.session_state.status_filter_admin = 'PENDING'
            st.session_state.pending_requests = show_pending_requests()  # Reload pending requests
    with col2:
        if st.button("✅ Approved", key="filter_approved_admin"):
            st.session_state.status_filter_admin = 'APPROVED'
            st.session_state.pending_requests = show_pending_requests()  # Reload approved requests
    with col3:
        if st.button("❌ Rejected", key="filter_rejected_admin"):
            st.session_state.status_filter_admin = 'REJECTED'
            st.session_state.pending_requests = show_pending_requests()  # Reload rejected requests

    # Show current status filter
    st.caption(f"Currently showing: {st.session_state.status_filter_admin}")

    pending_requests = st.session_state.pending_requests
    if not pending_requests:
        st.info("No requests found.")
        return

    df = pd.DataFrame(pending_requests)

    # Filter based on the selected status
    df = df[df['STATUS'] == st.session_state.status_filter_admin]

    if len(df) == 0:
        st.info(f"No requests with status: {st.session_state.status_filter_admin}")
        return

    # Iterate over each pending request and display options for approval/rejection
    for idx, request in df.iterrows():
        with st.expander(f"Request #{request['REQUEST_ID']} - {request['USERNAME']} - {request['REQUEST_TYPE']}"):
            st.write(f"**Details:** {request['REQUEST_DETAILS']}")
            st.write(f"**Date:** {request['REQUEST_DATE']}")
            st.write(f"**Status:** {request['STATUS']}")

            # Show Account Admin and Sys Admin approval statuses
            accountadmin_status = "APPROVED" if request.get('ACCOUNTADMIN_APPROVAL') is True else "REJECTED" if request.get(
                'ACCOUNTADMIN_APPROVAL') is False else "PENDING"
            sysadmin_status = "APPROVED" if request.get('SYSADMIN_APPROVAL') is True else "REJECTED" if request.get(
                'SYSADMIN_APPROVAL') is False else "PENDING"

            st.write(f"**Account Admin Approval:** {accountadmin_status}")
            st.write(f"**Sys Admin Approval:** {sysadmin_status}")

            # Columns for action buttons
            col1, col2 = st.columns(2)

            # Account Admin approval/rejection
            if current_role == "ACCOUNTADMIN" and request['ACCOUNTADMIN_APPROVAL'] is None:
                with col1:
                    if st.button("Approve", key=f"approve_accountadmin_{request['REQUEST_ID']}"):
                        update_approval_status(request['REQUEST_ID'], True, "ACCOUNTADMIN")
                        st.session_state.pending_requests = show_pending_requests()  # Reload pending requests
                        st.rerun()

                with col2:
                    rejection_reason = st.text_area("Reason for rejection (Account Admin)",
                                                    key=f"reject_reason_accountadmin_{request['REQUEST_ID']}")
                    if st.button("Reject", key=f"reject_accountadmin_{request['REQUEST_ID']}"):
                        if rejection_reason:
                            update_approval_status(request['REQUEST_ID'], False, "ACCOUNTADMIN", rejection_reason)
                            st.session_state.pending_requests = show_pending_requests()  # Reload pending requests
                            st.rerun()

            # Sys Admin approval/rejection
            if current_role == "SYSADMIN" and request['SYSADMIN_APPROVAL'] is None:
                with col1:
                    if st.button("Approve", key=f"approve_sysadmin_{request['REQUEST_ID']}"):
                        update_approval_status(request['REQUEST_ID'], True, "SYSADMIN")
                        st.session_state.pending_requests = show_pending_requests()  # Reload pending requests
                        st.rerun()

                with col2:
                    rejection_reason = st.text_area("Reason for rejection (Sys Admin)",
                                                    key=f"reject_reason_sysadmin_{request['REQUEST_ID']}")
                    if st.button("Reject", key=f"reject_sysadmin_{request['REQUEST_ID']}"):
                        if rejection_reason:
                            update_approval_status(request['REQUEST_ID'], False, "SYSADMIN", rejection_reason)
                            st.session_state.pending_requests = show_pending_requests()  # Reload pending requests
                            st.rerun()
def render_user_requests():
    """Render the requests panel for users to view their requests and statuses"""
    st.subheader("Your Requests")

    current_role = st.session_state.get("role")
    if current_role != "user":
        st.warning("You must be a User to view your requests.")
        return

    # Initialize status filter if not exists
    if 'status_filter_user' not in st.session_state:
        st.session_state.status_filter_user = 'PENDING'

    # Initialize requests if not exists
    if 'user_requests' not in st.session_state:
        st.session_state.user_requests = get_user_requests(st.session_state.username)

    # Add status filter buttons in a horizontal layout
    st.write("Filter by status:")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("🕒 Pending", key="filter_pending_user"):
            st.session_state.status_filter_user = 'PENDING'
            st.session_state.user_requests = get_user_requests(st.session_state.username)
    with col2:
        if st.button("✅ Approved", key="filter_approved_user"):
            st.session_state.status_filter_user = 'APPROVED'
            st.session_state.user_requests = get_user_requests(st.session_state.username)
    with col3:
        if st.button("❌ Rejected", key="filter_rejected_user"):
            st.session_state.status_filter_user = 'REJECTED'
            st.session_state.user_requests = get_user_requests(st.session_state.username)

    # Add a small text indicator for current filter
    st.caption(f"Currently showing: {st.session_state.status_filter_user}")

    user_requests = st.session_state.user_requests

    if not user_requests:
        st.info("You have no requests.")
        return

    df = pd.DataFrame(user_requests)

    # Filter based on selected status
    df = df[df['STATUS'] == st.session_state.status_filter_user]

    if len(df) == 0:
        st.info(f"No requests with status: {st.session_state.status_filter_user}")
        return

    # Display each request in an expandable section
    for _, request in df.iterrows():
        with st.expander(f"Request #{request['REQUEST_ID']} - {request['REQUEST_TYPE']}"):
            st.write(f"**Details:** {request['REQUEST_DETAILS']}")
            st.write(f"**Date:** {request['REQUEST_DATE']}")
            st.write(f"**Status:** {request['STATUS']}")





def render_roles_users_panel():
    """Render the roles and users management panel"""
    st.subheader("Role and User Management")

    # Initialize session state for roles visibility and user creation
    if 'show_roles' not in st.session_state:
        st.session_state.show_roles = False

    if 'show_users' not in st.session_state:
        st.session_state.show_users = False

    # Tabs for different sections
    tab1, tab2, tab3, tab4 , tab5= st.tabs(["View Roles","View Users" ,"Create Role", "Create User", "Manage Role Access"])

    # View Roles Tab
    with tab1:
        if st.button("Show/Hide Roles"):
            st.session_state.show_roles = not st.session_state.show_roles

        if st.session_state.show_roles:
            roles = fetch_role_names_all_fields(connector_connection)
            st.dataframe(roles)

    # View Roles Tab
    with tab2:
        if st.button("Show/Hide Users"):
            st.session_state.show_users = not st.session_state.show_users

        if st.session_state.show_users:
            users = fetch_users()
            st.dataframe(users)

    # Create Role Tab
    with tab3:
        new_role = st.text_input("Role Name")
        role_comment = st.text_input("Role Comment", key="role_comment")

        if st.button("Create Role"):
            if new_role:
                try:
                    create_role(new_role, role_comment)
                    st.success(f"Role '{new_role}' created successfully!")
                except Exception as e:
                    st.error(f"Error creating role: {str(e)}")
            else:
                st.warning("Please provide a role name.")

    # Create User Tab
    with tab4:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        roles = fetch_role_names(connector_connection)  # Fetch available roles for selection
        role = st.selectbox("Select Role", roles, key="create_user_role")  # Unique key for this selectbox

        if st.button("Create User"):
            if username and password and role:
                try:
                    create_user(username, password, role)
                    st.success(f"User '{username}' created successfully!")
                except Exception as e:
                    st.error(f"Error creating user: {str(e)}")
            else:
                st.warning("Please provide username, password, and role.")

    # Manage Role Access Tab
    with tab5:
        # Fetch the list of users
        try:
            user_list = fetch_users()
            usernames = [user['name'] for user in user_list]  # Extract the 'name' column for dropdown
        except Exception as e:
            st.error(f"Error fetching users: {str(e)}")
            usernames = []

        roles = fetch_role_names(connector_connection)  # Fetch available roles for selection
        action = st.radio("Action", ["Grant Role", "Revoke Role"], key="role_action")  # Unique key for the radio button

        selected_user = st.selectbox("Select User", usernames, key="manage_user")  # Unique key for this selectbox
        selected_role = st.selectbox("Select Role", roles, key="manage_role")  # Unique key for this selectbox

        if st.button("Apply"):
            if selected_user and selected_role:
                try:
                    if action == "Grant Role":
                        grant_role(selected_user, selected_role)
                        st.success(f"Granted '{selected_role}' to '{selected_user}'.")
                    elif action == "Revoke Role":
                        revoke_role(selected_user, selected_role)
                        st.success(f"Revoked '{selected_role}' from '{selected_user}'.")
                except Exception as e:
                    st.error(f"Error managing role: {str(e)}")
            else:
                st.warning("Please provide both user and role.")


def snowflake_user():
    """Render the form for submitting a request to create or update a Snowflake user."""
    st.markdown(
        """
        <div style="text-align: center;">
            <h4>Submit User Creation/Update Request</h4>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Automatically pre-fill the username from the logged-in session
    if "username" in st.session_state:
        username = st.session_state.get("username", "")
    else:
        # Handle cases where the user is not logged in yet
        st.warning("You need to be logged in to submit a user creation request.")
        return

    # Show the username field as non-editable (pre-filled)
    st.text_input("Username", value=username, disabled=True)

    # Fetch the user's current password (hashed) from the USER_ACCOUNTS table
    user_details = session.sql(f"""
        SELECT PASSWORD_HASH
        FROM RAHUL.USERS.USER_ACCOUNTS
        WHERE USERNAME = '{username}';
    """).collect()

    if user_details:
        # Extract current password hash
        current_password_hash = user_details[0]['PASSWORD_HASH']

        # Show the password field as non-editable (hashed password)
        st.text_input("Password", value=current_password_hash, type="password", disabled=True)
    else:
        st.error("User details not found.")
        return

    # Set the role selection to always be 'PUBLIC'
    selected_role = "PUBLIC"  # Fixed role selection, no need to fetch roles

    # Additional Comments with unique key
    additional_comments = st.text_area("Additional Comments (optional)", key=f"comments_{username}")

    # Request Submission
    if st.button("Submit User Creation Request"):
        try:
            # Fetch all users in Snowflake
            all_users = fetch_users()
            all_usernames = [user["name"].upper() for user in all_users]
            # Check if the user already exists
            if username.upper() in all_usernames:
                st.warning(f"User '{username}' already exists in the snowflake account.")
                return

        except Exception as e:
            st.error(f"Failed to fetch existing users: {e}")
            return

        if selected_role:
            # Prepare the request details (no need for password here)
            request_type = "USER_CREATION"
            request_details = f"Username: {username}, Role: {selected_role}"
            if additional_comments:
                request_details += f"\n\nAdditional Comments: {additional_comments}"

            try:
                # Submit the request to update the user role (password remains unchanged)
                submit_request(username, request_type, request_details)

                st.success(f"User creation request for '{username}' submitted successfully!")
            except Exception as e:
                st.error(f"Failed to submit request: {e}")
        else:
            st.warning("Please select a role.")
