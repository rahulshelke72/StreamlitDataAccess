# import streamlit as st
# import pandas as pd
# from services.snowflake_utils import (get_available_databases, get_available_schemas, get_available_tables,
#                                       check_user_role,fetch_users,fetch_users_from_accounts, fetch_roles_from_accounts)
# from app.request_handling import (submit_request, show_pending_requests, update_approval_status,
#                                   get_user_requests,show_roles, fetch_role_names, create_role,
#                                   create_user, grant_role, revoke_role)
# from config.snowflake_connection import connector_connection
#
# ACCOUNTADMIN_ROLE = 'ACCOUNTADMIN'
# SYSADMIN_ROLE  = 'SYSADMIN'
#
# def render_request_form():
#     """Render the form for users to submit requests"""
#     st.subheader("Submit a Request")
#
#     username = st.session_state.get("username", "Guest")
#     request_type = st.selectbox("Select Request Type", ["DATABASE_ACCESS", "SCHEMA_ACCESS", "TABLE_ACCESS"])
#
#     request_details = ""
#
#     if request_type == "DATABASE_ACCESS":
#         # Database Access request type
#         databases = get_available_databases()
#         if databases:
#             selected_database = st.selectbox("Select a Database", databases)
#             print("Database Name",selected_database)
#             request_details = selected_database
#         else:
#             st.warning("No databases available for selection.")
#             request_details = None
#
#     elif request_type == "SCHEMA_ACCESS":
#         # Schema Access request type
#         databases = get_available_databases()
#         if databases:
#             selected_database = st.selectbox("Select a Database", databases)
#             schemas = get_available_schemas(selected_database)
#             if schemas:
#                 selected_schema = st.selectbox("Select a Schema", schemas)
#                 request_details = f"{selected_database}.{selected_schema}"
#             else:
#                 st.warning("No schemas available for the selected database.")
#                 request_details = None
#         else:
#             st.warning("No databases available for selection.")
#             request_details = None
#
#     elif request_type == "TABLE_ACCESS":
#         # Table Access request type
#         databases = get_available_databases()
#         if databases:
#             selected_database = st.selectbox("Select a Database", databases)
#             schemas = get_available_schemas(selected_database)
#             if schemas:
#                 selected_schema = st.selectbox("Select a Schema", schemas)
#                 tables = get_available_tables(selected_database, selected_schema)
#                 if tables:
#                     selected_table = st.selectbox("Select a Table", tables)
#                     request_details = f"{selected_database}.{selected_schema}.{selected_table}"
#                 else:
#                     st.warning("No tables available for the selected schema.")
#                     request_details = None
#             else:
#                 st.warning("No schemas available for the selected database.")
#                 request_details = None
#         else:
#             st.warning("No databases available for selection.")
#             request_details = None
#
#     # Additional Comments
#     additional_comments = st.text_area("Additional Comments (optional)")
#     if request_details and additional_comments:
#         request_details += f"\n\nAdditional Comments: {additional_comments}"
#
#     # Submit Request Button
#     if st.button("Submit Request"):
#         if username and request_type and request_details:
#             # Submit request and update the status
#             submit_request(username, request_type, request_details)
#             # Initialize the request status if not already done
#             if 'requests_status' not in st.session_state:
#                 st.session_state.requests_status = {}
#             st.session_state.requests_status[username] = {"status": "Pending", "details": request_details}
#             st.success("Request submitted successfully.")
#
#         else:
#             st.warning("Please provide username, request type, and details.")
#
#     # Show the request status for the user
#     if 'requests_status' in st.session_state and username in st.session_state.requests_status:
#         request_status = st.session_state.requests_status[username]
#         st.write(f"Your request is currently: {request_status['status']}")
#         st.write(f"Request details: {request_status['details']}")
#
#
# def render_approval_panel():
#     """Render the approval panel for admins to review requests."""
#     st.subheader("Request Approval Panel")
#
#     current_role = st.session_state.get("role")
#     if current_role not in [ACCOUNTADMIN_ROLE, SYSADMIN_ROLE]:
#         st.warning("You must be an Admin to approve/reject requests.")
#         return
#
#     # Initialize status filter if not exists
#     if 'status_filter_admin' not in st.session_state:
#         st.session_state.status_filter_admin = 'PENDING'
#
#     # Initialize requests if not exists
#     if 'pending_requests' not in st.session_state:
#         st.session_state.pending_requests = show_pending_requests()
#
#     # Add status filter buttons in a horizontal layout
#     st.write("Filter by status:")
#     col1, col2, col3 = st.columns(3)
#     with col1:
#         if st.button("🕒 Pending", key="filter_pending_admin"):
#             st.session_state.status_filter_admin = 'PENDING'
#             st.session_state.pending_requests = show_pending_requests()
#     with col2:
#         if st.button("✅ Approved", key="filter_approved_admin"):
#             st.session_state.status_filter_admin = 'APPROVED'
#             st.session_state.pending_requests = show_pending_requests()
#     with col3:
#         if st.button("❌ Rejected", key="filter_rejected_admin"):
#             st.session_state.status_filter_admin = 'REJECTED'
#             st.session_state.pending_requests = show_pending_requests()
#
#     # Add a small text indicator for current filter
#     st.caption(f"Currently showing: {st.session_state.status_filter_admin}")
#
#     pending_requests = st.session_state.pending_requests
#
#     if not pending_requests:
#         st.info("No requests found.")
#         return
#
#     df = pd.DataFrame(pending_requests)
#
#     # Filter based on selected status
#     df = df[df['STATUS'] == st.session_state.status_filter_admin]
#
#     if len(df) == 0:
#         st.info(f"No requests with status: {st.session_state.status_filter_admin}")
#         return
#
#     for idx, request in df.iterrows():
#         with st.expander(f"Request #{request['REQUEST_ID']} - {request['USERNAME']} - {request['REQUEST_TYPE']}"):
#             st.write(f"**Details:** {request['REQUEST_DETAILS']}")
#             st.write(f"**Date:** {request['REQUEST_DATE']}")
#             st.write(f"**Status:** {request['STATUS']}")
#
#             accountadmin_status = "APPROVED" if request.get(
#                 'ACCOUNTADMIN_APPROVAL') is True else "REJECTED" if request.get(
#                 'ACCOUNTADMIN_APPROVAL') is False else "PENDING"
#             sysadmin_status = "APPROVED" if request.get('SYSADMIN_APPROVAL') is True else "REJECTED" if request.get(
#                 'SYSADMIN_APPROVAL') is False else "PENDING"
#
#             st.write(f"**Account Admin Approval:** {accountadmin_status}")
#             st.write(f"**Sys Admin Approval:** {sysadmin_status}")
#
#             col1, col2 = st.columns(2)
#
#             # Independent approval/rejection for Account Admin
#             if current_role == "ACCOUNTADMIN" and request['ACCOUNTADMIN_APPROVAL'] is None:
#                 with col1:
#                     if st.button("Approve", key=f"approve_accountadmin_{request['REQUEST_ID']}_{idx}"):
#                         update_approval_status(request['REQUEST_ID'], True, "ACCOUNTADMIN")
#                         st.session_state.pending_requests = show_pending_requests()
#                         st.rerun()
#                 with col2:
#                     if st.button("Reject", key=f"reject_accountadmin_{request['REQUEST_ID']}_{idx}"):
#                         rejection_reason = st.text_area("Reason for rejection (Account Admin)",
#                                                         key=f"reject_reason_accountadmin_{request['REQUEST_ID']}_{idx}")
#                         if rejection_reason:
#                             update_approval_status(request['REQUEST_ID'], False, "ACCOUNTADMIN", rejection_reason)
#                             st.session_state.pending_requests = show_pending_requests()
#                             st.rerun()
#
#             # Independent approval/rejection for Sys Admin
#             if current_role == "SYSADMIN" and request['SYSADMIN_APPROVAL'] is None:
#                 with col1:
#                     if st.button("Approve", key=f"approve_sysadmin_{request['REQUEST_ID']}_{idx}"):
#                         update_approval_status(request['REQUEST_ID'], True, "SYSADMIN")
#                         st.session_state.pending_requests = show_pending_requests()
#                         st.rerun()
#                 with col2:
#                     if st.button("Reject", key=f"reject_sysadmin_{request['REQUEST_ID']}_{idx}"):
#                         rejection_reason = st.text_area("Reason for rejection (Sys Admin)",
#                                                         key=f"reject_reason_sysadmin_{request['REQUEST_ID']}_{idx}")
#                         if rejection_reason:
#                             update_approval_status(request['REQUEST_ID'], False, "SYSADMIN", rejection_reason)
#                             st.session_state.pending_requests = show_pending_requests()
#                             st.rerun()
#
#
# def render_user_requests():
#     """Render the requests panel for users to view their requests and statuses"""
#     st.subheader("Your Requests")
#
#     current_role = st.session_state.get("role")
#     if current_role != "user":
#         st.warning("You must be a User to view your requests.")
#         return
#
#     # Initialize status filter if not exists
#     if 'status_filter_user' not in st.session_state:
#         st.session_state.status_filter_user = 'PENDING'
#
#     # Initialize requests if not exists
#     if 'user_requests' not in st.session_state:
#         st.session_state.user_requests = get_user_requests(st.session_state.username)
#
#     # Add status filter buttons in a horizontal layout
#     st.write("Filter by status:")
#     col1, col2, col3 = st.columns(3)
#     with col1:
#         if st.button("🕒 Pending", key="filter_pending_user"):
#             st.session_state.status_filter_user = 'PENDING'
#             st.session_state.user_requests = get_user_requests(st.session_state.username)
#     with col2:
#         if st.button("✅ Approved", key="filter_approved_user"):
#             st.session_state.status_filter_user = 'APPROVED'
#             st.session_state.user_requests = get_user_requests(st.session_state.username)
#     with col3:
#         if st.button("❌ Rejected", key="filter_rejected_user"):
#             st.session_state.status_filter_user = 'REJECTED'
#             st.session_state.user_requests = get_user_requests(st.session_state.username)
#
#     # Add a small text indicator for current filter
#     st.caption(f"Currently showing: {st.session_state.status_filter_user}")
#
#     user_requests = st.session_state.user_requests
#
#     if not user_requests:
#         st.info("You have no requests.")
#         return
#
#     df = pd.DataFrame(user_requests)
#
#     # Filter based on selected status
#     df = df[df['STATUS'] == st.session_state.status_filter_user]
#
#     if len(df) == 0:
#         st.info(f"No requests with status: {st.session_state.status_filter_user}")
#         return
#
#     # Display each request in an expandable section
#     for _, request in df.iterrows():
#         with st.expander(f"Request #{request['REQUEST_ID']} - {request['REQUEST_TYPE']}"):
#             st.write(f"**Details:** {request['REQUEST_DETAILS']}")
#             st.write(f"**Date:** {request['REQUEST_DATE']}")
#             st.write(f"**Status:** {request['STATUS']}")
#
#
# def render_roles_users_panel():
#     """Render the roles and users management panel"""
#     st.subheader("Role and User Management")
#
#     # Initialize status for roles visibility
#     if 'show_roles' not in st.session_state:
#         st.session_state.show_roles = False
#
#     tab1, tab2, tab3, tab4 = st.tabs([
#         "View Roles", "Create Role", "Create User", "Manage Role Access"
#     ])
#
#     # View Roles Tab
#     with tab1:
#         if st.button("Show/Hide Roles"):
#             st.session_state.show_roles = not st.session_state.show_roles
#
#         if st.session_state.show_roles:
#             roles_result = show_roles()
#             st.dataframe(roles_result)
#
#     # Create Role Tab
#     with tab2:
#         st.markdown("##### Create New Role")
#         new_role_name = st.text_input("Role Name", key="new_role_name")
#         role_comment = st.text_input("Role Comment", key="role_comment")
#
#         if st.button("Create Role", key="create_role_btn"):
#             if new_role_name:
#                 try:
#                     create_role(new_role_name, role_comment)
#                     st.success(f"Role '{new_role_name}' created successfully!")
#                 except Exception as e:
#                     st.error(f"Error creating role: {str(e)}")
#             else:
#                 st.warning("Please provide a role name.")
#
#     # Create User Tab
#     with tab3:
#         st.markdown("##### Create New User")
#         new_username = st.text_input("Username", key="new_username")
#         new_password = st.text_input("Password", type="password", key="new_password")
#         role_names = fetch_role_names()
#         default_role = st.selectbox("Default Role", role_names, key="default_role")
#
#         if st.button("Create User", key="create_user_btn"):
#             if new_username and new_password and default_role:
#                 try:
#                     create_user(new_username, new_password, default_role)
#                     st.success(f"User '{new_username}' created successfully!")
#                 except Exception as e:
#                     st.error(f"Error creating user: {str(e)}")
#             else:
#                 st.warning("Please provide username, password, and default role.")
#
#     # Manage Role Access Tab
#     with tab4:
#         st.markdown("##### Manage Role Access")
#         col1, col2 = st.columns(2)
#
#         # Fetch the list of users
#         try:
#             user_list = fetch_users(connector_connection)
#             usernames = [user['name'] for user in user_list]  # Extract the 'name' column for dropdown
#         except Exception as e:
#             st.error(f"Error fetching users: {str(e)}")
#             usernames = []
#
#         with col1:
#             action = st.radio("Select Action", ["Grant Role", "Revoke Role"])
#
#         with col2:
#             # Replace text input with selectbox for username
#             if usernames:
#                 user = st.selectbox("Select User", usernames, key="role_management_user")
#             else:
#                 user = None
#                 st.warning("No users available to select.")
#
#             # Fetch available roles
#             role_names = fetch_role_names()
#             role_name = st.selectbox("Role", role_names, key="role_management_role")
#
#         if st.button("Apply Changes", key="apply_role_changes"):
#             if user and role_name:
#                 try:
#                     if action == "Grant Role":
#                         grant_role(user, role_name)
#                         st.success(f"Role '{role_name}' granted to user '{user}'")
#                     else:
#                         revoke_role(user, role_name)
#                         st.success(f"Role '{role_name}' revoked from user '{user}'")
#                 except Exception as e:
#                     st.error(f"Error managing role: {str(e)}")
#             else:
#                 st.warning("Please provide both username and role name.")







import streamlit as st
import pandas as pd
from services.snowflake_utils import (
    get_available_databases, get_available_schemas, get_available_tables,
    check_user_role,fetch_users ,fetch_role_names
)
from app.request_handling import (
    submit_request, show_pending_requests, update_approval_status,
    get_user_requests, create_role, create_user, grant_role, revoke_role
)
from config.snowflake_connection import connector_connection

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

    # Tabs for different sections
    tab1, tab2, tab3, tab4 = st.tabs(["View Roles", "Create Role", "Create User", "Manage Role Access"])

    # View Roles Tab
    with tab1:
        if st.button("Show/Hide Roles"):
            st.session_state.show_roles = not st.session_state.show_roles

        if st.session_state.show_roles:
            roles = fetch_role_names(connector_connection)
            st.dataframe(roles)

    # Create Role Tab
    with tab2:
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
    with tab3:
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
    with tab4:
        # Fetch the list of users
        try:
            user_list = fetch_users(connector_connection)
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
