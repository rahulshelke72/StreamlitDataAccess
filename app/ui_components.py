import streamlit as st
import pandas as pd
from services.snowflake_utils import get_available_databases, get_available_schemas, get_available_tables, check_user_role
from app.request_handling import submit_request, show_pending_requests, update_approval_status, get_user_requests

ACCOUNTADMIN_ROLE = 'ACCOUNTADMIN'
SYSADMIN_ROLE  = 'SYSADMIN'

def render_request_form():
    """Render the form for users to submit requests"""
    st.subheader("Submit a Request")

    username = st.session_state.get("username", "Guest")
    request_type = st.selectbox("Select Request Type", ["DATABASE_ACCESS", "SCHEMA_ACCESS", "TABLE_ACCESS"])

    request_details = ""

    if request_type == "DATABASE_ACCESS":
        # Database Access request type
        databases = get_available_databases()
        if databases:
            selected_database = st.selectbox("Select a Database", databases)
            print("Database Name",selected_database)
            request_details = selected_database
        else:
            st.warning("No databases available for selection.")
            request_details = None

    elif request_type == "SCHEMA_ACCESS":
        # Schema Access request type
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
        else:
            st.warning("No databases available for selection.")
            request_details = None

    elif request_type == "TABLE_ACCESS":
        # Table Access request type
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
        else:
            st.warning("No databases available for selection.")
            request_details = None

    # Additional Comments
    additional_comments = st.text_area("Additional Comments (optional)")
    if request_details and additional_comments:
        request_details += f"\n\nAdditional Comments: {additional_comments}"

    # Submit Request Button
    if st.button("Submit Request"):
        if username and request_type and request_details:
            # Submit request and update the status
            submit_request(username, request_type, request_details)
            # Initialize the request status if not already done
            if 'requests_status' not in st.session_state:
                st.session_state.requests_status = {}
            st.session_state.requests_status[username] = {"status": "Pending", "details": request_details}
            st.success("Request submitted successfully.")

        else:
            st.warning("Please provide username, request type, and details.")

    # Show the request status for the user
    if 'requests_status' in st.session_state and username in st.session_state.requests_status:
        request_status = st.session_state.requests_status[username]
        st.write(f"Your request is currently: {request_status['status']}")
        st.write(f"Request details: {request_status['details']}")


def render_approval_panel():
    """Render the approval panel for admins to review requests."""
    st.subheader("Request Approval Panel")

    current_role = st.session_state.get("role")
    if current_role not in [ACCOUNTADMIN_ROLE, SYSADMIN_ROLE]:
        st.warning("You must be an Admin to approve/reject requests.")
        return

    # Refresh requests
    if st.button("Refresh Requests"):
        st.session_state.pending_requests = show_pending_requests()

    if 'pending_requests' not in st.session_state:
        st.session_state.pending_requests = show_pending_requests()

    pending_requests = st.session_state.pending_requests

    if not pending_requests:
        st.info("No requests found.")
        return

    df = pd.DataFrame(pending_requests)

    for idx, request in df.iterrows():
        with st.expander(f"Request #{request['REQUEST_ID']} - {request['USERNAME']} - {request['REQUEST_TYPE']}"):
            st.write(f"**Details:** {request['REQUEST_DETAILS']}")
            st.write(f"**Date:** {request['REQUEST_DATE']}")
            st.write(f"**Status:** {request['STATUS']}")  # Display request status (Pending, Approved, Rejected)

            # Show current approval status for each role
            # Determine status for ACCOUNTADMIN_APPROVAL and SYSADMIN_APPROVAL
            accountadmin_status = "APPROVED" if request.get('ACCOUNTADMIN_APPROVAL') is True else "REJECTED" if request.get('ACCOUNTADMIN_APPROVAL') is False else "PENDING"
            sysadmin_status = "APPROVED" if request.get('SYSADMIN_APPROVAL') is True else "REJECTED" if request.get('SYSADMIN_APPROVAL') is False else "PENDING"

            # Display the results in Streamlit
            st.write(f"**Account Admin Approval:** {accountadmin_status}")
            st.write(f"**Sys Admin Approval:** {sysadmin_status}")

            col1, col2 = st.columns(2)

            # Independent approval/rejection for Account Admin
            if current_role == "ACCOUNTADMIN" and request['ACCOUNTADMIN_APPROVAL'] is None:
                with col1:
                    if st.button("Approve", key=f"approve_accountadmin_{request['REQUEST_ID']}_{idx}"):
                        update_approval_status(request['REQUEST_ID'], True, "ACCOUNTADMIN")
                        st.session_state.pending_requests = show_pending_requests()
                with col2:
                    if st.button("Reject", key=f"reject_accountadmin_{request['REQUEST_ID']}_{idx}"):
                        rejection_reason = st.text_area("Reason for rejection (Account Admin)",
                                                        key=f"reject_reason_accountadmin_{request['REQUEST_ID']}_{idx}")
                        if rejection_reason:
                            update_approval_status(request['REQUEST_ID'], False, "ACCOUNTADMIN", rejection_reason)
                            st.session_state.pending_requests = show_pending_requests()
                        else:
                            st.warning("Please provide a rejection reason.")

            # Independent approval/rejection for Sys Admin
            if current_role == "SYSADMIN" and request['SYSADMIN_APPROVAL'] is None:
                with col1:
                    if st.button("Approve", key=f"approve_sysadmin_{request['REQUEST_ID']}_{idx}"):
                        update_approval_status(request['REQUEST_ID'], True, "SYSADMIN")
                        st.session_state.pending_requests = show_pending_requests()
                with col2:
                    if st.button("Reject", key=f"reject_sysadmin_{request['REQUEST_ID']}_{idx}"):
                        rejection_reason = st.text_area("Reason for rejection (Sys Admin)",
                                                        key=f"reject_reason_sysadmin_{request['REQUEST_ID']}_{idx}")
                        if rejection_reason:
                            update_approval_status(request['REQUEST_ID'], False, "SYSADMIN", rejection_reason)
                            st.session_state.pending_requests = show_pending_requests()
                        else:
                            st.warning("Please provide a rejection reason.")

            # If already processed, show message but keep buttons available for independent decisions
            if request['STATUS'] != 'PENDING':
                st.info(
                    f"This request is currently marked as {request['STATUS']}.")


def render_user_requests():
    """Render the requests panel for users to view their requests and statuses"""
    st.subheader("Your Requests")

    current_role = st.session_state.get("role")
    if current_role != "user":
        st.warning("You must be a User to view your requests.")
        return

    # Refresh requests for the user
    if st.button("Refresh Requests"):
        st.session_state.user_requests = get_user_requests(st.session_state.username)

    if 'user_requests' not in st.session_state:
        st.session_state.user_requests = get_user_requests(st.session_state.username)

    user_requests = st.session_state.user_requests

    if not user_requests:
        st.info("You have no requests.")
        return

    df = pd.DataFrame(user_requests)

    # Display each request in an expandable section
    for _, request in df.iterrows():
        with st.expander(f"Request #{request['REQUEST_ID']} - {request['REQUEST_TYPE']}"):
            st.write(f"**Details:** {request['REQUEST_DETAILS']}")
            st.write(f"**Date:** {request['REQUEST_DATE']}")
            st.write(f"**Status:** {request['STATUS']}")