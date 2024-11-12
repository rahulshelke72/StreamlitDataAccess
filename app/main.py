import streamlit as st
from app.ui_components import render_request_form, render_approval_panel

# Set the page title and icon
st.set_page_config(page_title="Snowflake Access Management", page_icon="🔑")

# Define default users with roles
USERS = {
    "user": {"password": "user123", "role": "user"},
    "admin": {"password": "admin123", "role": "admin"},
    "sysadmin":{"password":"sysadmin123","role":"sysadmin"}
}

def login():
    """Render a login form for user authentication"""
    st.subheader("Login")

    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")

    if st.button("Login"):
        if username in USERS and USERS[username]["password"] == password:
            st.session_state.logged_in = True
            st.session_state.role = USERS[username]["role"]
            st.session_state.username = username
        else:
            st.error("Invalid username or password")

def main():
    st.title("Snowflake Request Management System")

    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        login()
    else:
        st.write(f"Welcome, {st.session_state.username} ({st.session_state.role.capitalize()})")
        st.button("Logout", on_click=lambda: st.session_state.clear())

        # Create tabs based on the user's role
        if st.session_state.role == "user":
            tab1, tab2 = st.tabs(["Submit Request", "Request Status"])
            with tab1:
                render_request_form()
            with tab2:
                st.write("Request status functionality goes here.")
        elif st.session_state.role == "admin":
            tab1, tab2 = st.tabs(["Submit Request", "Approval Panel"])
            with tab1:
                render_request_form()
            with tab2:
                render_approval_panel()

if __name__ == "__main__":
    main()
