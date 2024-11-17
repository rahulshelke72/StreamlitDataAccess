import streamlit as st
from app.user_model import register_user, validate_user, create_users_table
import re


def is_valid_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    is_valid = re.match(pattern, email) is not None
    print(f"Email validation for '{email}': {is_valid}")
    return is_valid


def render_registration_form():
    """Render the registration form"""
    st.markdown("<h2>Register New User</h2>", unsafe_allow_html=True)
    with st.form("registration_form"):
        username = st.text_input("Username*")
        password = st.text_input("Password*", type="password")
        confirm_password = st.text_input("Confirm Password*", type="password")
        email = st.text_input("Email*")
        full_name = st.text_input("Full Name*")
        submit_button = st.form_submit_button("Register")

        if submit_button:
            try:
                print("Registration form submitted")
                if not all([username, password, confirm_password, email, full_name]):
                    st.error("All fields are required")
                    print("Error: Missing fields")
                    return

                if password != confirm_password:
                    st.error("Passwords do not match")
                    print("Error: Passwords do not match")
                    return

                if len(password) < 8:
                    st.error("Password must be at least 8 characters long")
                    print(f"Error: Password too short: {len(password)} characters")
                    return

                if not is_valid_email(email):
                    st.error("Please enter a valid email address")
                    print("Error: Invalid email format")
                    return

                success = register_user(username, password, email, full_name)
                if success:
                    st.success("Registration successful! Please login.")
                    st.session_state.show_login = True
                else:
                    st.error("Username or email already exists")
                    print("Error: Registration failed, possibly due to duplicate username/email")
            except Exception as e:
                st.error("An unexpected error occurred during registration")
                print(f"Error during registration: {e}")


def render_login_form():
    """Render the login form"""
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown('<div style="text-align: center;"><img src="your_logo_url" alt="App Logo"></div>',
                    unsafe_allow_html=True)
        st.markdown("<h2>Login</h2>", unsafe_allow_html=True)
        with st.container():
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            login_button = st.button("Login", use_container_width=True)

            if login_button:
                try:
                    print("Login button clicked")
                    user_data = validate_user(username, password)
                    print(f"User data fetched: {user_data}")
                    if user_data:
                        st.session_state.logged_in = True
                        st.session_state.role = user_data["ROLE"]
                        st.session_state.username = user_data["USERNAME"]
                        st.session_state.email = user_data["EMAIL"]
                        st.session_state.full_name = user_data["FULL_NAME"]
                        st.rerun()
                    else:
                        st.error("Invalid username or password")
                        print("Error: Invalid credentials")
                except Exception as e:
                    st.error("An unexpected error occurred during login")
                    print(f"Error during login: {e}")

        st.markdown("---")
        st.markdown("Don't have an account?")
        if st.button("Register", use_container_width=True):
            st.session_state.show_login = False
            st.rerun()
        st.markdown('<div style="text-align: center;">...</div>', unsafe_allow_html=True)


def handle_authentication():
    """Handle authentication flow"""
    # Initialize session state variables
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    if "show_login" not in st.session_state:
        st.session_state.show_login = True

    # Ensure users table exists
    try:
        create_users_table()
        print("Users table creation ensured")
    except Exception as e:
        st.error("Failed to initialize the user database")
        print(f"Error creating users table: {e}")

    # Show appropriate form based on state
    if st.session_state.show_login:
        render_login_form()
    else:
        render_registration_form()
        if st.button("Back to Login", use_container_width=True):
            st.session_state.show_login = True
            st.rerun()
