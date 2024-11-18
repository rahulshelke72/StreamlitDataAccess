import streamlit as st
from app.ui_components import (
    render_request_form, render_approval_panel,
    render_user_requests, render_roles_users_panel
)
from app.auth_components import handle_authentication

# Configure page settings for better layout
st.set_page_config(
    page_title="Snowflake Request Management",
    page_icon="❄️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling - reduced top spacing
st.markdown("""
    <style>
    /* Remove top padding from main container */
    .main {
        padding-top: 0rem;
    }

    /* Reduce spacing of header */
    header {
        background-color: transparent !important;
    }

    /* Remove default Streamlit padding */
    .stApp {
        max-width: 1200px;
        margin: 0 auto;
    }

    /* Adjust header margins */
    .main-header {
        font-size: 1.8rem;
        padding: 0.5rem 0;
        margin-top: -1rem;
        text-align: center;
        color: #0066cc;
    }

    /* Remove padding from containers */
    .stContainer {
        padding-top: 0 !important;
    }

    /* Style for the login container */
    .login-container {
        padding: 1rem;
        margin-top: -1rem;
    }

    .user-welcome {
        padding: 0.5rem;
        background-color: #f0f2f6;
        border-radius: 5px;
        margin-bottom: 1rem;
    }

    /* Button styling */
    .stButton>button {
        width: 100%;
    }

    /* Tab styling */
    .stTabs {
        margin-top: 0.5rem;
    }

    /* Sidebar adjustments */
    .css-1d391kg {
        padding-top: 1rem;
    }
    </style>
    """, unsafe_allow_html=True)

def create_sidebar():
    """Create a sidebar with user information and logout button"""
    with st.sidebar:
        st.markdown("<div style='margin-top: -2rem;'>", unsafe_allow_html=True)
        st.markdown("### User Information")
        st.markdown(f"**Username:** {st.session_state.username}")
        st.markdown(f"**Name:** {st.session_state.full_name}")
        st.markdown(f"**Email:** {st.session_state.email}")
        st.markdown(f"**Role:** {st.session_state.role.capitalize()}")
        if st.button("Logout", key="logout_button"):
            st.session_state.clear()
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

def main():
    """Main application with improved layout and navigation"""
    # Create the header with minimal spacing
    st.markdown("<div style='margin-top: -3rem;'>", unsafe_allow_html=True)
    st.markdown("<h1 class='main-header'>Snowflake Request Management System</h1>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    if not st.session_state.get("logged_in", False):
        handle_authentication()
    else:
        # Create sidebar
        create_sidebar()

        # Create container for main content with reduced spacing
        main_container = st.container()

        with main_container:
            if st.session_state.role == "user":
                tab1, tab2 = st.tabs(["📝 Submit Request", "📊 Request Status"])
                with tab1:
                    with st.container():
                        render_request_form()
                with tab2:
                    with st.container():
                        render_user_requests()

            elif st.session_state.role in ["ACCOUNTADMIN", "SYSADMIN"]:
                tab1, tab2, tab3 = st.tabs(
                    ["📝 Submit Request", "✅ Approval Panel", "🔧 Role/User Management"]
                )
                with tab1:
                    with st.container():
                        render_request_form()
                with tab2:
                    with st.container():
                        render_approval_panel()
                with tab3:
                    with st.container():
                        render_roles_users_panel()

if __name__ == "__main__":
    main()