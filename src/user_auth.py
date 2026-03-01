import streamlit as st
import os
import platformdirs
from streamlit_google_auth import Authenticate

# Constants
APP_NAME = "auto_diagram"
# Note: Streamlit handles secrets.toml automatically via st.secrets
WORKDIR_ENV_VAR = "AUTO_DIAGRAM_WORKDIR"
REDIRECT_URI = "http://localhost:8501"
COOKIE_NAME = "google_auth_cookie"
COOKIE_KEY = "some_signature_key"

import streamlit as st
from streamlit_google_auth import Authenticate

# Constants - Ensure these match your environment
REDIRECT_URI = "http://localhost:8501"
COOKIE_NAME = "google_auth_cookie"
COOKIE_KEY = "some_signature_key"

import streamlit as st
from streamlit_google_auth import Authenticate

# Configuration constants
REDIRECT_URI = "http://localhost:8501"
COOKIE_NAME = "google_auth_cookie"
COOKIE_KEY = "some_signature_key"

def authenticate() -> bool:
    """
    Handles Google OAuth2 authentication. 
    Returns True if user is logged in, False otherwise.
    """
    json_path = "./.streamlit/google_credentials.json"
    
    try:
        # Initialize the Google Authenticator
        authenticator = Authenticate(
            secret_credentials_path=json_path, 
            redirect_uri=REDIRECT_URI,
            cookie_name=COOKIE_NAME,
            cookie_key=COOKIE_KEY
        )
    except Exception as e:
        st.sidebar.error(f"Authentication Error: {e}")
        return False

    # Check the actual keys used by the library
    # Some versions use 'connected', some use 'auth_state'
    is_connected = st.session_state.get("connected", False)
    user_info = st.session_state.get("user_info")

    with st.sidebar:
        # If the user is connected, we ONLY show the profile
        if is_connected and user_info:
            st.markdown("### User Profile")
            col_img, col_text = st.columns([1, 3])
            
            with col_img:
                if user_info.get("picture"):
                    st.image(user_info.get("picture"), width=50)
            
            with col_text:
                st.write(f"Hello, \n**{user_info.get('name')}**")
            
            if st.button("Logout", use_container_width=True, key="auth_logout_btn"):
                # Manually clear everything to force Guest Mode
                st.session_state["connected"] = False
                st.session_state["user_info"] = None
                try:
                    authenticator.logout()
                except:
                    pass
                st.rerun()
            
            st.divider()
            return True 
            
        # Else, we ONLY show the Guest Mode / Login UI
        else:
            st.markdown("### Account")
            st.write("👤 **Guest Mode**")
            
            # Using a unique key for the button to prevent state freezing
            if st.button("Login with Google", use_container_width=True, key="auth_login_btn"):
                authenticator.login()
                
            st.caption("Login to sync your sessions.")
            return False