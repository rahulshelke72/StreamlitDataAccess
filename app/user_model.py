from datetime import datetime
import hashlib
from config.snowflake_connection import connector_connection, session


def create_users_table():
    """Create users table in Snowflake if it doesn't exist"""
    try:
        session.sql("""
            CREATE TABLE IF NOT EXISTS RAHUL.USERS.USER_ACCOUNTS (
                USER_ID NUMBER AUTOINCREMENT,
                USERNAME VARCHAR(50) UNIQUE NOT NULL,
                PASSWORD_HASH VARCHAR(256) NOT NULL,
                EMAIL VARCHAR(100) UNIQUE NOT NULL,
                FULL_NAME VARCHAR(100) NOT NULL,
                ROLE VARCHAR(20) DEFAULT 'user',
                CREATED_AT TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
                LAST_LOGIN TIMESTAMP_NTZ,
                STATUS VARCHAR(20) DEFAULT 'active',
                PRIMARY KEY (USER_ID)
            )
        """).collect()
        return True
    except Exception as e:
        print(f"Error creating users table: {e}")
        return False


# def hash_password(password: str) -> str:
#     """Hash password using SHA-256"""
#     return hashlib.sha256(password.encode()).hexdigest()


def register_user(username: str, password: str, email: str, full_name: str) -> bool:
    """Register a new user in Snowflake"""
    try:
        # password_hash = hash_password(password)
        # Using string formatting with quotes for string values
        query = f"""
            INSERT INTO RAHUL.USERS.USER_ACCOUNTS (USERNAME, PASSWORD_HASH, EMAIL, FULL_NAME, ROLE)
            VALUES ('{username}', '{password}', '{email}', '{full_name}', 'user')
        """
        session.sql(query).collect()
        return True
    except Exception as e:
        print(f"Error registering user: {e}")
        return False


def validate_user(username: str, password: str) -> dict:
    """Validate user credentials and return user data"""
    try:
        # password_hash = hash_password(password)
        # Using string formatting with quotes for string values
        query = f"""
            SELECT USERNAME, ROLE, EMAIL, FULL_NAME 
            FROM RAHUL.USERS.USER_ACCOUNTS 
            WHERE USERNAME = '{username}' 
            AND PASSWORD_HASH = '{password}' 
            AND STATUS = 'active'
        """
        result = session.sql(query).collect()

        if len(result) > 0:
            user_data = {
                'USERNAME': result[0]['USERNAME'],
                'ROLE': result[0]['ROLE'],
                'EMAIL': result[0]['EMAIL'],
                'FULL_NAME': result[0]['FULL_NAME']
            }

            # Update last login
            update_query = f"""
                UPDATE RAHUL.USERS.USER_ACCOUNTS 
                SET LAST_LOGIN = CURRENT_TIMESTAMP()
                WHERE USERNAME = '{username}'
            """
            session.sql(update_query).collect()
            return user_data
        return None
    except Exception as e:
        print(f"Error validating user: {e}")
        return None