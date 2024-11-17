from app.user_model import create_users_table, register_user
import hashlib
from config.snowflake_connection import session


def add_predefined_users():
    """Add predefined users to the USER_ACCOUNTS table"""
    predefined_users = [
        {"username": "accountadmin", "password": "admin123", "email": "accountadmin@example.com",
         "full_name": "Account Admin", "role": "ACCOUNTADMIN"},
        {"username": "sysadmin", "password": "admin123", "email": "sysadmin@example.com", "full_name": "System Admin",
         "role": "SYSADMIN"}
    ]
    for user in predefined_users:
        try:
            # Hash the password
            password_hash = hashlib.sha256(user["password"].encode()).hexdigest()
            print(f"Adding user: {user['username']} with role: {user['role']}")

            # Insert the user
            session.sql("""
                INSERT INTO RAHUL.USERS.USER_ACCOUNTS (USERNAME, PASSWORD_HASH, EMAIL, FULL_NAME, ROLE, STATUS)
                VALUES (?, ?, ?, ?, ?, 'active')
            """).params(user["username"], password_hash, user["email"], user["full_name"], user["role"]).collect()
            print(f"User {user['username']} added successfully.")
        except Exception as e:
            print(f"Error adding user {user['username']}: {e}")


# Initialize the table and add predefined users
if __name__ == "__main__":
    if create_users_table():
        print("User table created or already exists.")
        add_predefined_users()
    else:
        print("Failed to create user table.")
