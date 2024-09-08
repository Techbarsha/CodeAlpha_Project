import sqlite3
import bcrypt

class UserLoginSystem:
    def __init__(self, db_path):
        self.connection = sqlite3.connect(db_path)
        self.cursor = self.connection.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute(
            """CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY, 
                password TEXT
            )"""
        )
        self.connection.commit()

    @staticmethod
    def hash_password(password):
        """Securely hash the password using bcrypt."""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt)

    @staticmethod
    def verify_password(password, hashed_password):
        """Verify the password against the stored hash."""
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

    def register_user(self, username, password):
        """Register a new user with hashed password and prevent SQL injection."""
        try:
            hashed_password = self.hash_password(password)
            query = "INSERT INTO users (username, password) VALUES (?, ?)"
            self.cursor.execute(query, (username, hashed_password))
            self.connection.commit()
            return "User registered successfully!"
        except sqlite3.IntegrityError:
            return "Username already exists!"

    def login_user(self, username, password):
        """Login user by securely verifying the password."""
        query = "SELECT password FROM users WHERE username = ?"
        self.cursor.execute(query, (username,))
        user = self.cursor.fetchone()
        if user and self.verify_password(password, user[0]):
            return "Login successful!"
        return "Invalid credentials!"

    def close(self):
        self.connection.close()


db_path = "user_data.db"
login_system = UserLoginSystem(db_path)
print(login_system.register_user("admin", "SecurePass123"))
print(login_system.login_user("admin", "SecurePass123"))
login_system.close()
# this code is conducted by Barsha Saha
