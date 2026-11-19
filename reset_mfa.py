
import sqlite3

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

cursor.execute("""
    UPDATE users
    SET mfa_enabled = 0,
        totp_secret = NULL
    WHERE username = 'student'
""")

conn.commit()

print("MFA has been reset for the student account.")

conn.close()
