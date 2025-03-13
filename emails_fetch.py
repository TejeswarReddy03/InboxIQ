import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("SELECT * FROM emails")
emails = cursor.fetchall()

print("Stored Emails:")
for email in emails:
    print(email)

conn.close()
