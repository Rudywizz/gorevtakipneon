import sqlite3

conn = sqlite3.connect('gorev_takip.db')
cursor = conn.cursor()

try:
    cursor.execute("ALTER TABLE tasks ADD COLUMN completion_note TEXT")
    print("completion_note sütunu eklendi.")
except Exception as e:
    print("Hata:", e)

conn.commit()
conn.close()
