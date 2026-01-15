import sqlite3

conn = sqlite3.connect("db.sqlite")
conn.executescript("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TRIGGER IF NOT EXISTS update_users_timestamp AFTER UPDATE ON users
FOR EACH ROW BEGIN UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id; END;
""")
conn.commit()
conn.close()
print("Base de donnees creee.")
