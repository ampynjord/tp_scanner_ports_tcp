from src.db import get_connection


def user_exists(username):
    """Vérifie si un utilisateur existe."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        return result is not None


def add_user(username, password):
    """Ajoute un nouvel utilisateur."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)", (username, password)
        )
        conn.commit()


def get_user_password(username):
    """Récupère le mot de passe hashé d'un utilisateur."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        return result[0] if result else None
