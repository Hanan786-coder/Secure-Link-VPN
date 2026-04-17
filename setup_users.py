# setup_users.py
import json
import hashlib


def create_user_db():
    # Define your users here (Username : Plaintext Password)
    # Example users
    users = {
        "admin": "password123",
        "alice": "secret2025",
        "bob": "vpn_user_99",
    }

    hashed_db = {}

    print("[*] Hashing passwords and creating database...")

    for username, password in users.items():
        # We store ONLY the hash, never the plain password
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        hashed_db[username] = pwd_hash
        print(f"[-] User '{username}' added.")
    with open("users.json", "w") as f:
        json.dump(hashed_db, f, indent=4)

    print("[+] 'users.json' created successfully.")


if __name__ == "__main__":
    create_user_db()