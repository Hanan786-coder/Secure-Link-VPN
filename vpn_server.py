import socket
import ssl
import threading
import json
import hashlib
import os
import zlib
import base64

# Configuration
HOST = '0.0.0.0'
PORT = 8443
CERT_FILE = 'certs/server.crt'
KEY_FILE = 'certs/server.key'
USER_DB_FILE = 'users.json'
FILES_DIR = 'server_files'


def setup_files_dir():
    if not os.path.exists(FILES_DIR):
        os.makedirs(FILES_DIR)
        with open(f"{FILES_DIR}/welcome.txt", "w") as f:
            f.write("Welcome to the Secure VPN File Server!")


def send_packet(conn, data_dict):
    """Sends JSON data ending with a newline character"""
    try:
        json_str = json.dumps(data_dict)
        conn.sendall(json_str.encode('utf-8') + b'\n')
    except Exception as e:
        print(f"[-] Send Error: {e}")


# --- NEW: Helper to send file with size info ---
def send_file_packet(conn, filename, b64_data):
    """Calculates size, sends header, then sends data"""
    try:
        # Prepare the actual big data packet
        data_packet = {
            "type": "file_data",
            "filename": filename,
            "data": b64_data,
            "status": "success"
        }
        json_str = json.dumps(data_packet)
        total_bytes = len(json_str.encode('utf-8'))  # Exact size in bytes

        # 1. Send Header (Total Size)
        send_packet(conn, {
            "type": "dl_start",
            "filename": filename,
            "total_size": total_bytes
        })

        # 2. Send The Content
        conn.sendall(json_str.encode('utf-8') + b'\n')

    except Exception as e:
        print(f"[-] File Send Error: {e}")


def load_users():
    if not os.path.exists(USER_DB_FILE): return {}
    try:
        with open(USER_DB_FILE, 'r') as f:
            return json.loads(f.read().strip())
    except:
        return {}


def save_new_user(username, password_hash):
    users = load_users()
    if username in users: return False
    users[username] = password_hash
    with open(USER_DB_FILE, 'w') as f: json.dump(users, f, indent=4)
    return True


def generate_virtual_ip(username):
    crc = zlib.crc32(username.encode())
    last_octet = (crc % 253) + 2
    return f"10.8.0.{last_octet}"


def handle_client(conn, addr):
    print(f"[+] Connection from {addr[0]}")
    client_user = "Unknown"
    buffer = ""

    try:
        while True:
            data = conn.recv(4096).decode('utf-8')
            if not data: break
            buffer += data

            while '\n' in buffer:
                message, buffer = buffer.split('\n', 1)
                if not message: continue

                request = json.loads(message)
                action = request.get('action', '')
                req_type = request.get('type', '')

                if action == 'signup':
                    new_user = request.get('username')
                    new_pass = request.get('password')
                    pwd_hash = hashlib.sha256(new_pass.encode()).hexdigest()
                    if save_new_user(new_user, pwd_hash):
                        send_packet(conn, {"status": "success", "msg": "Created"})
                    else:
                        send_packet(conn, {"status": "fail", "msg": "Exists"})
                    return

                elif action == 'login':
                    user_db = load_users()
                    username = request.get('username')
                    input_hash = hashlib.sha256(request.get('password').encode()).hexdigest()

                    if username in user_db and user_db[username] == input_hash:
                        client_user = username
                        virtual_ip = generate_virtual_ip(username)
                        send_packet(conn,
                                    {"status": "success", "vip": virtual_ip, "real_ip": addr[0], "msg": "Authorized"})
                        print(f"[V] {username} logged in.")
                    else:
                        send_packet(conn, {"status": "fail", "msg": "Bad Credentials"})
                        return

                elif req_type == 'message':
                    print(f"[{client_user}]: {request['payload']}")
                    send_packet(conn, {"type": "response", "payload": request['payload']})

                elif req_type == 'list_files':
                    try:
                        files = os.listdir(FILES_DIR)
                        send_packet(conn, {"type": "file_list", "files": files})
                    except:
                        pass

                # --- UPDATED DOWNLOAD LOGIC ---
                elif req_type == 'download':
                    filename = request.get('filename')
                    filepath = os.path.join(FILES_DIR, filename)
                    if os.path.exists(filepath):
                        print(f"[*] Preparing {filename} for {client_user}...")
                        with open(filepath, "rb") as f:
                            b64_data = base64.b64encode(f.read()).decode('utf-8')

                        # Use the new helper to send size + data
                        send_file_packet(conn, filename, b64_data)
                        print(f"[+] Sent {filename}")
                    else:
                        send_packet(conn, {"type": "file_data", "filename": filename, "status": "fail"})

    except ConnectionResetError:
        print(f"[-] {client_user} disconnected (Connection Reset).")
    except Exception as e:
        print(f"[-] Error with {client_user}: {e}")
    finally:
        conn.close()
        if client_user != "Unknown": print(f"[-] Session closed: {client_user}")


def start_server():
    if not os.path.exists(CERT_FILE): print("Missing certs. Run setup_certs.py"); return
    if not os.path.exists(USER_DB_FILE):
        with open(USER_DB_FILE, 'w') as f: json.dump({}, f)
    setup_files_dir()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT_FILE, KEY_FILE)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(5)
    print(f"[*] Server listening on {HOST}:{PORT}")
    while True:
        try:
            raw, addr = sock.accept()
            conn = context.wrap_socket(raw, server_side=True)
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except:
            pass


if __name__ == "__main__":
    start_server()