import socket
import threading
import json

HOST = '127.0.0.1'
PORT = 5000
clients = {}

def handle_client(conn):
    try:
        while True:
            data = conn.recv(65536)
            if not data:
                break
            msg = json.loads(data.decode())
            to = msg.get("to")
            frm = msg.get("from")
            mtype = msg.get("type")
            print(f"[SERVER] {mtype} from {frm} to {to}")
            print("Ciphertext (base64):", msg.get("payload_b64")[:60], "...\n")
            if to in clients:
                clients[to].sendall(json.dumps(msg).encode())
    except:
        pass
    finally:
        conn.close()

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen()
    print(f"[SERVER] Listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        reg = json.loads(conn.recv(65536).decode())
        name = reg["name"]
        clients[name] = conn
        print(f"[SERVER] {name} connected.")
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()

if __name__ == "__main__":
    main()
