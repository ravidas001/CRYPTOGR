import socket, json, base64, os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad

HOST = '127.0.0.1'
PORT = 5000
NAME = "Bob"

# --- RSA key generation ---
if not os.path.exists("bob_private.pem"):
    print("[Bob] Generating RSA key pair...")
    key = RSA.generate(2048)
    with open("bob_private.pem", "wb") as f:
        f.write(key.export_key())
    with open("bob_public.pem", "wb") as f:
        f.write(key.publickey().export_key())

# --- Load Bob's private key ---
privkey = RSA.import_key(open("bob_private.pem").read())

# --- Connect to the server ---
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
sock.sendall(json.dumps({"type": "register", "name": NAME}).encode())

aes_key = None
messages = []

print("\n[Bob] ✅ Connected to server and registered.")
print("[Bob] Waiting for messages...\n")

try:
    while True:
        data = sock.recv(65536)
        if not data:
            break

        try:
            msg = json.loads(data.decode())
        except json.JSONDecodeError:
            continue  # Ignore invalid data

        mtype = msg.get("type")
        sender = msg.get("from")
        payload_b64 = msg.get("payload_b64", "")

        print(f"\n🔒 Encrypted data received from {sender}: {payload_b64[:60]}...")

        # --- Handle session key ---
        if mtype == "session_key":
            try:
                encrypted_key = base64.b64decode(payload_b64)
                cipher_rsa = PKCS1_OAEP.new(privkey)
                aes_key = cipher_rsa.decrypt(encrypted_key)
                print("✅ AES session key decrypted and stored.")
            except Exception as e:
                print(f"⚠️ Error decrypting session key: {e}")

        # --- Handle encrypted message ---
        elif mtype == "message":
            if aes_key is None:
                print("⚠️ No AES session key available yet — cannot decrypt.")
                continue

            try:
                iv_ct = base64.b64decode(payload_b64)
                iv, ct = iv_ct[:16], iv_ct[16:]
                cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
                plaintext = unpad(cipher_aes.decrypt(ct), AES.block_size).decode("utf-8")

                print(f"💬 Message from {sender}: {plaintext}")

                messages.append({
                    "type": "message",
                    "from": sender,
                    "ciphertext_b64": payload_b64,
                    "plaintext": plaintext
                })

            except Exception as e:
                print(f"⚠️ Error decrypting message: {e}")

        else:
            print(f"⚠️ Unknown message type: {mtype}")

        # --- Save logs ---
        with open("bob-messages.json", "w") as f:
            json.dump(messages, f, indent=2)

except KeyboardInterrupt:
    print("\n[Bob] Chat closed.")
finally:
    sock.close()
