import socket, json, base64, os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

HOST = '127.0.0.1'
PORT = 5000
NAME = "Alice"

if not os.path.exists("alice_private.pem"):
    key = RSA.generate(2048)
    with open("alice_private.pem", "wb") as f:
        f.write(key.export_key())
    with open("alice_public.pem", "wb") as f:
        f.write(key.publickey().export_key())

# Load Bob’s public key
if not os.path.exists("bob_public.pem"):
    print("Run receiver.py once first to create Bob’s public key.")
    exit()

bob_pubkey = RSA.import_key(open("bob_public.pem").read())
rsa_cipher = PKCS1_OAEP.new(bob_pubkey)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
sock.sendall(json.dumps({"type": "register", "name": NAME, "from": NAME, "to": ""}).encode())

aes_key = get_random_bytes(16)
enc_key = rsa_cipher.encrypt(aes_key)
sock.sendall(json.dumps({"type": "session_key", "from": NAME, "to": "Bob", "payload_b64": base64.b64encode(enc_key).decode()}).encode())

print("[Alice] Session key sent to Bob.")

messages = []
while True:
    text = input("Enter message to Bob (or 'quit'): ")
    if text.lower() == "quit":
        break
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher_aes.encrypt(pad(text.encode(), AES.block_size))
    iv_ct = cipher_aes.iv + ct_bytes
    msg = {"type": "message", "from": NAME, "to": "Bob", "payload_b64": base64.b64encode(iv_ct).decode()}
    sock.sendall(json.dumps(msg).encode())
    print("[Alice] Encrypted message sent.")
    messages.append({"type": "message", "to": "Bob", "ciphertext_b64": base64.b64encode(iv_ct).decode(), "plaintext": text})
    with open("alice-messages.json", "w") as f:
        json.dump(messages, f, indent=2)
