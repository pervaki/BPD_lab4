import hashlib
import rsa

def generate_keys():
    (public_key, private_key) = rsa.newkeys(512)
    return public_key, private_key

def encrypt_file(filename, public_key):
    with open(filename, 'rb') as f:
        file_data = f.read()
    encrypted_data = rsa.encrypt(file_data, public_key)
    with open(f"{filename}.enc", 'wb') as f:
        f.write(encrypted_data)

def decrypt_file(filename, private_key):
    with open(filename, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = rsa.decrypt(encrypted_data, private_key)
    with open(f"{filename}.dec", 'wb') as f:
        f.write(decrypted_data)

def hash_sha1(data):
    sha1 = hashlib.sha1()
    sha1.update(data.encode('utf-8'))
    return sha1.hexdigest()

def sign_message(message, private_key):
    message_hash = hash_sha1(message)
    signature = rsa.sign(message_hash.encode(), private_key, 'SHA-1')
    return signature

def verify_signature(message, signature, public_key):
    try:
        message_hash = hash_sha1(message)
        rsa.verify(message_hash.encode(), signature, public_key)
        print("Підпис вірний")
    except:
        print("Підпис невірний")

public_key, private_key = generate_keys()
message = "Hello, world!"
signature = sign_message(message, private_key)

verify_signature(message, signature, public_key)

encrypt_file('test.txt', public_key)
decrypt_file('test.txt.enc', private_key)
