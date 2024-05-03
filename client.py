import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
import os
import traceback

def get_server_ip(broadcast_port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client_socket.bind(('', broadcast_port))

    while True:
        try:
            data, addr = client_socket.recvfrom(1024)
            message = data.decode()
            if message.startswith("SERVER_IP:"):
                server_ip = message.split(":")[1]
                client_socket.close()
                return server_ip
        except (KeyboardInterrupt, Exception) as e:
            print(f"Error: {e}")
            client_socket.close()
            break

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Load creditinfo data from file
def load_creditinfo():
    creditinfo = {}
    with open("creditinfo.txt", "r") as file:
        for line in file:
            name, hashed_card, available_credits = line.strip().split()
            creditinfo[name] = (hashed_card, int(available_credits))
    return creditinfo

def hash_credit_card_number(credit_card_number):
    # Hash the credit card number using SHA-256
    digest = hashes.Hash(hashes.SHA256())
    digest.update(credit_card_number.encode())
    hashed_credit_card_number = digest.finalize()
    # Convert the hashed value to a hexadecimal string
    hashed_credit_card_number_hex = hashed_credit_card_number.hex()
    return hashed_credit_card_number_hex

# Encrypt message using hybrid encryption (AES for message, RSA for AES key)
def encrypt_message(message, public_key):
    try:
        backend = default_backend()
        # Generate a random AES key
        aes_key = os.urandom(32)  # 32 bytes for AES-256
        
        # Encrypt the message using AES
        iv = os.urandom(16)  # 16 bytes for AES IV
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=backend)
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(message.encode()) + encryptor.finalize()
        
        # Encrypt the AES key with RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Concatenate IV, encrypted AES key, and encrypted data
        encrypted_message = iv + encrypted_aes_key + encrypted_data
        return encrypted_message
    except Exception as e:
        print("Encryption failed:", e)
        traceback.print_exc()  # Print traceback for detailed error information
        return None

# Sign data using client's private key
def sign(data, private_key):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def main():
    try:
        broadcast_port = 9999  # Choose the same broadcast port as the server
        server_ip = get_server_ip(broadcast_port)
        server_port = 12346  # Default port number

        # Create a socket and connect it to the server IP and port
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((server_ip, server_port))
        
        item_data = server_socket.recv(1024).decode()
        print("Received item data from server:", item_data)

        # Parse item data and get the item price
        items = item_data.split("\n")
        item_details = {}
        for item in items:
            item_number, item_name, item_price = item.split()
            item_details[item_number] = (item_name, int(item_price))

        # Handle further communication with the server as needed
        item_number = input("Enter the item number you wish to purchase: ")
        if item_number not in item_details:
            print("Invalid item number.")
            return

        name = input("Enter your name: ")
        credit_card_number = input("Enter your credit card number: ")

        if not (name and credit_card_number):
            print("Invalid input. Please provide all required information.")
            return

        # Get the item price based on the selected item number
        item_name, item_price = item_details[item_number]

        # Hash the credit card number
        hashed_credit_card_number = hash_credit_card_number(credit_card_number)

        # Encrypt the message
        encrypted_message = encrypt_message(f"{item_number}||{name}||{hashed_credit_card_number}", public_key)
        if encrypted_message is None:
            print("Failed to encrypt the message.")
            return

        # Send the encrypted message to the server
        server_socket.sendall(encrypted_message)

        response = server_socket.recv(1024).decode()
        if response == "1":
            print("Your order is confirmed.")
        else:
            print("Credit card transaction is unauthorized.")

        server_socket.close()

        # Connect to the bank server
        bank_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bank_socket.connect(('localhost', 12345))  # Replace with the bank server's IP and port

        # Prepare the data to send to the bank
        data_to_sign = f"{item_price}||{name}||{credit_card_number}"
        signature = sign(data_to_sign.encode(), private_key)

        # Send the data to the bank
        data_to_send = f"{item_price}||{name}||{credit_card_number}||{signature.hex()}"
        bank_socket.sendall(data_to_send.encode())

        # Receive the response from the bank
        response = bank_socket.recv(1024).decode()
        if response == "1":
            print("Transaction successful.")
        else:
            print("Transaction failed.")

        bank_socket.close()

    except Exception as e:
        print("An error occurred during execution:", e)

if __name__ == "__main__":
    main()