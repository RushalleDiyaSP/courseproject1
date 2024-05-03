from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import socket
import traceback

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Serialize public key
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Deserialize public key
public_key = serialization.load_pem_public_key(public_key_pem)

# Load creditinfo data from file
def load_creditinfo():
    creditinfo = {}
    with open("creditinfo.txt", "r") as file:
        for line in file:
            name, hashed_card, available_credits = line.strip().split()
            creditinfo[name] = (hashed_card, int(available_credits))
    return creditinfo

# Function to update available credits in creditinfo file
def update_creditinfo(name, new_available_credits, credit_card_number):
    creditinfo = load_creditinfo()
    hashed_card = hash(credit_card_number)
    if name in creditinfo and creditinfo[name][0] == str(hashed_card):
        creditinfo[name] = (creditinfo[name][0], new_available_credits)
        with open("creditinfo.txt", "w") as file:
            for name, (hashed_card, available_credits) in creditinfo.items():
                file.write(f"{name} {hashed_card} {available_credits}\n")

# Sign data using bank's private key
def sign(data):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Validate transaction
def validate_transaction(name, credit_card_number, item_price):
    creditinfo = load_creditinfo()
    hashed_card = hash(credit_card_number)
    if name in creditinfo and creditinfo[name][0] == str(hashed_card) and creditinfo[name][1] >= item_price:
        return True
    else:
        return False

# Main function
def main():
    while True:
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind(('localhost', 12345))
            server_socket.listen(1)
            print("Bank is listening...")
            
            conn, addr = server_socket.accept()
            with conn:
                print('Connected by', addr)
                data = conn.recv(1024)
                print("Received data from client:", data.decode())
                data_parts = data.decode().split("||")
                if len(data_parts) == 4:  # Check if data has expected format
                    item_price, customer_name, credit_card_number, signature = data_parts
                    if public_key.verify(
                        signature,
                        (item_price + customer_name + credit_card_number).encode(),
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    ):
                        if validate_transaction(customer_name, credit_card_number, int(item_price)):
                            update_creditinfo(customer_name, int(item_price), credit_card_number) # Update credit info with the price
                            response = "1"  # Success
                        else:
                            response = "0"  # Unauthorized
                    else:
                        response = "0"  # Unauthorized
                    conn.sendall(response.encode())
                else:
                    print("Received malformed data:", data)
        except Exception as e:
            print("Error occurred in bank:", e)
            traceback.print_exc()  # Print traceback for detailed error information
        finally:
            server_socket.close()


if __name__ == "__main__":
    main()
