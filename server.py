import socket
import threading
import time  # Add this line

def broadcast_server_ip(broadcast_port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        server_ip = socket.gethostbyname(socket.gethostname())
        broadcast_message = f"SERVER_IP:{server_ip}".encode()
        server_socket.sendto(broadcast_message, ('<broadcast>', broadcast_port))
        # print(f"Broadcasted server IP: {server_ip}")
        time.sleep(10)  # Broadcast every 10 seconds

def main():
    item_data = ""
    with open("items.txt", "r") as file:
        item_data = file.read().strip()  # Remove any trailing newline characters

    # Define the port number
    server_port = 12346  # Default port number

    # Create a socket and bind it to the server IP and port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', server_port))
    server_socket.listen(1)
    print("Server is listening...")

    # Start a separate thread to broadcast the server IP
    broadcast_port = 9999  # Choose a suitable broadcast port
    broadcast_thread = threading.Thread(target=broadcast_server_ip, args=(broadcast_port,))
    broadcast_thread.start()

    while True:
        conn, addr = server_socket.accept()
        with conn:
            print('Connected by', addr)
            conn.sendall(item_data.encode())

if __name__ == "__main__":
    main()
