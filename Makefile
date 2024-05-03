.PHONY: all clean

all: bank server client

clean:
	@echo "Cleaning up..."
	rm -rf bank/__pycache__ server/__pycache__ client/__pycache__

bank:
	@echo "Compiling bank code..."
	cd bank && python3 bank.py

server:
	@echo "Compiling server code..."
	cd server && python3 server.py

client:
	@echo "Compiling client code..."
	cd client && python3 client.py