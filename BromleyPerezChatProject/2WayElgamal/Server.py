#
# * Server.py; a server that chats with a client over UDP
#
# * This program opens a connection over UDP and binds to the device it is ran from.
# * The user provides an byte length for AES key generation, and all messages are encrypted using
# * this AES key. The AES key is first encrypted using Elgamal, and then it is sent over UDP normally
# * thereafter.
#
#
# * Project Prep #2
# * @author Caden Bromley, Chris Perez
# * @email bromlecl205@potsdam.edu, perezcm205@potsdam.edu
# * @due 22 November 2025
# * @course CIS 475
#

# imports socket as a namespace
from socket import *
# for encrypt and decrypt AES
import Elgamel
import secrets
import threading
import readline
import os
# AES libraries
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


#UDP packet made. binds to localhost
serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind(('', 12000))
print("Opening our eyes.")
ping, address = serverSocket.recvfrom(65535)
print("Received a message from the client. Let's let them know we're alive.")
serverSocket.sendto("pong".encode(), address)
print("We are good.")
os.system('clear')
print()

# Takes in elgamal information
p, _ = serverSocket.recvfrom(65535)
print("Received P from " + address[0] + ".")
g, _ = serverSocket.recvfrom(65535)
print("Received G from " + address[0] + ".")
otherhalf, address = serverSocket.recvfrom(65535)
print("Received halfmask from " + address[0] + ".")
p = int(p.decode())
g = int(g.decode())
otherhalf = int(otherhalf.decode())
print("G: " + str(g))
print("P: " + str(p))
print("Received half mask: " + str(otherhalf))
print()

# Generates our elgamal information
print("Generating our own key.")
k = secrets.randbelow(p-1)
print("Generating our own halfmask.")
half = pow(g, k, p)
print("Generated halfmask: " + str(half))
print("Sending our halfmask to " + address[0] + ".")
serverSocket.sendto(str(half).encode(), address)
os.system('clear')
print()

# Receives key. Converst the key into an integer since it is sent as bytes
otherkeyasbytes, _ = serverSocket.recvfrom(65535)
otherkey = int.from_bytes(otherkeyasbytes, 'big')
print("Received key from " + address[0] + ".")
print("Received key (encrypted): " + str(otherkeyasbytes))

# Decrypts the integer and then turns it back into bytes. Used for decryption
key = Elgamel.decrypt(otherkey, otherhalf, k, p)
key = key.to_bytes((key.bit_length() + 7) // 8, 'big')
print("Received key (decrypted): " + str(key))
print()

# Takes user input to generate own AES key
print("Time to generate our own key.")
byte_length = input("Bit length for AES (recc. 256): ")

# Generates key. Turns it into integer and encrypts it, then turns it back into bytes and sends
newkey = get_random_bytes(int(byte_length) // 8)
print("AES key generated: " + str(newkey))
newkey2 = Elgamel.encrypt(int.from_bytes(newkey, 'big'), otherhalf, k, p)
print("Sending the key to " + address[0] + ".")
serverSocket.sendto(newkey2.to_bytes((newkey2.bit_length() + 7) // 8, 'big'), address)
print()

os.system('clear')

printlock = threading.Lock()


#
# * prompthandling(); handles incoming information and the subsequent prompt issues
#
# * Whenever the client sends a message, this will parse the information that is given. It
# * will decrypt the message using the given AES key, and then it will display the message. This takes into
# * account the prompt being re-printed so it isn't messy, and the possibility of a user already typing in input.
def prompthandling():
    while True:
        # The message received
        massage, _ = serverSocket.recvfrom(65535)
        # gets the AES nonce from the first 16 bytes
        nonce = massage[:16]
        # Next 16 bytes for AES tag
        tag = massage[16:32]
        # Actual message is the remaining bytes
        response = massage[32:]

        # Decryption
        dec = AES.new(key, AES.MODE_EAX, nonce=nonce)
        response = dec.decrypt_and_verify(response, tag)
        response = response.decode()

        # Gets what user already typed
        line = readline.get_line_buffer()
        with printlock:

            # Deletes prompt
            print('\r' + ' ' * (len(line) + 15) + '\r', end='')
            # Prints message and who it was from
            print("\r[" + str(address[0]) + "]: " + response, flush = True)
            # Reprints prompt with user type
            print("\rSend to le client: " + line, end = "")
            readline.redisplay()


thread = threading.Thread(target = prompthandling, daemon = True)
thread.start()

#perpetual loop
while True:
    msg = input("Send to le client: ")
    # Delete prompt
    print("\033[F\033[K", end="")
    # Show what you sent
    print("\r[You]: " + msg, flush = True)
    # Encrypt
    encrypt = AES.new(newkey, AES.MODE_EAX)
    enctext, tag = encrypt.encrypt_and_digest(msg.encode())
    nonce = encrypt.nonce

    # Send it all as combined bytes
    message = nonce + tag + enctext
    serverSocket.sendto(message, address)