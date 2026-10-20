#
# * Client.py; a client that chats with a server over UDP
#
# * This program opens a connection over UDP with a designated server, provided
# * by the user via input. The user also provides prime length, and provides AES byte length.
# * All messages are encrypted using this AES key. The AES key is first encrypted using
# * Elgamal, and then it is sent over UDP normally thereafter.
#
#
# * Project Prep #2
# * @author Caden Bromley, Chris Perez
# * @email bromlecl205@potsdam.edu, perezcm205@potsdam.edu
# * @due 22 November 2025
# * @course CIS 475
#

import socket
# Needed for encrypt/decrypt AES key
import Elgamel
# for secret number generation
import secrets
import sys
# threading used to read oncoming messages
import threading
# for handling prompts
import readline
# handling cleaning on unix
import os
# used for AES keys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# UDP socket created. IP and port taken in
clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print("Eyes have been opened.")
destIP = input("IP Address to link up to: ")
destPort = input("Port to link up to: ")

# This is used to make sure the server is a real server that can respond
print("Testing the waters...")
destAddress = (destIP, int(destPort))
clientSock.sendto("ping".encode(), destAddress)
clientSock.settimeout(1)
try:
    response, _ = clientSock.recvfrom(65535)
    print("Nice, they're awake")
except socket.timeout:
    print("Timed out, it failed.")
    clientSock.close()
    sys.exit(1)

# Resets timeout
clientSock.settimeout(None)
print()
os.system('clear')


primelength = input("Input a prime length: ")

# Gets primes and generator and key
p, g = Elgamel.getPandG(int(primelength))
print("P: " + str(p))
print("G: " + str(g))
print("Generating our own key.")
k = secrets.randbelow(p - 1)
print("Secret key: " + str(k))
print("Generating our halfmask.")
half = pow(g, k, p)
print("Generated halfmask: " + str(half))
print()

# Share keys with server
print("Sending P to " + destAddress[0] + ".")
clientSock.sendto(str(p).encode(), destAddress)
print("Sending G to " + destAddress[0] + ".")
clientSock.sendto(str(g).encode(), destAddress)
print("Generating our halfmask to " + destAddress[0] + ".")
clientSock.sendto(str(half).encode(), destAddress)
print("Receiving halfmask from " + destAddress[0] + ".")
otherhalf, _ = clientSock.recvfrom(65535)
otherhalf = int(otherhalf)
print("Received halfmask: " + str(otherhalf))
print()
os.system('clear')

# Getting AES byte lenth and generating
byte_length = input("AES bit length (recc. 256): ")
key = get_random_bytes(int(byte_length) // 8)
print("Generated AES key: " + str(key))
# Turns the bytes to an integer and then encrypts it
newkey = Elgamel.encrypt(int.from_bytes(key, 'big'), otherhalf, k, p)
print("Sending key to " + destAddress[0] + ".")
# Turns the encrypted integer back into bytes and sends it
clientSock.sendto(newkey.to_bytes((newkey.bit_length() + 7) // 8, 'big'), destAddress)
print()

# Receives servers encrypted AES
otherkeyasbytes, _ = clientSock.recvfrom(65535)
# Turns it back into an integer
otherkey = int.from_bytes(otherkeyasbytes, 'big')
print("Received key from " + destAddress[0] + ".")
print("Received AES key (encrypted): " + str(otherkeyasbytes))

# Decrypts the integer
otherkey = Elgamel.decrypt(otherkey, otherhalf, k, p)
# Turns the integer back into bytes
otherkey = otherkey.to_bytes((otherkey.bit_length() + 7) // 8, 'big')
print("Received AES key (decrypted): " + str(otherkey))

os.system('clear')

# Locking is an artifact from previous implementation, but still helps
printlock = threading.Lock()


#
# * prompthandling(); handles incoming information and the subsequent prompt issues
#
# * Whenever the server sends a message, this will parse the information that is given. It
# * will decrypt the message using the given AES key, and then it will display the message. This takes into
# * account the prompt being re-printed so it isn't messy, and the possibility of a user already typing in input.
def prompthandling():
    while True:
        # The message received
        massage, _ = clientSock.recvfrom(65535)
        # gets the AES nonce from the first 16 bytes
        nonce = massage[:16]
        # Next 16 bytes for AES tag
        tag = massage[16:32]
        # Actual message is the remaining bytes
        response = massage[32:]

        # Decryption
        dec = AES.new(otherkey, AES.MODE_EAX, nonce=nonce)
        response = dec.decrypt_and_verify(response, tag)
        response = response.decode()

        # Getting what the user has already typed in event we get a message
        line = readline.get_line_buffer()

        # using the lock
        with printlock:

            # Erase the prompt
            print('\r' + ' ' * (len(line) + 15) + '\r', end='')
            # Show who sent the message and the message
            print("\r[" + str(destAddress[0]) + "]: " + response, flush = True)
            # Reprints the prompt with what you already typed
            print("\rSend to le server: " + line, end = "")
            readline.redisplay()

# Starts threading
thread = threading.Thread(target = prompthandling, daemon = True)
thread.start()


# perpetual loop
while True:

    # Prompt
    msg = input("Send to le server: ")
    if "exit" == msg.lower():
        break
    # Deletes prompt
    print("\033[F\033[K", end="")
    # Sends what you sent
    print("\r[You]: " + msg, flush = True)
    # Encrypts the message
    encrypt = AES.new(key, AES.MODE_EAX)
    enctext, tag = encrypt.encrypt_and_digest(msg.encode())
    nonce = encrypt.nonce

    # Puts all the bytes together and sends
    message = nonce + tag + enctext
    clientSock.sendto(message, destAddress)


# end after loop exits
clientSock.close()