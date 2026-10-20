# Client.py; simple client that joins a server to send messages to others, using encryption
#
# This is a very simple test client. It is finicky with synchronization, as the heavy usage of threading
# and usage of UDP makes things unsecure and require many edge cases for this usage.
#
# This program will connect to a server and ensure that a connection can be made via handshake. Client
# receives the prime and generator from the server for elgamal. From there, a half mask is generated
# and shared with the server for message usage. We generate an AES key based on user input.
#
# The client runs a thread and a message loop. The message loop can take in two commands: exit (to leave)
# and list (to get a list of the server members). Otherwise, it follows a format to send messages. The client will receive the recipients
# half mask from the server and encrypt the AES key with it using elgamal. Messages encrypted in AES. Messages are then sent in 
# format (IP, MSG, AES).
#
# All messages are received using a finicky threading set-up. It works for the demo, but can be problematic if receiving multiple
# messages at once; it is not able to handle extreme overload.
#
# Project Demo
# @author Caden Bromley, Chris Perez
# @email bromlecl205@potsdam.edu, perezcm205@potsdam.edu
# @due 04 December 2025
# @course CIS 475

# Socket and elgamal encryption
import socket
import Elgamal
# Random values and string tuple reconstruction
import secrets
import ast 
# Termination, threading, line buffer reading, and terminal (linux) commands
import sys
import threading
import readline
import pyreadline3
import os
# AES libraries from pycryptodome
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# UDP socket created. IP and port taken in
clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Handshake
print("Waking up...")
ip = input("IP Address of the server: ")
port = input("Port of the server: ")
print("Connecting to " + ip + " at port " + port + ". ")
destAddress = (ip, int(port))
clientSock.sendto("cnct".encode(), destAddress)
clientSock.settimeout(1)
try:
    response, _ = clientSock.recvfrom(65535)
    print("Nice, they're awake")
except socket.timeout:
    print("Timed out, it failed.")
    clientSock.close()
    sys.exit(1)
clientSock.settimeout(None)

# Get prime and generator
print()
p, _ = clientSock.recvfrom(65535)
p = int(p.decode())
print("Received P: " + str(p))
g, _ = clientSock.recvfrom(65535)
g = int(g.decode())
print("Received G: " + str(g))

print("Generating our own key.")
k = secrets.randbelow(p - 1)
print("K: " + str(k))
print("Generating our halfmask.")
half = pow(g, k, p)
print("Half mask: " + str(half))
print()
clientSock.sendto(str(half).encode(), destAddress)

bit_length = 0
while bit_length < 128:
    bit_length = int(input("AES bit length (recc. 256, min. 128): "))
    if bit_length < 128:
        print("Minimum length is 128 bits")
key = get_random_bytes(int(bit_length) // 8)
print("AES key generated: " + str(key))
print()

os.system('clear')

# Global variable initialization
sendkey = None
error = False
waiting = True

# Setting threading lock to handle message printing with synchronization
printlock = threading.Lock()

def prompthandling():
    # Global variables to be adjusted for synchronization
    global waiting
    global sendkey
    global error

    # While true to always run the thread
    while True:
        massage, _ = clientSock.recvfrom(65535)
        massage = massage.decode()
        # All messages that the client receives are tuples
        massage = ast.literal_eval(massage)
        # These are specific cases that the server will send with a message.
        if massage[0] != "half" and massage[0] != "error" and massage[0] != "list":
            # Getting the sender IP
            fromip = massage[0][0][0]

            # Turns bytes to integer, decrypts. turns that into bytes. This is the decrypted
            # AES key
            otherkey = Elgamal.decrypt(int.from_bytes(massage[2], "big"), massage[0][1], k, p)
            otherkey = otherkey.to_bytes((otherkey.bit_length() + 7) // 8, 'big')

            # AES components
            nonce = massage[1][:16]
            tag = massage[1][16:32]
            response = massage[1][32:]

            # AES decryption of the message
            dec = AES.new(otherkey, AES.MODE_EAX, nonce=nonce)
            response = dec.decrypt_and_verify(response, tag)
            response = response.decode()

            # To get the line that was previously typed, just incase
            line = readline.get_line_buffer()
            
            # Artifact from previous implementation for printing
            with printlock:

                # Optimized for linux best. Prints the message received, reprints prompt with buffer
                print('\r' + ' ' * (len(line) + 15) + '\r', end='')
                print("\r[" + fromip + "]: " + response, flush = True)
                print("\rSend to le server: " + line, end = "")
                readline.redisplay()

        # Error case
        elif massage[0] == "error":
            # Optimized for linux best. Prints message received, reprints prompt with buffer
            line = readline.get_line_buffer()
            print('\r' + ' ' * (len(line) + 15) + '\r', end='')
            print("\r[SERVER]: " + massage[1], flush=True)
            print("\rSend to le server: " + line, end="")
            readline.redisplay()
            
            # Error set to true and waiting to false for synchronization. Read below for usage
            error = True
            waiting = False
        
        # Receiving list of users from server
        elif massage[0] == "list":
            line = readline.get_line_buffer()
            print('\r' + ' ' * (len(line) + 15) + '\r', end='')
            print("\r[SERVER]: " + massage[1], flush=True)
            print("\rSend to le server: " + line, end="")
            waiting = False
        else:
            # Case where we handle receiving half masks.
            # Encrypts client AES key using the received half mask. 

            # Turns to integer, encrypts, turns back to bytes
            newkey = Elgamal.encrypt(int.from_bytes(key, 'big'), int(massage[1]), k, p)
            sendkey = newkey.to_bytes((newkey.bit_length() + 7) // 8, 'big')
            waiting = False


# Threading start
thread = threading.Thread(target = prompthandling, daemon = True)
thread.start()

print("\nWelcome to the server chatroom.")
print("To send messages use the following format: (IP) MESSAGE")
print("To receive a list of users in the server, type 'list'.")
print("To safely exit the server, type 'exit'.\n")

# Loop for sending messages
while True:

    # Message prompt
   # msg = input("Send to le server: ")
    msg = input("Send to le server: ")

    # If the message is exit, we send that to server and end.
    if "exit" == msg.lower():
        clientSock.sendto("exit".encode(), destAddress)
        break

    # To get the list of users in the server
    if "list" == msg.lower():
        clientSock.sendto("list".encode(), destAddress)
        while waiting:
            continue
        continue


    # Figure out if format is correct
    peran1 = False
    peran2 = False
    counter = 0
    for char in msg:
        counter = counter + 1
        if char == '(' and peran1 == False :
            peran1 = True 
        
        if char == ')' and peran1 == True and counter != 2:
            peran2 = True

    # If it is not correct, we end
    if not peran1 or not peran2:
        print("\033[F\033[K", end="")
        print("\rMessage format is: (IP) MESSAGE", flush = True)
        continue

    # Direct parcing to split the IP and message up
    ipstart = msg.find("(") + 1
    ipend = msg.find(")")
    theip = msg[ipstart:ipend]
    themsg = msg[ipend+1:]

    # Set waiting to true to indicate we are waiting for synchronization. Sendkey to none to reset
    # and error to false to indicate no error
    waiting = True
    sendkey = None
    error = False
    
    # Get half mask
    gethalf = str(("get half", theip))
    clientSock.sendto(gethalf.encode(), destAddress)

    # Lock the prompt here to wait briefly
    while waiting:
        continue
    # To synchronize
    waiting = False

    # If recipient isn't in the message, we end here
    if error:
        error = False
        continue
    
    # Printing message to indicate what we sent
    print("\033[F\033[K", end="")
    print("\r[You -> " + theip + " ]: " + themsg, flush = True)

    # Encrypting our message using AES. Compiling said message
    encrypt = AES.new(key, AES.MODE_EAX)
    enctext, tag = encrypt.encrypt_and_digest(themsg.encode())
    nonce = encrypt.nonce
    message = nonce + tag + enctext

    # Send to server
    fullmessage = (theip, message, sendkey)
    fullmessage = str(fullmessage)
    clientSock.sendto(fullmessage.encode(), destAddress)


# end after loop exits
clientSock.close()