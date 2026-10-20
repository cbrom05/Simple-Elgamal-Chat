# Server.py; simple server that manages connections utilizing an encryption format
#
# This program runs a server that manages several UDP packet transmission. It is a very finicky chat, 
# as this is merely a demo that does not handle every possible edge case, nor does it handle 
# message overload nuances. 
#
# The server listens by utilizing threading. In order to connect to this server, you must
# connect using a specific ping phrase that indicates a connection. A handshake will be carried out
# and the primes and generators will be exchanged. This is the primary purpose of the server, to 
# exchange all main public keys. Server adds successful connections to a list (and their half mask), 
# and removes them once they exit (only conventionally).
#
# If a person wants to send a message to a client, they will send a ping to this server to get 
# the recipients half-mask. The server checks stored half masks with connections. It will then
# send it to the sender. Then, this will simply just forward messages by parsing through the list of 
# connections that are stored to find the recipients exact address to send over UDP. This does
# not handle any form of encryption.
#
# This handles invalid connection errors. This is a very finnicky set-up, as it will not 
# be able to handle multiple messages at the same time, nor can it handle messages interrupting 
# the handshakes.
#
# Project Demo
# @author Caden Bromley, Chris Perez
# @email bromlecl205@potsdam.edu, perezcm205@potsdam.edu
# @due 04 December 2025
# @course CIS 475


# Socket and elgamal namespaces
from socket import *
from Elgamal import *
# Threading for listening, ast for tuple messages
import threading 
import ast

# Creates a UDP socket binded to port 12000 using this local machines IP address
serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind(('', 12000))

# A list where every connection is stored
connections = []
listastext = ""

# User input to provide prime bit length. Recommended 1024 for maximum security
bitlength = input("Server prime bit length (recc. 1024): ")
# Gets respective prime and generators
p, g = getPandG(int(bitlength))


# listener; where all of the server processes occur
#
# Listener is operated via thread. Messages are first received here.
#
# Cases handled: 
# - first connection (client sends "poo" and handshake is made. P, G, and half mask exchanged
#   client is then appended to the client)
# - exiting (client sends "exit", removed from client)
# - halfmask distribution to senders for message sending
# - message sending (messages are sent in format (IP/PORT, encrypted message, encrypted AES), then rerouted)
# - errors (if a client tries to send to the wrong person)
#
# Again, finicky
def listener():
    while True:
        global listastext
        # Typical message receive and decoding.
        msg, addr = serverSocket.recvfrom(65535)
        msg = msg.decode()
        print("Processing message from: " + addr[0])

        # Handshake intialized
        if msg == "cnct":
            print("Processing handshake from: " + addr[0])
            serverSocket.sendto("ping".encode(), addr)
            # Sending p, g
            serverSocket.sendto(str(p).encode(), addr)
            serverSocket.sendto(str(g).encode(), addr)
            # Receiving half mask and adding to the list in format ((IP, PORT), HALF MASK)
            half, _ = serverSocket.recvfrom(65535)
            connections.append((addr, int(half.decode())))
            print(addr[0] + " has entered the server.\n")

            if len(connections) > 1:
                listastext = listastext + ", " + addr[0]
            else:
                listastext = addr[0]
        
        # Exiting server
        elif msg == "exit":
            print("Processing server exit from: " + addr[0])
            # Reading list of connections to match the IPs, then remove
            for i in range(0, len(connections)):
                if addr[0] == connections[i][0][0]:
                    print(addr[0] + " has left the server. \n")
                    connections.remove(connections[i])
                    
                    # Re-adjusting the total list of users
                    if len(connections) > 0:
                        listastext = connections[0][0][0]
                        if len(connections) > 1:
                            for i in range(1, len(connections)):
                                listastext = listastext + ", " + connections[i][0][0]
                    break

        # Client wants list of users.
        elif msg == "list":
            print("Processing server list request from: " + addr[0] + "\n")
            msg = str(("list", listastext))
            serverSocket.sendto(msg.encode(), addr)
            
            # Fence post problem

        else:
            # For tuple messages
            try:
                msg = ast.literal_eval(msg)


                # Half mask exchange
                if msg[0] == "get half":
                    print("Processing half mask distribution of connection " + msg[1] +  " from: " + addr[0] + "\n")
                    userfound = False
                    # Loop through list of connections to match IP up
                    for i in range(0, len(connections)):
                        if msg[1] == connections[i][0][0]:
                            userfound = True
                            # Send half mask
                            newmsg = str(("half", connections[i][1]))
                            serverSocket.sendto(newmsg.encode(), addr)
                            print("Half mask distribution completed.\n")
                            break
                    # Encounter error, send it as a tuple back to client
                    if userfound == False:
                        print(addr[0] + " has encountered a user not found error.\n")
                        newmsg = str(("error", "User not in the server."))
                        serverSocket.sendto(newmsg.encode(), addr)
                # Real message case
                else:
                    # Parsing all components
                    print("Processing message send request from: " + addr[0] + " to: " + msg[0])
                    theip = msg[0]
                    themessage = msg[1]
                    theAES = msg[2]

                    # Verifying connection for half mask distribution
                    userfound = False
                    for i in range(0, len(connections)):
                        if addr[0] == connections[i][0][0]:
                            theconnection = connections[i]
                            break

                    # Finding requested recipient
                    for i in range(0, len(connections)):
                        if theip == connections[i][0][0]:
                            # Sent as: (IP/PORT, AES, msg)
                            userfound = True
                            newmsg = (theconnection, themessage, theAES)
                            serverSocket.sendto(str(newmsg).encode(), connections[i][0])
                            print(addr[0] + " -> " + connections[i][0][0] + "\n")
                            break
                    # User found error
                    if userfound == False:
                            print(addr[0] + " has encountered a user not found error.\n")
                            newmsg = str(("error", "User not in the chat."))
                            serverSocket.sendto(newmsg.encode(), addr)
            except:
                print("Encountered a message error.\n")


# Threading to run the listener
thread = threading.Thread(target = listener, daemon = True)
thread.start()

# To terminate and keep things running
terminate = ""
while terminate.lower() != "y":
    terminate = input("Terminate server by sending y: \n")

sys.exit(0)