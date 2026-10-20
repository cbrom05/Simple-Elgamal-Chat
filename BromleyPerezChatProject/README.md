# README 
## CRYPTOGRAPHY PROJECT
**Authors:** Caden Bromley, Chris Perez  
**EmailS:** bromlecl205@potsdam.edu, perezcm205@potsdam.edu  
**Course:** CIS 475  
**Date:** 04 December 2025  

### Description
This project implements a four client encrypted chat system using a central server. Whoever runs the server will have it bound to their
localhost and port 12000. The server will use the provided ElGamal code to generate primes and generators upon user input. Clients can
connect to the server, grab the p/g from server using a handshake, and then generates their secret k exponent key, and halfmask, exchanging the 
latter with the server. The server updates its list of connected clients using their IP, port, and half masks. Client generates an AES key
using the number of bits provided by user. Server will reroute all messages to each client. Commands exist on the UI to get the list of users ('list') and
exit the chat ('exit', safest way to leave). Clients will encrypt messages to be sent using their AES key, encrypt their AES key using ElGamal and the half mask of
the recipient, all with the format (Recipient IP/HalfMask, Encrypted Message, Encrypted AES Key). The server will interpret this. If the recipient is not in the 
connection, then it will give an error to the client. If they are, it will send a new message in format (Sender IP, Encrypted Message, Encrypted AES Key) to 
the recipient client. Recipient client will decrypt the message by first decrypting the AES, and then decrypting the message. All listening to messages
and the majority of the message processing is done via tuples and threading.

All  messages between clients are fully end-to-end encrypted. There is no group chat feature.

### Deliveriables
- Client.py -> Clients that are connect to server to communicate with one another.
- Server.py -> Server that generates public prime and generator, and coordinates all communication.
- Elgamal.py -> Creates primes, generator, and carries out encrypt/decrypt.

### Dependencies
(Elgamal.py) random - generate random numbers used during prime testing and prime generation
(Client.py & Server.py) socket - create the UDP socket used for sending and receiving messages between the client and server
(Client.py) readline - manage user input and allow line editing while messages are received in the background
(Client.py & Server.py) Elgamel - ElGamal encryption and decryption needed for secure key exchange between clients
(Client.py) secrets - generate secure random values for key creation
(Client.py) sys - access system level functions like exiting the program when needed
(Client.py & Server.py) threading - run a background listener thread while the user types messages
(Client.py & Server.py) ast - convert received string representations of Python objects back into actual objects
(Client.py) os - execute system commands, like clearing the terminal screen
(Client.py) AES from Crypto.Cipher - AES encryption and decryption of messages
(Client.py) get_random_bytes from Crypto.Random - generate random AES keys

### Instructions
1. Run Server (python Server.py)
    Choose server prime bit length
    (can terminate the server by pressing y)
    Watch server coordination, as it is printed

2. Run Client (python Client.py)
    Enter server IP
    Enter Port number
    Enter the size of AES key

3. Clients can now talk to each other
    in order to message another client we use the format-> ("The IP of the recipient") "The message"
    The command "list" can give you a list of everyone in the server.

4. Exit the program
    type exit to exit the program

### Demo Steps
1. First we will run the server and explain the server set-up stage:
    - Primes that are generated from user input (and how: Elgamal.py)
    - Generator that is also generated randomly (and how: Elgamal.py)

2. Then we will connect just one client to the server to view handshake:
    - Provide server IP
    - Provide server port
    - Show code that shows the initial test handshake to ensure connections are valid
    - Show the P and G exchange
    - Halfmask generation and exponent generation, and the exchange of the former to the server
    - Show how the server stores connections and turns them into a list

3. We will explain some of the basic commands and error testing:
    - Show prompt handling
    - '() message' -> Show how error is generated, no IP provided
    - 'message' -> Show how error is generated, invalid format
    - '(invalid IP) message' -> show how error is generated, invalid IP
    - (Real IP) message -> Show the process of sending messages (encryption, decryption, and server coordination)
    - Show the threading process and synchronization process

4. Then we will actually demonstrate multiple connections:
    - 4-way elgamal, showing all messages are handled and showing how it is in line with our code

5. We will exit and shut it all down
    - 'exit' on each client, showing the server outputs to see the exit handling
    - 'y' on server to shut down