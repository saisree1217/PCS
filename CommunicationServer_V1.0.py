# CMSC 626 PRINCIPLES OF COMPUTER SECURITY - Project

# Submitted by Group 6

# Hima Poojitha Sai Sree Myla	    -	QN08170
# Parinitha Reddy Gaddam		    -	KT16974
# Pragadiswar Nanda Muralidharan	-	PO21974
# Vishnu Vardhan Samba		        -	IK67010

#About CommunicationServer: This node mainly acts as communication channel between all the nodes connected. It forwards the commands executing by
#current nodes to all the other active nodes and queues the commands for the nodes that are not active at the moment.

#Importing the required python modules
import socket
import threading
import time

from Crypto.Cipher import AES #Advanced Encryption Standard
from Crypto.Util.Padding import pad, unpad

#Creating and binding a Socket
PORT = 5050 #Assigning port
NODE = socket.gethostname() #Dynamically getting the local machine IPv4 address
print(f"Communiation server machine name is {NODE}")
node_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #Creating a socket
ADDRESS = (NODE, PORT) #Defining the address tuple which is needed to bind the socket to a spacific port
node_socket.bind(ADDRESS) #Binding the socket

#Declaring constants
MESSAGE_SIZE = 64 
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "Disconnect"
FEEDBACK = "Message received"

#Declaring variables
nodes_connected = [] #This list holds the connection details of the all the nodes active in the network
#This dictionary holds the address of that respective user
users_connections = {
    "Vishnu" : "",
    "Pragdish" : "",
    "Saisree" : "",
    "Parinitha" : ""
}
#Holds the commands implemented by active users untill user is active
vishnu_queue = []
parinitha_queue = []
pragdish_queue = []
saisree_queue = []
#The key which is present with all nodes and plugged into the code
actual_key = b'~$?R\x0e\x14\xab\xbd\xc3\xdeL\xa1N(\x83\xd5T\xdb1\x83\xd9ANy\xc4\xe5\x19\xb6s\x82\xc1\x8e'

#Defining functions

#This function is used for encrypting plain text. It takes plain text as argument and retunr an initialization vector(which is used a nonce 
#during decryption) and the encrypted text
def encryptMessage(plain_text):
    plain_text_bytes = plain_text.encode() #converting plain text to bytes which is the required data type for padding
    encryption = AES.new(actual_key, AES.MODE_CBC) #We are using AES encryption with Chain Block Cipher
    encrypted_text = encryption.encrypt(pad(plain_text_bytes, AES.block_size))
    return encryption.iv,encrypted_text

#This function is used for decrypting encrypted message. It takes nonce and encrypted text as arguments and returns the plain text.
def decryptMessage(nonce,decryption_data):
    #Decrypting thte data
    decryption = AES.new(actual_key, AES.MODE_CBC, iv=nonce)
    decrypted_text = unpad(decryption.decrypt(decryption_data), AES.block_size)
    return str(decrypted_text)

#This function sends the command implemented by one active user to all other active users and queue the commands for the users who are not active.
#Takes the command implemented by the user and the address of the user sa arguments
def broadcast(message,current_connection):
    for est_conn in users_connections:
        if users_connections[est_conn] != "":
            pass
        else:
            if est_conn == "Vishnu":
                vishnu_queue.append(message)
            if est_conn == "Parinitha":
                parinitha_queue.append(message)
            if est_conn == "Pragdish":
                pragdish_queue.append(message)
            if est_conn == "Saisree":
                saisree_queue.append(message)
    for connection in nodes_connected:
        if connection == current_connection:
            pass
        else:      
            message_iv, message_enc = encryptMessage(message)
            connection.send(message_iv)
            time.sleep(0.1)
            connection.send(message_enc)


#This function establishes the connection with the active node trying to communicate, then forwards the command implemented by the connected node 
#to other nodes by passing to broadcast function. Takes the connection details of the connected node as argument.
def node_handler(conn, addr):
    print(f"{addr} connected.")
    node_connected = True

    while node_connected:
        #getting the actual message from the node
        node_message_iv = conn.recv(16)
        node_message_enc = conn.recv(2048)
        node_message = decryptMessage(node_message_iv,node_message_enc)
        node_message_len = len(node_message)
        node_message = node_message[2:node_message_len-1]
        #If the node wants to disconnect, this message allows it to disconnect by exiting the while
        #loop and executing the close connection command
        if node_message == DISCONNECT_MESSAGE:
            node_connected = False
            nodes_connected.remove(conn)
            print(f"{addr} : Connection disconnected!")
            disconnect_iv, disconnect_msg = encryptMessage("Connection disconnected!")
            conn.send(disconnect_iv)
            conn.send(disconnect_msg)
        # If the message received is actual command then it is passed on the broadcast function
        else:
            print(f"{addr} : {node_message}")  
            broadcast(node_message,conn)   

    conn.close() 
       

#This functions starts listening and initializes the nodes concurently. Once established it checks for commands in queue for the current node and
#pushes to commands to the node for implementation.
def initialize_socket():
    node_socket.listen() #Socket is listening

    while True:
        conn, addr = node_socket.accept() #establishing connection
        user_iv = conn.recv(2048)
        user_enc = conn.recv(2048)
        user = decryptMessage(user_iv,user_enc)
        user = user[2:len(user)-1]
        
        #Storing the nodes address in the data list
        if conn in nodes_connected:
            clear_iv, clear_enc = encryptMessage("CLEAR")
            conn.send(clear_iv)
            time.sleep(0.1)
            conn.send(clear_enc)
        else:
            nodes_connected.append(conn)
            users_connections[user] = conn
            if user == "Vishnu" and len(vishnu_queue) != 0:
                for command in vishnu_queue:
                    message_iv, message_enc = encryptMessage(command)
                    conn.send(message_iv)
                    time.sleep(0.1)
                    conn.send(message_enc)
                clear_iv, clear_enc = encryptMessage("CLEAR")
                conn.send(clear_iv)
                time.sleep(0.1)
                conn.send(clear_enc)
            if user == "Parinitha" and len(parinitha_queue) != 0:
                for command in parinitha_queue:
                    message_iv, message_enc = encryptMessage(command)
                    conn.send(message_iv)
                    time.sleep(0.1)
                    conn.send(message_enc)
                clear_iv, clear_enc = encryptMessage("CLEAR")
                conn.send(clear_iv)
                time.sleep(0.1)
                conn.send(clear_enc)
            if user == "Pragdish" and len(pragdish_queue) != 0:
                for command in pragdish_queue:
                    message_iv, message_enc = encryptMessage(command)
                    conn.send(message_iv)
                    time.sleep(0.1)
                    conn.send(message_enc)
                clear_iv, clear_enc = encryptMessage("CLEAR")
                conn.send(clear_iv)
                time.sleep(0.1)
                conn.send(clear_enc)   
            if user == "Saisree" and len(saisree_queue) != 0:
                for command in saisree_queue:
                    message_iv, message_enc = encryptMessage(command)
                    conn.send(message_iv)
                    time.sleep(0.1)
                    conn.send(message_enc)
            clear_iv, clear_enc = encryptMessage("CLEAR")
            conn.send(clear_iv)
            time.sleep(0.1)
            conn.send(clear_enc)   

            
        #Threading node_handere to handle concurrent nodes
        thread = threading.Thread(target=node_handler,args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    print("NODE is listening......")
    initialize_socket()