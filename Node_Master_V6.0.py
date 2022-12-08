#6. Implementing mutex

#MESSAGE LENGTH IS 2048
#REMOVED FEEDBACK

#Master node gets request from multiple nodes and implements the requests. In this particular version we are
#just getting a string from node, printing it, sending it to the rest of the user nodes and sending a feedback
#to the node. Concept of threading is also implemented.

import socket
import threading
import time

from Crypto.Cipher import AES #Advanced Encryption Standard
from Crypto.Util.Padding import pad, unpad

#Assigning port
PORT = 5050

#Dynamically getting the local machine IPv4 address
NODE = socket.gethostbyname(socket.gethostname())

#Creating a socket
node_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Defining the address tuple which is needed to bind the socket to a spacific port
ADDRESS = (NODE, PORT) 

#Binding the socket
node_socket.bind(ADDRESS)

MESSAGE_SIZE = 64 #This containes the size of the actual message
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "Connection disconnect"
FEEDBACK = "Message received"

#This data structure holds the connection details of the all the nodes in the network
nodes_connected = []

users_connections = {
    "Vishnu" : "",
    "Pragdish" : "",
    "Saisree" : "",
    "Parinitha" : ""
}

vishnu_queue = []
parinitha_queue = []
pragdish_queue = []
saisree_queue = []

actual_key = b'~$?R\x0e\x14\xab\xbd\xc3\xdeL\xa1N(\x83\xd5T\xdb1\x83\xd9ANy\xc4\xe5\x19\xb6s\x82\xc1\x8e'

def encryptMessage(plain_text):
    #Encrypting the data
    plain_text_bytes = plain_text.encode() #converting plain text to bytes which is the required data type for padding
    encryption = AES.new(actual_key, AES.MODE_CBC)
    encrypted_text = encryption.encrypt(pad(plain_text_bytes, AES.block_size))
    return encryption.iv,encrypted_text

def decryptMessage(nonce,decryption_data):
    #Decrypting thte data
    decryption = AES.new(actual_key, AES.MODE_CBC, iv=nonce)
    decrypted_text = unpad(decryption.decrypt(decryption_data), AES.block_size)
    return str(decrypted_text)

#This function is called whenever the the called node request if fullfilled and the request is to be sent
#over other nodes in the client
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
            time.sleep(1)
            connection.send(message_enc)


#This function gets the node request, perform the action and then broadcast it to other node
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
        # the case of client actually sending a message
        else:
            print(f"{addr} : {node_message}")  
            #Sending the client request to backup NODE
            broadcast(node_message,conn)   
            #Sending feedback to the client 
            # f = str(FEEDBACK)
            # feedback_iv, feedback_msg = encryptMessage(f)
            # conn.send(feedback_iv)      
            # conn.send(feedback_msg)

    conn.close() 
       

#This functions opens the listening socket and initializes the nodes concurently
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
            time.sleep(1)
            conn.send(clear_enc)
        else:
            nodes_connected.append(conn)
            users_connections[user] = conn
            if user == "Vishnu" and len(vishnu_queue) != 0:
                for command in vishnu_queue:
                    message_iv, message_enc = encryptMessage(command)
                    conn.send(message_iv)
                    time.sleep(1)
                    conn.send(message_enc)
                clear_iv, clear_enc = encryptMessage("CLEAR")
                conn.send(clear_iv)
                time.sleep(1)
                conn.send(clear_enc)
            if user == "Parinitha" and len(parinitha_queue) != 0:
                for command in parinitha_queue:
                    message_iv, message_enc = encryptMessage(command)
                    conn.send(message_iv)
                    time.sleep(1)
                    conn.send(message_enc)
                clear_iv, clear_enc = encryptMessage("CLEAR")
                conn.send(clear_iv)
                time.sleep(1)
                conn.send(clear_enc)
            if user == "Pragdish" and len(pragdish_queue) != 0:
                for command in pragdish_queue:
                    message_iv, message_enc = encryptMessage(command)
                    conn.send(message_iv)
                    time.sleep(1)
                    conn.send(message_enc)
                clear_iv, clear_enc = encryptMessage("CLEAR")
                conn.send(clear_iv)
                time.sleep(1)
                conn.send(clear_enc)   
            if user == "Saisree" and len(saisree_queue) != 0:
                for command in saisree_queue:
                    message_iv, message_enc = encryptMessage(command)
                    conn.send(message_iv)
                    time.sleep(1)
                    conn.send(message_enc)
            clear_iv, clear_enc = encryptMessage("CLEAR")
            conn.send(clear_iv)
            time.sleep(1)
            conn.send(clear_enc)   

            
        #Threading to handle multiple nodes
        thread = threading.Thread(target=node_handler,args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    print("NODE is listening......")
    initialize_socket()