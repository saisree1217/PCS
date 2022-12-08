#6. Implementing mutex

#pREV version we are integrating encryption and decryption

#MESSAGE LENGTH IS 2048
#REMOVED FEEDBACK

#The node establishes connection with master node and sends two messages. 1 containing a string and
#2 a message to disconnect the connection. We should be able to see the same messages across all other nodes

import os
import shutil
import socket
import threading
import time

from Crypto.Cipher import AES #Advanced Encryption Standard
from Crypto.Util.Padding import pad, unpad

lock = threading.Lock()

#Assigning port
PORT = 5050
MESSAGE_SIZE = 64 #This containes the size of the actual message
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "Connection disconnect"

#Dynamically getting the local machine IPv4 address
#NODE = socket.gethostbyname(socket.gethostname())
NODE = socket.gethostbyname(socket.gethostname())

#Defining the address tuple which is needed to connect the socket to a specific port
ADDRESS = (NODE, PORT) 
print(ADDRESS)

#Creating a socket
node_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)



actual_key = b'~$?R\x0e\x14\xab\xbd\xc3\xdeL\xa1N(\x83\xd5T\xdb1\x83\xd9ANy\xc4\xe5\x19\xb6s\x82\xc1\x8e'

recycle_path = "C:/Users/parin/OneDrive/Documents/PCS_Project/Recycle"
recycle_path = recycle_path.replace('/','\\')

read_permissions_vishnu = []
read_permissions_parinitha = []
read_permissions_saisree = []
read_permissions_pragdish = []

write_permissions_vishnu = []
write_permissions_parinitha = []
write_permissions_saisree = []
write_permissions_pragdish = []

delete_permissions_vishnu = []
delete_permissions_parinitha = []
delete_permissions_saisree = []
delete_permissions_pragdish = []

restore_permissions_vishnu = []
restore_permissions_parinitha = []
restore_permissions_saisree = []
restore_permissions_pragdish = []

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

#This function sends data to the NODE
def send_request(user):
    while True:
        deny_forward = "NO"
        try:
            #Converting the message to be send into bytes stream
            msg = input("Please provide the command: ")
            forward = msg
            commands = msg.split(' -')
            msg = commands[0]
            file_name = commands[1]
            if msg == "WRITE":
                try:
                    content = commands[2]
                    content_iv,content = encryptMessage(content)
                except:
                    pass
            if msg == "CREATE":
                try:
                    vishnu_permissions = commands[2]
                    parinitha_permissions = commands[3]
                    pragdish_permissions = commands[4]
                    saisree_permissions = commands[5]
                except:
                    pass
            
            if msg == "CREATE":                
                create(file_name,file_path,vishnu_permissions,parinitha_permissions,pragdish_permissions,saisree_permissions)

            elif msg == "WRITE":
                if user == "Vishnu":
                    if file_name in write_permissions_vishnu:
                        write(file_name,file_path,content,content_iv)
                    else:
                        print("Write permission denied for this user.")
                        deny_forward = "YES"
                if user == "Parinitha":
                    if file_name in write_permissions_parinitha:
                        write(file_name,file_path,content,content_iv)
                    else:
                        print("Write permission denied for this user.")
                        deny_forward = "YES"
                if user == "Pragdish":
                    if file_name in write_permissions_pragdish:
                        write(file_name,file_path,content,content_iv)
                    else:
                        print("Write permission denied for this user.")
                        deny_forward = "YES"
                if user == "Saisree":
                    if file_name in write_permissions_saisree:
                        write(file_name,file_path,content,content_iv)
                    else:
                        print("Write permission denied for this user.")
                        deny_forward = "YES"

                
            elif msg == "READ":
                if user == "Vishnu":
                    if file_name in read_permissions_vishnu:
                        read(file_name,file_path)
                    else:
                        print("Read permission denied for this user.")
                        deny_forward = "YES"
                if user == "Parinitha":
                    if file_name in read_permissions_parinitha:
                        read(file_name,file_path)
                    else:
                        print("Read permission denied for this user.")
                        deny_forward = "YES"
                if user == "Pragdish":
                    if file_name in read_permissions_pragdish:
                        read(file_name,file_path)
                    else:
                        print("Read permission denied for this user.")
                        deny_forward = "YES"
                if user == "Saisree":
                    if file_name in read_permissions_saisree:
                        read(file_name,file_path)
                    else:
                        print("Read permission denied for this user.")
                        deny_forward = "YES"
                
            elif msg == "DELETE":
                if user == "Vishnu":
                    if file_name in delete_permissions_vishnu:
                        delete(file_name,file_path)
                    else:
                        print("Delete permission denied for this user.")
                        deny_forward = "YES"
                if user == "Parinitha":
                    if file_name in delete_permissions_parinitha:
                        delete(file_name,file_path)
                    else:
                        print("Delete permission denied for this user.")
                        deny_forward = "YES"
                if user == "Pragdish":
                    if file_name in delete_permissions_pragdish:
                        delete(file_name,file_path)
                    else:
                        print("Delete permission denied for this user.")
                        deny_forward = "YES"
                if user == "Saisree":
                    if file_name in delete_permissions_saisree:
                        delete(file_name,file_path)
                    else:
                        print("Delete permission denied for this user.")
                        deny_forward = "YES"
                
            elif msg == "RESTORE":
                if user == "Vishnu":
                    if file_name in restore_permissions_vishnu:
                        restore(file_name,file_path)
                    else:
                        print("Restore permission denied for this user.")
                        deny_forward = "YES"
                if user == "Parinitha":
                    if file_name in restore_permissions_parinitha:
                        restore(file_name,file_path)
                    else:
                        print("Restore permission denied for this user.")
                        deny_forward = "YES"
                if user == "Pragdish":
                    if file_name in restore_permissions_pragdish:
                        restore(file_name,file_path)
                    else:
                        print("Restore permission denied for this user.")
                        deny_forward = "YES"
                if user == "Saisree":
                    if file_name in restore_permissions_saisree:
                        restore(file_name,file_path)
                    else:
                        print("Restore permission denied for this user.")
                        deny_forward = "YES"
                
            # msg_bytes = msg.encode(FORMAT)

            # #Getting the message length
            # msg_length = len(msg_bytes)
            # msg_length_bytes = str(msg_length).encode(FORMAT)
            # #Padding it to 64 bits
            # msg_length_bytes += b' ' * (MESSAGE_SIZE -  len(msg_length_bytes))

            # msg_length_iv, msg_length_enc = encryptMessage(str(msg_length_bytes))

            # #Sending the message length and the message itself
            # node_socket.send(msg_length_iv)
            # node_socket.send(msg_length_enc) #sending the message length
            if deny_forward == "NO":
                msg_iv, msg_enc = encryptMessage(forward)
                node_socket.send(msg_iv) #sending the actual message
                node_socket.send(msg_enc)
            #getting feedback from NODE
            # feedback_iv = node_socket.recv(16)
            # feedback_enc = node_socket.recv(16384)
            # feedback = decryptMessage(feedback_iv,feedback_enc)
            # print(feedback)
        except:
            print("Error in send_request in users node.")

def get_request():
    while True:
        try:
            # message_length_iv = node_socket.recv(16)
            # message_length_enc = node_socket.recv(MESSAGE_SIZE)
            # message_length = decryptMessage(message_length_iv, message_length_enc)
            message_iv = node_socket.recv(16)
            message_enc = node_socket.recv(16384)
            message = decryptMessage(message_iv,message_enc)
            message_length = len(message)
            msg = message[2:message_length-1]
            print(message)
            #msg = input("Please provide the command: ")
            commands = msg.split(' -')
            msg = commands[0]
            file_name = commands[1]
            if msg == "WRITE":
                try:
                    content = commands[2]
                    content_iv,content = encryptMessage(content)
                except:
                    pass
            if msg == "CREATE":
                try:
                    vishnu_permissions = commands[2]
                    parinitha_permissions = commands[3]
                    pragdish_permissions = commands[4]
                    saisree_permissions = commands[5]
                except:
                    pass
            
            if msg == "CREATE":
                create(file_name,file_path,vishnu_permissions,parinitha_permissions,pragdish_permissions,saisree_permissions)
            elif msg == "WRITE":
                write(file_name,file_path,content,content_iv)
            elif msg == "READ":
                read(file_name,file_path)
            elif msg == "DELETE":
                delete(file_name,file_path)
            elif msg == "RESTORE":
                restore(file_name,file_path)
        except:
            print("An error occured.")

def get_queue_request(queue):
    try:
            # message_length_iv = node_socket.recv(16)
            # message_length_enc = node_socket.recv(MESSAGE_SIZE)
            # message_length = decryptMessage(message_length_iv, message_length_enc)
            message = queue
            message_length = len(message)
            if message[0] == "b":
                msg = message[2:message_length-1]
            else: msg = message
            print(msg)
            #msg = input("Please provide the command: ")
            commands = msg.split(' -')
            msg = commands[0]
            file_name = commands[1]
            if msg == "WRITE":
                try:
                    content = commands[2]
                    content_iv,content = encryptMessage(content)
                except:
                    pass
            if msg == "CREATE":
                try:
                    vishnu_permissions = commands[2]
                    parinitha_permissions = commands[3]
                    pragdish_permissions = commands[4]
                    saisree_permissions = commands[5]
                except:
                    pass
            
            if msg == "CREATE":
                create(file_name,file_path,vishnu_permissions,parinitha_permissions,pragdish_permissions,saisree_permissions)
            elif msg == "WRITE":
                write(file_name,file_path,content,content_iv)
            elif msg == "READ":
                read(file_name,file_path)
            elif msg == "DELETE":
                delete(file_name,file_path)
            elif msg == "RESTORE":
                restore(file_name,file_path)
    except:
            print("An error occured.")


def create(f_name,dir_path,permissions_vishnu,permissions_parinitha,permissions_pragdish,permissions_saisree):
    print("Create Module")
    

    permissions_vishnu_list = permissions_vishnu.split(',')
    permissions_parinitha_list = permissions_parinitha.split(',')
    permissions_pragdish_list = permissions_pragdish.split(',')
    permissions_saisree_list = permissions_saisree.split(',')

    if permissions_vishnu_list[0] == "1":
        read_permissions_vishnu.append(f_name)
    if permissions_vishnu_list[1] == "1":
        write_permissions_vishnu.append(f_name)
    if permissions_vishnu_list[2] == "1":
        delete_permissions_vishnu.append(f_name)
    if permissions_vishnu_list[3] == "1":
        restore_permissions_vishnu.append(f_name)

    if permissions_parinitha_list[0] == "1":
        read_permissions_parinitha.append(f_name)
    if permissions_parinitha_list[1] == "1":
        write_permissions_parinitha.append(f_name)
    if permissions_parinitha_list[2] == "1":
        delete_permissions_parinitha.append(f_name)
    if permissions_parinitha_list[3] == "1":
        restore_permissions_parinitha.append(f_name)

    if permissions_pragdish_list[0] == "1":
        read_permissions_pragdish.append(f_name)
    if permissions_pragdish_list[1] == "1":
        write_permissions_pragdish.append(f_name)
    if permissions_pragdish_list[2] == "1":
        delete_permissions_pragdish.append(f_name)
    if permissions_pragdish_list[3] == "1":
        restore_permissions_pragdish.append(f_name)

    if permissions_saisree_list[0] == "1":
        read_permissions_saisree.append(f_name)
    if permissions_saisree_list[1] == "1":
        write_permissions_saisree.append(f_name)
    if permissions_saisree_list[2] == "1":
        delete_permissions_saisree.append(f_name)
    if permissions_saisree_list[3] == "1":
        restore_permissions_saisree.append(f_name)

    f_path = dir_path + '\\' + f_name
    if os.path.exists(f_path):
        print("This file is already in your directory")
    else:
        fp=open(f_path,'x')
        fp.close()

def write(f_name,dir_path,file_content,content_iv):
    print("Write Module")
    #dir_path = input("Provied the location of the file: ")
    #f_name = input("Please provide the file name: ")
    f_path = dir_path + '\\' + f_name
    #file_content = input("What do you write: ")
    lock.acquire()
    with open(f_path, 'wb') as file:
        file.write(content_iv)
        file.write(file_content)
        file.close()
    lock.release()

def read(f_name,dir_path):
    print("Read Module")
    # dir_path = input("Provied the location of the file: ")
    # f_name = input("Please provide the file name: ")
    f_path = dir_path + '\\' + f_name
    with open(f_path, 'rb') as file:
        content_nonce = file.read(16)
        content = file.read()
        file.close()
        content = decryptMessage(content_nonce,content)
        print(content)

def delete(f_name,dir_path):
    print("Delete Module")
    # dir_path = input("Provied the location of the file: ")
    # f_name = input("Please provide the file name: ")
    f_path = dir_path + '\\' + f_name
    
    src_path = f_path
    dest_path = recycle_path
    try:
        shutil.move(src_path,dest_path)
    except:
        os.remove(f_path)


def restore(f_name,dir_path):
    print("Restore Module")
    f_path = dir_path 
    
    dest_path = f_path
    src_path = recycle_path + '\\' + f_name
    try:
        shutil.copy(src_path,dest_path)
    except:
        pass


if __name__ == "__main__" :

    user = input("Username: ")
    if user == "Vishnu":
        file_path = "C:/Users/parin/OneDrive/Documents/PCS_Project/Vishnu"
        file_path = file_path.replace('/','\\')
    elif user == "Parinitha":
        file_path = "C:/Users/parin/OneDrive/Documents/PCS_Project/Parinitha"
        file_path = file_path.replace('/','\\')
    
    #Connecting the socket
    node_socket.connect(ADDRESS)

    user_iv, user_enc = encryptMessage(user)
    node_socket.send(user_iv)
    time.sleep(1)
    node_socket.send(user_enc)

    queue_iv = node_socket.recv(16)
    queue_enc = node_socket.recv(2048)
    queue = decryptMessage(queue_iv,queue_enc)
    queue = queue[2:len(queue)-1]
    if queue == "CLEAR" or queue == "b'CLEAR'":
        pass
    else:
        while queue != "CLEAR" and queue != "b'CLEAR'":
            get_queue_request(queue)
            queue_iv = node_socket.recv(16)
            queue_enc = node_socket.recv(2048)
            queue = decryptMessage(queue_iv,queue_enc)
            queue = queue[2:len(queue)-1]


    send_thread = threading.Thread(target=send_request,args=(user,))
    send_thread.start()

    recv_thread = threading.Thread(target=get_request, args=())
    recv_thread.start()
