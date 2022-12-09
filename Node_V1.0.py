# CMSC 626 PRINCIPLES OF COMPUTER SECURITY - Project

# Submitted by Group 6

# Hima Poojitha Sai Sree Myla	    -	QN08170
# Parinitha Reddy Gaddam		    -	KT16974
# Pragadiswar Nanda Muralidharan	-	PO21974
# Vishnu Vardhan Samba		        -	IK67010

#This programs helps the node to establish communication with the with other nodes in the network with direct communication to 
# the Communication server.
#Here the user commands are implemented by using the resources of the machine on which it is hosted and sends the implemented commands 
# across the network to other nodes via communication server.
#CRUD operations are implemented here after checking for permissions.

#Importing required python libraries
import os
import shutil
import socket
import threading
import time

from Crypto.Cipher import AES #Advanced Encryption Standard
from Crypto.Util.Padding import pad, unpad

#Defining the constants
PORT = 5050     #Assigning port
MESSAGE_SIZE = 64 
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "Connection disconnect"

#Defining variables
lock = threading.Lock() #Lock varibale
#The key which is present with all nodes and plugged into the code
actual_key = b'~$?R\x0e\x14\xab\xbd\xc3\xdeL\xa1N(\x83\xd5T\xdb1\x83\xd9ANy\xc4\xe5\x19\xb6s\x82\xc1\x8e'

#Queue for each user where are all read permission file for a particular user are pushes in one list.
read_permissions_vishnu = []
read_permissions_parinitha = []
read_permissions_saisree = []
read_permissions_pragdish = []

#Queue for each user where are all write permission file for a particular user are pushes in one list.
write_permissions_vishnu = []
write_permissions_parinitha = []
write_permissions_saisree = []
write_permissions_pragdish = []

#Queue for each user where are all delete permission file for a particular user are pushes in one list.
delete_permissions_vishnu = []
delete_permissions_parinitha = []
delete_permissions_saisree = []
delete_permissions_pragdish = []

#Queue for each user where are all restore permission file for a particular user are pushes in one list.
restore_permissions_vishnu = []
restore_permissions_parinitha = []
restore_permissions_saisree = []
restore_permissions_pragdish = []

#Defining Functions

#This function is used for encrypting plain text. It takes plain text as argument and retunr an initialization vector(which is used a nonce 
#during decryption) and the encrypted text
def encryptMessage(plain_text):
    plain_text_bytes = plain_text.encode() #converting plain text to bytes which is the required data type for padding
    encryption = AES.new(actual_key, AES.MODE_CBC)
    encrypted_text = encryption.encrypt(pad(plain_text_bytes, AES.block_size))
    return encryption.iv,encrypted_text

#This function is used for decrypting encrypted message. It takes nonce and encrypted text as arguments and returns the plain text.
def decryptMessage(nonce,decryption_data):
    decryption = AES.new(actual_key, AES.MODE_CBC, iv=nonce)
    decrypted_text = unpad(decryption.decrypt(decryption_data), AES.block_size)
    return str(decrypted_text)

#This function implements the CRUD operations by updating and checking the permissions for a particular user. After the implementation of each
#command it is sent to the every other active user via communication server.
def send_request(user):
    while True:
        deny_forward = "NO" #This variable sends the command to other nodes only if it is legal for this node to perform that action
        try:
            content = input("Enter the commands in the standard format: ")
            commands = content.split('|')       #Seperating each command
            for x in commands:                
                msg = x
                forward = msg
                commands = msg.split(' -')      #Seperating one command to identify the elements of the command
                msg = commands[0]
                try:
                    file_name = commands[1]     #for create command
                except:
                    pass
                if msg == "WRITE":
                    try:
                        content = commands[2]   #Getting the contents to be written in file
                        content_iv,content = encryptMessage(content) #encrypting the contents to be written in the file
                    except:
                        pass
                if msg == "CREATE":
                    try:
                        vishnu_permissions = commands[2] #Getting the permissions for every user
                        parinitha_permissions = commands[3]
                        pragdish_permissions = commands[4]
                        saisree_permissions = commands[5]
                    except:
                        pass
                if msg == "LS":
                    dir_path = file_name    #Used while printing the file name sin a directory
                
                if msg == "CREATE":                
                    create(file_name,file_path,vishnu_permissions,parinitha_permissions,pragdish_permissions,saisree_permissions)

                elif msg == "WRITE":
                    if user == "Vishnu":
                        #Checking for permissions and doing the respective action
                        if file_name in write_permissions_vishnu:
                            write(file_name,file_path,content,content_iv)
                        else:
                            print("Write permission denied for this user.")
                            deny_forward = "YES"
                    if user == "Parinitha":
                        #Checking for permissions and doing the respective action
                        if file_name in write_permissions_parinitha:
                            write(file_name,file_path,content,content_iv)
                        else:
                            print("Write permission denied for this user.")
                            deny_forward = "YES"
                    if user == "Pragdish":
                        #Checking for permissions and doing the respective action
                        if file_name in write_permissions_pragdish:
                            write(file_name,file_path,content,content_iv)
                        else:
                            print("Write permission denied for this user.")
                            deny_forward = "YES"
                    if user == "Saisree":
                        #Checking for permissions and doing the respective action
                        if file_name in write_permissions_saisree:
                            write(file_name,file_path,content,content_iv)
                        else:
                            print("Write permission denied for this user.")
                            deny_forward = "YES"

                    
                elif msg == "READ":
                    if user == "Vishnu":
                        #Checking for permissions and doing the respective action
                        if file_name in read_permissions_vishnu:
                            read(file_name,file_path)
                        else:
                            print("Read permission denied for this user.")
                            deny_forward = "YES"
                    if user == "Parinitha":
                        #Checking for permissions and doing the respective action
                        if file_name in read_permissions_parinitha:
                            read(file_name,file_path)
                        else:
                            print("Read permission denied for this user.")
                            deny_forward = "YES"
                    if user == "Pragdish":
                        #Checking for permissions and doing the respective action
                        if file_name in read_permissions_pragdish:
                            read(file_name,file_path)
                        else:
                            print("Read permission denied for this user.")
                            deny_forward = "YES"
                    if user == "Saisree":
                        #Checking for permissions and doing the respective action
                        if file_name in read_permissions_saisree:
                            read(file_name,file_path)
                        else:
                            print("Read permission denied for this user.")
                            deny_forward = "YES"
                    
                elif msg == "DELETE":
                    if user == "Vishnu":
                        #Checking for permissions and doing the respective action
                        if file_name in delete_permissions_vishnu:
                            delete(file_name,file_path)
                        else:
                            print("Delete permission denied for this user.")
                            deny_forward = "YES"
                    if user == "Parinitha":
                        #Checking for permissions and doing the respective action
                        if file_name in delete_permissions_parinitha:
                            delete(file_name,file_path)
                        else:
                            print("Delete permission denied for this user.")
                            deny_forward = "YES"
                    if user == "Pragdish":
                        #Checking for permissions and doing the respective action
                        if file_name in delete_permissions_pragdish:
                            delete(file_name,file_path)
                        else:
                            print("Delete permission denied for this user.")
                            deny_forward = "YES"
                    if user == "Saisree":
                        #Checking for permissions and doing the respective action
                        if file_name in delete_permissions_saisree:
                            delete(file_name,file_path)
                        else:
                            print("Delete permission denied for this user.")
                            deny_forward = "YES"
                    
                elif msg == "RESTORE":
                    if user == "Vishnu":
                        #Checking for permissions and doing the respective action
                        if file_name in restore_permissions_vishnu:
                            restore(file_name,file_path)
                        else:
                            print("Restore permission denied for this user.")
                            deny_forward = "YES"
                    if user == "Parinitha":
                        #Checking for permissions and doing the respective action
                        if file_name in restore_permissions_parinitha:
                            restore(file_name,file_path)
                        else:
                            print("Restore permission denied for this user.")
                            deny_forward = "YES"
                    if user == "Pragdish":
                        #Checking for permissions and doing the respective action
                        if file_name in restore_permissions_pragdish:
                            restore(file_name,file_path)
                        else:
                            print("Restore permission denied for this user.")
                            deny_forward = "YES"
                    if user == "Saisree":
                        #Checking for permissions and doing the respective action
                        if file_name in restore_permissions_saisree:
                            restore(file_name,file_path)
                        else:
                            print("Restore permission denied for this user.")
                            deny_forward = "YES"
                elif msg == "LS":
                    readDirectory(dir_path,user)
                    
                if deny_forward == "NO":
                    msg_iv, msg_enc = encryptMessage(forward)
                    node_socket.send(msg_iv) #sending the actual message
                    node_socket.send(msg_enc)
                    time.sleep(0.1)
        except:
            exit

#This function has the same functionality of send_request() function except that this handles commands from other nodes sent via communication
#server under send_request() which handles commands from terminal
def get_request():
    while True:
        try:
            message_iv = node_socket.recv(16)   #getting command of other nodes from communication server
            message_enc = node_socket.recv(16384)
            message = decryptMessage(message_iv,message_enc)
            message_length = len(message)
            msg = message[2:message_length-1]
            print(message)
            commands = msg.split(' -')  #split to command to get individual entities
            msg = commands[0]           #Which among CRUD operation
            file_name = commands[1]     #file name to perform operation on
            if msg == "WRITE":
                try:
                    content = commands[2] #Getting content to write to file
                    content_iv,content = encryptMessage(content)    #encrypting the content
                except:
                    pass
            if msg == "CREATE":
                try:
                    vishnu_permissions = commands[2]    #updating permission for each user
                    parinitha_permissions = commands[3]
                    pragdish_permissions = commands[4]
                    saisree_permissions = commands[5]
                except:
                    pass
            
            #Implementing CRUD operations based on the command
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
            elif msg == "LS":
                pass
        except:
            print("Please hit enter to proceed further.")

#This function has the same functionality of get_request() function except that this handles commands from queue which it missed when not active
def get_queue_request(queue):
    try:
            message = queue
            message_length = len(message)
            if message[0] == "b":
                msg = "CLEAR"
            else: msg = message
            print(msg)
            commands = msg.split(' -')  #split to command to get individual entities
            msg = commands[0]           #Which among CRUD operation
            file_name = commands[1]     #file name to perform operation on
            if msg == "WRITE":
                try:
                    content = commands[2]   #Getting content to write to file
                    content_iv,content = encryptMessage(content)    #encrypting the content
                except:
                    pass
            if msg == "CREATE":
                try:
                    vishnu_permissions = commands[2]    #updating permission for each user
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
            elif msg == "LS":
                pass
    except:
            print("Please hit enter to proceed further.")

#This functions creates a file and sets permissions for every user
def create(f_name,dir_path,permissions_vishnu,permissions_parinitha,permissions_pragdish,permissions_saisree):
    print("Create file....")    

    #Getting individual read,write,delete,restore permissions
    permissions_vishnu_list = permissions_vishnu.split(',')
    permissions_parinitha_list = permissions_parinitha.split(',')
    permissions_pragdish_list = permissions_pragdish.split(',')
    permissions_saisree_list = permissions_saisree.split(',')

    #Updating permissions in the respective users queue
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

    #Creating the functions
    f_path = dir_path + '\\' + f_name
    if os.path.exists(f_path):
        print("This file is already in your directory")
    else:
        fp=open(f_path,'x')
        fp.close()

#This function writes the contents into the file if authorized
def write(f_name,dir_path,file_content,content_iv):
    print("Writing to the file....")
    f_path = dir_path + '\\' + f_name
    #locking to not allow any actions while writing
    lock.acquire()
    with open(f_path, 'wb') as file:
        file.write(content_iv)
        file.write(file_content)
        file.close()
    lock.release()

#This function reads the contents from the file if authorized
def read(f_name,dir_path):
    print("Reading File....")
    f_path = dir_path + '\\' + f_name
    with open(f_path, 'rb') as file:
        content_nonce = file.read(16)
        content = file.read()
        file.close()
        content = decryptMessage(content_nonce,content) #decrypting the message from file
        print(content)

#This function deletes the file if authorized
def delete(f_name,dir_path):
    print("Deleting file....")
    f_path = dir_path + '\\' + f_name    
    src_path = f_path
    dest_path = recycle_path
    try:
        shutil.move(src_path,dest_path)
    except:
        os.remove(f_path)

#This function restores the deleted files if authorized
def restore(f_name,dir_path):
    print("Restore Module")
    f_path = dir_path     
    dest_path = f_path
    src_path = recycle_path + '\\' + f_name
    try:
        shutil.copy(src_path,dest_path)
    except:
        pass

#This function prints the files in the directory if authorized
def readDirectory(dir_path,user):
    files_in_dir = os.listdir(dir_path)
    for f in files_in_dir:
        if user == "Vishnu":
            if f in read_permissions_vishnu and f in write_permissions_vishnu and f in delete_permissions_vishnu and f in restore_permissions_vishnu:
                print(f)
        elif user == "Parinitha":
            if f in read_permissions_parinitha and f in write_permissions_parinitha and f in delete_permissions_parinitha and f in restore_permissions_parinitha:
                print(f)
        elif user == "Pragdish":
            if f in read_permissions_pragdish and f in write_permissions_pragdish and f in delete_permissions_pragdish and f in restore_permissions_pragdish:
                print(f)
        elif user == "Saisree":
            if f in read_permissions_saisree and f in write_permissions_saisree and f in delete_permissions_saisree and f in restore_permissions_saisree:
                print(f)


if __name__ == "__main__" :

    user = input("Username: ")
    file_path = input("Please provide the path where you want the operations on the files to be performed: ")
    recycle_path = input("Please enter the path of recycle bin: ")

    #establishing the connection by creating a socket
    NODE = input("Please enter the central communication machine name: ")
    ADDRESS = (NODE, PORT) #Defining the address tuple which is needed to connect the socket to a specific port
    node_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    node_socket.connect(ADDRESS)

    #sending user details to communication server
    user_iv, user_enc = encryptMessage(user)
    node_socket.send(user_iv)
    time.sleep(0.1)
    node_socket.send(user_enc)

    #Checking if any message in queue when node was not active
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