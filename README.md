REQUIREMENTS:
Install the required modules using the following commands:
• py -m pip install pycryptodome (or) pip install pycryptodome
• py -m pip install sockets (or) pip install sockets
Step by step implementation of the project:
Activating the communication server node:
We run the python command mentioned below
$ py CommunicationServer_V1.0.py
Note: replace py with python or python3 based on your machine
The node prints the name of machine and that it is ready to listen

Activating the nodes:
We need to open 1 terminal for each node and run the following command:
$ py Node_V1.0.py
It asks for username. It must be only authorised used which in this case are Saisree, Parinitha,
Pragdish and Vishnu only.
Then it asks for path as follow “Please provide the path where you want the operations on the files
to be performed:”
Next it asks for recycle bin path as follows “Please enter the path of recycle bin:”
Then the machine name where communication server is hosted as follows “Please enter the central
communication machine name:”
Then it asks to enter the commands in standard format. The standard format is as follows
Create command
CREATE -<file_name>.bin -<vishnu_permission> -<parinitha_permission> -<pragdish_permission> -
<saisree_permissions>
Permissions are comma separated and 1 is YES and 0 is NO.
Sequence of permissions is read,write,delete,restore
Example: CREATE -Cookbook.bin -1,1,1,1 -0,0,0,0 -1,0,1,0 - 0,1,0,1
The above command creates a file named "Cookbook.bin" with
Vishnu having all the permissions
Parinitha having no permissions
Pragdish having read and delete
Saisree having write and retsore
Write Command
WRITE -<file_name>.bin -<contents_to_be_written>
Read Command
READ -<file_name>.bin
Delete Command
DELETE -<file_name>.bin
Restore Command
RESTORE -<file_name>.bin
List Directories Command
LS -<directory_path>

The same needs to be done in four new terminals to start four nodes.
Showing it is P2P implementation:
In the above said procedure we ran the users Vishnu and Parinitha concurrently and we the
commands implemented from Vishnu, Parinitha individually and passing Vishnu commands to
Parinitha and vice versa.
