GIGAMON INTERNAL USE ONLY

Description: 
This "config_exec.py" script can be used to configure GVOS nodes by establishing a SSH session to the node. The script takes input from a text file, which has a list of commands that the user needs to run to make the necessary configurations on the GVOS node. The CLI output of all the commands run are stored as text files, which can be referenced to verify all the configurations were run successfully. The list of nodes on which the configuration needs to be made can be provided in the form of an excel sheet or the inventory can be dynamically obtained from FM.
Prerequisites:
Python3 environment to run the script from.
Network connection to the GVOS nodes from the Python3 environment.
The following libraries need to be present: requests, pandas, datetime, getpass, time, paramiko, multiprocessing. If not present these libraries can be installed using the command: pip install <library_name> (we need to have internet connection so the library can be downloaded).

Usage:
The "config_exec.py" depends on "essential.py" and "gigamon.py". All the functions for establishing the SSH connection, sending commands and receiving output are present in "essential.py",  the functions for FM Rest API calls are present in "gigamon.py". If the user wants to use static inventory they need to populate the CSV file as shown below with "HostName", "HostIP" (IP address or DNS of the GVOS node), "Command File Path" (path to where the "commands.txt" file is stored, containing the commands to be run on the node). An example is shown below:


Demo and results:
The script can be run from the Python environment prompt:
$python command_exec.py (environment where only python version >3 is present)
$python3 command_exec.py (environment where only python version >3 and python version 2 is present)
On execution the user is requested for the following inputs:
GVOS node username : the username to login to the node.
GVOS user password: the password to login to the node.
Path to input csv file: the path to the csv file containing the static inventory.



The output is logged in a text file in a folder whose name has the time stamp of when the script was run.
