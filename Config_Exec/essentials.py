import datetime
import getpass
import multiprocessing
import pandas
import paramiko
import requests
import sys
import os
import time
import warnings
from datetime import datetime

warnings.filterwarnings("ignore")


def connect_to(hostIP, username, password):
    Gigamon_Device = paramiko.SSHClient()
    Gigamon_Device.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    Gigamon_Device.connect(hostIP, username=username, password=password)
    GiG_OS = Gigamon_Device.get_transport().open_session()
    GiG_OS.get_pty()
    GiG_OS.invoke_shell()
    (GiG_OS.recv(1024))
    time.sleep(5)
    return GiG_OS


"""
GigamonDevice_send(argument1, argument2, argument3)	this sends commands to the GVOS device over the ssh session
argument1= is the ssh connction returned from connect_to(argument1, argument2, argument2)
argument2= is the cli command you want to send
argument3= the time interval you want to wait before sending the next command
"""


def GigamonDevice_send(GiG_OS, command, Time):
    GiG_OS.send(command + "\n")
    time.sleep(Time)


"""
GigamonDevice_recv(argument1, argument2)	this recieves the cli output to the command sent to the GVOS device over the ssh session using GigamonDevice_send(argument1, argument2, argument3) function
argument1= is the ssh connction returned from connect_to()
argument2= the time interval you want to wait before recieving the cli output (beacause certain cli commands take long reponse times so this time delay helps in collecting the correct information)
"""


def GigamonDevice_recv(GiG_OS, Time):
    output = ""
    GiG_OS.setblocking(0)
    time.sleep(5)
    while True:
        time.sleep(Time)

        if GiG_OS.recv_ready():
            data = GiG_OS.recv(111320)
            output += data.decode('utf-8')

        else:
            time.sleep(5)
            if GiG_OS.exit_status_ready():
                break
        return output


"""
wait_for_config_prompt_ready(argument1, argument2)	this sends a command to the GVOS device over the ssh session and waits for the config prompt to be returned
argument1= is the ssh connction returned from connect_to()
argument2= is the cli command you want to send
"""


def wait_for_config_prompt_ready(g_c, command):
    GigamonDevice_send(g_c, command, 0)
    output = GigamonDevice_recv(g_c, 20)
    print(output)
    while True:
        output_l = output.split('\n')
        if "#" in output_l[-1] and "config" in output_l[-1]:
            break
        else:
            time.sleep(20)
            outx = GigamonDevice_recv(g_c, 1)
            if len(outx) > 0:
                output += outx
                print(output)
            else:
                break
    return output


"""
do_config(argument1, argument2, argument3, argument4) this backups
the device and creates the backup files in the specified directory
argument1= the IP of the Gigamon device you want to connect to
argument2= username for the Gigamon device login
argument3= password for the Gigamon device login
argument4= list of commands to be executed
the resulting log files will be stored in a folder under the name with execution date date ex: CommandLog_2022_11_28_11
"""


def do_config(device_ip, device_user, device_passwd, command_dict):
    ts1 = (datetime.now().strftime("%Y_%m_%d_%H_%M_%S"))
    directory = datetime.now().strftime("%Y_%m_%d_%H")
    directory = "CommandLog" + "_" + directory
    f = open(command_dict[device_ip], 'r')
    command_list = []
    for i in f:
        command_list.append(i)
    if not os.path.exists(directory):
        os.mkdir(directory)
    f = open(directory + "/" + device_ip + "_logs.txt", "a")
    try:
        g_c = connect_to(device_ip, device_user, device_passwd)
        output = GigamonDevice_recv(g_c, 1)
        f.write(output)
        f.write('\n')
        time.sleep(20)
        while True:
            if ">" in output:
                GigamonDevice_send(g_c, "enable", 0)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
                break
            else:
                time.sleep(5)
                output = GigamonDevice_recv(g_c, 1)
        GigamonDevice_send(g_c, "conf t", 0)
        output = GigamonDevice_recv(g_c, 1)
        f.write(output)
        f.write('\n')
        GigamonDevice_send(g_c, "no cli session paging enable", 0)
        output = GigamonDevice_recv(g_c, 1)
        f.write(output)
        f.write('\n')
        for command in command_list:
            output = wait_for_config_prompt_ready(g_c, command)
            f.write(output)
            f.write('\n')
        f.close()
    except:
        pass
