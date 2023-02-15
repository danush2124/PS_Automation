import ast
import getpass
import json
import multiprocessing
import pandas
import paramiko
import re
import sys
import time
import yaml
from datetime import datetime
from gigamon import *


def create_cluster_match(node_list, site_tag, region):
    cluster_id_list = []
    box_id_list = []
    device_ip_list = []
    model_list = []
    hostname_list = []
    cluster_master_list = []
    cluster_list = []
    region_list = []
    cluster_dict = {}
    serial_no_list = []
    combine_all_clusters_dict = {}
    hostname_ip_cluster_correlation_dict = {}
    for node in node_list:
        if node[u'hostname'][3:6] == site_tag:
            try:
                cluster_master_list.append(node[u'clusterMaster'])
            except KeyError:
                cluster_master_list.append('None')
            try:
                box_id_list.append(node[u'boxId'])
            except KeyError:
                box_id_list.append('None')
            try:

                model_list.append(node[u'model'])
            except:
                model_list.append('None')
            try:
                serial_no_list.append(node[u'serialNumber'])
            except:
                serial_no_list.append('None')
            try:
                cluster_id_list.append(node['clusterId'])
            except KeyError:
                cluster_id_list.append("None")
            device_ip_list.append(node['deviceIp'])
            hostname_list.append(node['hostname'])
            region_list = [region] * len(hostname_list)
            site_list = [site_tag] * len(hostname_list)

    for i in range(0, len(cluster_master_list)):
        hostname_ip_cluster_correlation_dict[
            box_id_list[i], hostname_list[i], device_ip_list[i], model_list[i], region_list[i], site_list[i],
            serial_no_list[i]] = cluster_id_list[i]
    # print( hostname_ip_cluster_correlation_dict)
    return hostname_ip_cluster_correlation_dict


def get_cluster_id_list(node_list, site):
    cluster_master_list = []

    for node in node_list:

        try:
            if node[u'hostname'][3:6] == site:

                if node[u'clusterMode'] != u'Standalone' and node[u'clusterMaster'] not in cluster_master_list:
                    cluster_master_list.append(node[u'clusterMaster'])
                elif node[u'clusterMode'] == u'Standalone':
                    cluster_master_list.append(node[u'deviceIp'])
        except KeyError:
            pass
    return cluster_master_list


def read_yaml(yaml_file):
    with open(yaml_file) as file:
        documents = yaml.full_load(file)
    return documents


"""
connect_to(argument1, argument2, argument3) funtion creates ssh connection to a the GVOS device.
argument1= the IP of the Gigamon device you want to connect to
argument2= username for the Gigamon device login
argument3= password for the Gigamon device login //
"""


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
            output += data

        else:
            time.sleep(5)
            if GiG_OS.exit_status_ready():
                break
        return output


"""
do_backup(argument1, argument2, argument3, argument4) this backups
the device and creates the backup files in the specified directory
argument1= the IP of the Gigamon device you want to connect to
argument2= username for the Gigamon device login
argument3= password for the Gigamon device login
the resultant backup files will be stored in a folder under the name with execution date date ex: 2019_08_20_backup
"""


def do_password_change(device_ip, device_user, device_passwd, new_password):
    try:
        g_c = connect_to(device_ip, device_user, device_passwd)
        output = GigamonDevice_recv(g_c, 1)
        # print(output)
        time.sleep(20)
        while True:
            if ">" in output:
                GigamonDevice_send(g_c, "enable", 0)
                output = GigamonDevice_recv(g_c, 1)
                break
            else:
                time.sleep(5)
                output = GigamonDevice_recv(g_c, 1)
        # print(output)
        GigamonDevice_send(g_c, "conf t", 0)
        output = GigamonDevice_recv(g_c, 1)
        # print(output)
        GigamonDevice_send(g_c, "no cli session paging enable", 0)
        output = GigamonDevice_recv(g_c, 1)
        # print(output)

        GigamonDevice_send(g_c, "username admin password", 0)
        output = GigamonDevice_recv(g_c, 1)
        # print(output)
        while True:
            if "Password" in output:
                GigamonDevice_send(g_c, new_password, 0)
                output = GigamonDevice_recv(g_c, 1)
                # print(output)
                break
            else:
                time.sleep(1)
                output = GigamonDevice_recv(g_c, 1)
                # print(output)

        while True:
            if "Confirm" in output:
                GigamonDevice_send(g_c, new_password, 1)
                output = GigamonDevice_recv(g_c, 1)
                # print(output)
                break
            else:
                time.sleep(1)
                output = GigamonDevice_recv(g_c, 1)
                # print(output)
        while True:
            if "#" in output:
                GigamonDevice_send(g_c, "exit", 0)
                output = GigamonDevice_recv(g_c, 1)
                # print(output)
                GigamonDevice_send(g_c, "exit", 0)
                output = GigamonDevice_recv(g_c, 1)
                # print(output)
                break
            else:
                time.sleep(5)
                GigamonDevice_send(g_c, "", 0)
                output = GigamonDevice_recv(g_c, 1)
    except:
        pass


def create_user(device_ip, device_user, device_passwd, new_password):
    try:
        g_c = connect_to(device_ip, device_user, device_passwd)
        output = GigamonDevice_recv(g_c, 1)
        # print(output)
        time.sleep(20)
        while True:
            if ">" in output:
                GigamonDevice_send(g_c, "enable", 0)
                output = GigamonDevice_recv(g_c, 1)
                break
            else:
                time.sleep(5)
                output = GigamonDevice_recv(g_c, 1)
        # print(output)
        GigamonDevice_send(g_c, "conf t", 0)
        output = GigamonDevice_recv(g_c, 1)
        # print(output)
        GigamonDevice_send(g_c, "no cli session paging enable", 0)
        output = GigamonDevice_recv(g_c, 1)
        # print(output)

        GigamonDevice_send(g_c, "username admin2 password", 0)
        output = GigamonDevice_recv(g_c, 1)
        # print(output)
        while True:
            if "Password" in output:
                GigamonDevice_send(g_c, new_password, 0)
                output = GigamonDevice_recv(g_c, 1)
                # print(output)
                break
            else:
                time.sleep(1)
                output = GigamonDevice_recv(g_c, 1)
                # print(output)

        while True:
            if "Confirm" in output:
                GigamonDevice_send(g_c, new_password, 1)
                output = GigamonDevice_recv(g_c, 1)
                # print(output)
                break
            else:
                time.sleep(1)
                output = GigamonDevice_recv(g_c, 1)
                # print(output)
        while True:
            if "#" in output:
                GigamonDevice_send(g_c, "username admin2 role add admin", 0)
                output = GigamonDevice_recv(g_c, 1)
                GigamonDevice_send(g_c, "exit", 0)
                output = GigamonDevice_recv(g_c, 1)
                # print(output)
                GigamonDevice_send(g_c, "exit", 0)
                output = GigamonDevice_recv(g_c, 1)
                # print(output)
                break
            else:
                time.sleep(5)
                GigamonDevice_send(g_c, "", 0)
                output = GigamonDevice_recv(g_c, 1)

    except:
        pass


def check_user_admin2(device_ip, device_user, device_passwd, dict_ret1):
    try:
        g_c = connect_to(device_ip, device_user, device_passwd)
        output = GigamonDevice_recv(g_c, 1)
        # print(output)
        time.sleep(20)
        while True:
            if ">" in output:
                GigamonDevice_send(g_c, "enable", 0)
                output = GigamonDevice_recv(g_c, 1)
                dict_ret1[device_ip] = "Admin2 change verified"
                break

            else:
                time.sleep(5)
                output = GigamonDevice_recv(g_c, 1)
    except:
        pass


def check_user_admin(device_ip, device_user, device_passwd, dict_ret2):
    try:
        g_c = connect_to(device_ip, device_user, device_passwd)
        output = GigamonDevice_recv(g_c, 1)
        # print(output)
        time.sleep(20)
        while True:
            if ">" in output:
                GigamonDevice_send(g_c, "enable", 0)
                output = GigamonDevice_recv(g_c, 1)
                dict_ret2[device_ip] = "Admin change verified"
                break

            else:
                time.sleep(5)
                output = GigamonDevice_recv(g_c, 1)
    except:
        pass


"""
connect_to(argument1, argument2, argument3) function creates ssh connection to  the GVOS device.
argument1= the IP of the Gigamon device you want to connect to
argument2= username for the Gigamon device login
argument3= password for the Gigamon device login //
"""


def Filter_Cli(cli_output):
    cli_output = cli_output.split("\r")
    cli_output = [x.replace("\n", "") for x in cli_output]
    return cli_output


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
GigamonDevice_recv(argument1, argument2)	this receives the cli output to the command sent to the GVOS device over the ssh session using GigamonDevice_send(argument1, argument2, argument3) function
argument1= is the ssh connection returned from connect_to()
argument2= the time interval you want to wait before receiving the cli output (because certain cli commands take long response times so this time delay helps in collecting the correct information)
"""


def GigamonDevice_recv(GiG_OS, Time):
    output = ""
    GiG_OS.setblocking(0)
    time.sleep(5)
    while True:
        time.sleep(Time)

        if GiG_OS.recv_ready():
            data = GiG_OS.recv(111320000)
            output += data.decode('utf-8')

        else:
            time.sleep(5)
            if GiG_OS.exit_status_ready():
                break
        return output


def wait_for_prompt(g_c, output_prev, command):
    while True:
        if ">" in output_prev:
            GigamonDevice_send(g_c, command, 0)
            output = GigamonDevice_recv(g_c, 1)
            break
        else:
            time.sleep(5)
            output_prev += GigamonDevice_recv(g_c, 1)
    return [output, output_prev]


def wait_for_config_prompt(g_c, output_prev, command):
    while True:
        if "(config)" and "#" in output_prev:
            GigamonDevice_send(g_c, command, 0)
            output = GigamonDevice_recv(g_c, 1)
            break
        else:
            time.sleep(5)
            output_prev += GigamonDevice_recv(g_c, 1)
    return [output, output_prev]


"""
do_config(argument1, argument2, argument3, argument4) this backups
the device and creates the backup files in the specified directory
argument1 = the IP of the Gigamon device you want to connect to
argument2 = username for the Gigamon device login
argument3 = password for the Gigamon device login
argument4 = the hostname of the Gigamon device you want to connect to
argument5 = the list of commands you want to execute on the device
the resultant backup files will be stored in a folder under the name with execution date date ex: 2019_08_20_backup
"""


def do_config(device_ip, device_user, device_passwd, hostname):
    ts1 = (datetime.now().strftime("%Y_%m_%d_%H_%M_%S"))
    directory = datetime.now().strftime("%Y_%m_%d_%H")
    directory = "Config_Log_" + directory
    if not os.path.exists(directory):
        os.mkdir(directory)
    f = open(directory + "/" + device_ip + "_Config_Log.txt", "a")
    try:
        print(hostname)
        f.write(hostname)
        f.write('\n')
        g_c = connect_to(device_ip, device_user, device_passwd)
        output = GigamonDevice_recv(g_c, 1)
        time.sleep(2)
    except Exception as e:
        print("Connection Error")
        print("\n")
        f.write("Connection Error")
        f.write('\n')
        pass
    GigamonDevice_send(g_c, "enable", 0)
    output = GigamonDevice_recv(g_c, 1)
    print("In Enable Mode")
    print("\n")
    f.write(output)
    f.write('\n')
    GigamonDevice_send(g_c, "conf t", 0)
    output = GigamonDevice_recv(g_c, 1)
    print("In Config Mode")
    print("\n")
    f.write(output)
    f.write('\n')
    GigamonDevice_send(g_c, "no cli session paging enable", 0)
    output = GigamonDevice_recv(g_c, 1)
    print("Paging Disabled")
    print("\n")
    f.write(output)
    f.write('\n')
    c_list = ["show configuration", "show diag"]
    for cmd in c_list:
        print(cmd)
        outputx = wait_for_config_prompt(g_c, output, cmd)
        output = outputx[0]
        print("Running Command " + cmd)
        print("\n")
        f.write(outputx[1])
        f.write('\n')
    GigamonDevice_send(g_c, "exit", 0)
    output = GigamonDevice_recv(g_c, 1)
    print("Exit config mode")
    print("\n")
    f.write(output)
    f.write('\n')
    GigamonDevice_send(g_c, "conf t", 0)
    output = GigamonDevice_recv(g_c, 1)
    print("Exit ssh session")
    print("\n")
    f.write(output)
    f.write('\n')
