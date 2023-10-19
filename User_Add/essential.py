import ast
import json
import multiprocessing
import pandas
import paramiko
import sys
import time
import warnings
import yaml
import getpass
from gigamon import *

warnings.filterwarnings('ignore')


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
                cluster_id_list.append(node['clusterId'])
            except KeyError:
                cluster_id_list.append("None")
            device_ip_list.append(node['deviceIp'])
            hostname_list.append(node['hostname'])
            region_list = [region] * len(hostname_list)
            site_list = [site_tag] * len(hostname_list)

    for i in range(0, len(cluster_master_list)):
        hostname_ip_cluster_correlation_dict[
            box_id_list[i], hostname_list[i], device_ip_list[i], model_list[i], region_list[i], site_list[i]] = \
            cluster_id_list[i]
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
            output += data.decode("utf-8")

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
            if "admin" in output and "password" in output:
                GigamonDevice_send(g_c, device_passwd, 0)
                output = GigamonDevice_recv(g_c, 1)
                # print(output)
                break
            else:
                time.sleep(1)
                output = GigamonDevice_recv(g_c, 1)
                # print(output)
        while True:
            if "new password" in output:
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


def create_user(device_ip, device_user, device_passwd, user_list):
    for info_list in user_list:
        new_password = info_list[1]
        new_user = info_list[0]
        full_name = info_list[2]
        user_role = info_list[3]
        print(device_ip)
    try:
        g_c = connect_to(device_ip, device_user, device_passwd)
        output = GigamonDevice_recv(g_c, 1)
        print(output)
        time.sleep(20)
        while True:
            if ">" in output:
                GigamonDevice_send(g_c, "enable", 0)
                output = GigamonDevice_recv(g_c, 1)
                break
            else:
                time.sleep(5)
                output = GigamonDevice_recv(g_c, 1)
        print(output)
        GigamonDevice_send(g_c, "conf t", 0)
        output = GigamonDevice_recv(g_c, 1)
        print(output)
        GigamonDevice_send(g_c, "no cli session paging enable", 0)
        output = GigamonDevice_recv(g_c, 1)
        print(output)

        GigamonDevice_send(g_c, "username " + new_user + " password", 0)
        output = GigamonDevice_recv(g_c, 1)
        print(output)
        while True:
            if "admin" in output and "password" in output:
                GigamonDevice_send(g_c, device_passwd, 0)
                output = GigamonDevice_recv(g_c, 1)
                print(output)
                break
            else:
                time.sleep(1)
                output = GigamonDevice_recv(g_c, 1)
                print(output)
        while True:
            if "new password" in output:
                GigamonDevice_send(g_c, new_password, 1)
                output = GigamonDevice_recv(g_c, 1)
                print(output)
                break
            else:
                time.sleep(1)
                output = GigamonDevice_recv(g_c, 1)
                print(output)
        while True:
            if "Confirm" in output:
                GigamonDevice_send(g_c, new_password, 1)
                output = GigamonDevice_recv(g_c, 1)
                print(output)
                break
            else:
                time.sleep(1)
                output = GigamonDevice_recv(g_c, 1)
                print(output)
        while True:
            if "#" in output:
                GigamonDevice_send(g_c, "user " + new_user + " full-name " + full_name, 0)
                output = GigamonDevice_recv(g_c, 1)
                GigamonDevice_send(g_c, "username " + new_user + " role add " + user_role, 0)
                output = GigamonDevice_recv(g_c, 1)
                GigamonDevice_send(g_c, "wr mem", 0)
                output = GigamonDevice_recv(g_c, 1)
                GigamonDevice_send(g_c, "exit", 0)
                output = GigamonDevice_recv(g_c, 1)
                print(output)
                GigamonDevice_send(g_c, "exit", 0)
                output = GigamonDevice_recv(g_c, 1)
                print(output)
                break
            else:
                time.sleep(5)
                GigamonDevice_send(g_c, "", 0)
                output = GigamonDevice_recv(g_c, 1)

    except:
        pass


def check_user(device_ip, device_user, device_passwd, dict_ret1):
    try:
        g_c = connect_to(device_ip, device_user, device_passwd)
        output = GigamonDevice_recv(g_c, 1)
        # print(output)
        time.sleep(20)
        while True:
            if ">" in output:
                GigamonDevice_send(g_c, "enable", 0)
                output = GigamonDevice_recv(g_c, 1)
                print(output)
                dict_ret1[device_ip] = device_user + " user login verified"
                break

            else:
                time.sleep(5)
                output = GigamonDevice_recv(g_c, 1)
    except:
        pass


def delete_user(device_ip, device_user, device_passwd, user_list):
    print(device_ip)
    try:
        g_c = connect_to(device_ip, device_user, device_passwd)
        output = GigamonDevice_recv(g_c, 1)
        print(output)
        time.sleep(20)
        while True:
            if ">" in output:
                GigamonDevice_send(g_c, "enable", 0)
                output = GigamonDevice_recv(g_c, 1)
                break
            else:
                time.sleep(5)
                output = GigamonDevice_recv(g_c, 1)
        print(output)
        GigamonDevice_send(g_c, "conf t", 0)
        output = GigamonDevice_recv(g_c, 1)
        # print(output)
        GigamonDevice_send(g_c, "no cli session paging enable", 0)
        output = GigamonDevice_recv(g_c, 1)
        # print(output)
        for user_info in user_list:
            new_user = user_info[0]
            new_password = user_info[1]
            full_name = user_info[2]
            user_role = user_info[3]
            GigamonDevice_send(g_c, "no username " + new_user, 0)
            output = GigamonDevice_recv(g_c, 1)
            GigamonDevice_send(g_c, "wr mem", 0)
            output = GigamonDevice_recv(g_c, 1)
            print("User " + new_user + " deleted!")
        output = GigamonDevice_recv(g_c, 1)
        GigamonDevice_send(g_c, "exit", 0)
        output = GigamonDevice_recv(g_c, 1)
        GigamonDevice_send(g_c, "exit", 0)
        output = GigamonDevice_recv(g_c, 1)
    except:
        pass
