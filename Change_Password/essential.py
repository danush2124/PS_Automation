import ast
import getpass
import json
import multiprocessing
import pandas
import paramiko
import sys
import datetime
import time
import yaml
from datetime import datetime
from gigamon import *


def create_cluster_match(node_list, fm_ip):
    cluster_id_list = []
    box_id_list = []
    device_ip_list = []
    model_list = []
    hostname_list = []
    cluster_master_list = []
    cluster_list = []
    region_list = []
    cluster_dict = {}
    sw_list = []
    combine_all_clusters_dict = {}
    hostname_ip_cluster_correlation_dict = {}

    for node in node_list:
        try:
            cluster_master_list.append(node[u'clusterMaster'])
        except KeyError:
            cluster_master_list.append(node['deviceIp'])
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
        try:
            sw_list.append(node[u'swVersion'])
        except:
            sw_list.append("NONE")
        device_ip_list.append(node['deviceIp'])
        hostname_list.append(node['hostname'])

    fm_list = len(cluster_master_list) * [fm_ip]
    for i in range(0, len(cluster_master_list)):
        hostname_ip_cluster_correlation_dict[
            box_id_list[i], hostname_list[i], device_ip_list[i], model_list[i], sw_list[i], fm_list[i]] = \
            cluster_id_list[i]
    df = pandas.DataFrame({"Hostname": hostname_list, "HostIP": device_ip_list, "Cluster_Master": cluster_master_list,
                           "Cluster_ID": cluster_id_list,
                           "Box_ID": box_id_list, "Model": model_list, "SW": sw_list, "FM": fm_list})
    return df


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


def do_password_change(device_ip, device_user, device_passwd, username, new_password):
    directory = datetime.now().strftime("%Y_%m_%d_%H")
    directory = "Password_Change_logs_" + directory
    if not os.path.exists(directory):
        os.mkdir(directory)
    f = open(directory + "/" + device_ip + "_" + device_user + "_password_change_config_logs.txt", "a")
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

        # print(output)
        GigamonDevice_send(g_c, "conf t", 0)
        output = GigamonDevice_recv(g_c, 1)
        f.write(output)
        f.write('\n')
        GigamonDevice_send(g_c, "no cli session paging enable", 0)
        output = GigamonDevice_recv(g_c, 1)
        f.write(output)
        f.write('\n')

        GigamonDevice_send(g_c, "username " + username + " password", 0)
        output = GigamonDevice_recv(g_c, 1)
        f.write(output)
        f.write('\n')
        while True:
            if "current" in output and "password" in output:
                GigamonDevice_send(g_c, device_passwd, 0)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
                break
            else:
                time.sleep(1)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
        while True:
            if "new" in output and "password" in output:
                GigamonDevice_send(g_c, new_password, 0)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
                break
            else:
                time.sleep(1)
                output = GigamonDevice_recv(g_c, 1)
                print(output)

        while True:
            if "Confirm" in output:
                GigamonDevice_send(g_c, new_password, 0)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
                break
            else:
                time.sleep(1)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
        while True:
            if "#" in output:
                GigamonDevice_send(g_c, "write memory " + username, 0)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
                GigamonDevice_send(g_c, "exit", 0)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
                GigamonDevice_send(g_c, "exit", 0)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
                break
            else:
                time.sleep(5)
                GigamonDevice_send(g_c, "", 0)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
        f.close()
    except:
        f.write("User " + device_user + "password change error")
        f.write('\n')
        f.close()
        pass


def create_user(device_ip, device_user, device_passwd, username, new_user_password):
    directory = datetime.now().strftime("%Y_%m_%d_%H")
    directory = "Password_Change_logs_" + directory
    if not os.path.exists(directory):
        os.mkdir(directory)
    f = open(directory + "/" + device_ip + "_" + username + "_create_config_logs.txt", "a")
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
        GigamonDevice_send(g_c, "username " + username + " password", 0)
        output = GigamonDevice_recv(g_c, 1)
        f.write(output)
        f.write('\n')
        while True:
            if "current" in output and "password" in output:
                GigamonDevice_send(g_c, device_passwd, 0)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
                break
            else:
                time.sleep(1)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
        while True:
            if "new" in output and "password" in output:
                GigamonDevice_send(g_c, new_user_password, 0)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
                break
            else:
                time.sleep(1)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')

        while True:
            if "Confirm" in output:
                GigamonDevice_send(g_c, new_user_password, 1)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
                break
            else:
                time.sleep(1)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
        while True:
            if "#" in output:
                GigamonDevice_send(g_c, "username " + username + " role add admin", 0)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
                GigamonDevice_send(g_c, "write memory ", 0)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
                GigamonDevice_send(g_c, "exit", 0)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
                GigamonDevice_send(g_c, "exit", 0)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
                break
            else:
                time.sleep(5)
                GigamonDevice_send(g_c, "", 0)
                output = GigamonDevice_recv(g_c, 1)
                f.write(output)
                f.write('\n')
        f.close()
    except:
        f.write("User " + username + " creation failed on " + device_ip)
        f.write('\n')
        f.close()
        pass


def check_user_create(device_ip, device_user, device_passwd, dict_ret1):
    directory = datetime.now().strftime("%Y_%m_%d_%H")
    directory = "Password_Change_logs_" + directory
    if not os.path.exists(directory):
        os.mkdir(directory)
    f = open(directory + "/" + device_ip + "_" + device_user + "_password_change_verify_logs.txt", "a")
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
                dict_ret1[device_ip] = "New user login verified"
                break

            else:
                time.sleep(5)
                output = GigamonDevice_recv(g_c, 1)
        f.close()
    except:
        f.write("User " + device_user + " login failed on " + device_ip)
        f.write('\n')
        f.close()
        pass


def user_delete(device_ip, device_user, device_passwd, username, dict_ret3):
    directory = datetime.now().strftime("%Y_%m_%d_%H")
    directory = "Password_Change_logs_" + directory
    if not os.path.exists(directory):
        os.mkdir(directory)
    f = open(directory + "/" + device_ip + "_" + username + "_delete_logs.txt", "a")
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
        GigamonDevice_send(g_c, "no username " + username, 0)
        output = GigamonDevice_recv(g_c, 1)
        f.write(output)
        f.write('\n')
        GigamonDevice_send(g_c, "write memory", 0)
        output = GigamonDevice_recv(g_c, 1)
        f.write(output)
        f.write('\n')
        GigamonDevice_send(g_c, "exit", 0)
        output = GigamonDevice_recv(g_c, 1)
        f.write(output)
        f.write('\n')
        GigamonDevice_send(g_c, "exit", 0)
        output = GigamonDevice_recv(g_c, 1)
        f.write(output)
        f.write('\n')
        f.close()
        dict_ret3[device_ip] = "New user deleted"
    except:
        f.write("User " + username + " deletion failed on " + device_ip)
        f.write('\n')
        f.close()
        pass
