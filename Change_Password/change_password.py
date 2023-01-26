from essential import *

if __name__ == "__main__":

    fm_dict = {}
    fm_ip = str(input("Enter FM IP: "))
    fm_dict = {"Prod_FM": fm_ip}
    fmUser = str(input("Enter FM username: "))
    fmPasswd = getpass.getpass("Enter FM password: ")
    device_current_username = str(input("Enter GVOS node username: "))
    device_current_password = getpass.getpass("GVOS node password: ")
    device_new_password = getpass.getpass("GVOS node new password: ")
    new_user = str(input("Enter backup node username to be created: "))
    new_user_password = getpass.getpass("Enter password for backup user: ")
    node_list = []
    device_list = []
    ta1_inventory_list = []
    host_ip_dict = {}
    cluster_device_ip_list = []
    fm = FM(fm_ip, fmUser, fmPasswd)
    node_list = fm.get_device_inventory()
    out_df = create_cluster_match(node_list, fm_ip)
    print(out_df)
    print('\n')
    processes = []
    df = out_df
    device_list = [x for x in df["HostIP"]]
    print("The devices on which password is being changed: "),
    print(device_list)
    print('\n')
    count = 0
    manager = multiprocessing.Manager()
    dict_ret1 = manager.dict()
    dict_ret2 = manager.dict()
    for ip in device_list:
        count += 1
        t = multiprocessing.Process(target=create_user,
                                    args=(
                                        ip, device_current_username, device_current_password, new_user,
                                        new_user_password))
        processes.append(t)
        t.start()
    for one_process in processes:
        one_process.join()
    processes = []
    count = 0
    device_complete_list = [x for x in df["HostIP"]]
    print(device_complete_list)
    for ip in device_complete_list:
        count += 1
        t = multiprocessing.Process(target=check_user_create,
                                    args=(ip, new_user, new_user_password, dict_ret1))
        processes.append(t)
        t.start()
    for one_process in processes:
        one_process.join()

    print("The number of devices on which " + new_user + " creation is being verified : "),
    print(len(device_complete_list))
    print('\n')
    print("The number of devices on which " + new_user + " creation is successful : "),
    print(len(dict_ret1.keys()))
    print(dict_ret1.keys())
    processes = []

    count = 0
    device_complete_list = dict_ret1.keys()
    for ip in device_complete_list:
        count += 1
        t = multiprocessing.Process(target=do_password_change,
                                    args=(ip, new_user, new_user_password, device_current_username,
                                          device_new_password))
        processes.append(t)
        t.start()
    for one_process in processes:
        one_process.join()


    processes = []
    count = 0
    device_complete_list = dict_ret1.keys()
    for ip in device_complete_list:
        count += 1
        t = multiprocessing.Process(target=check_user_create,
                                    args=(ip, device_current_username, device_new_password, dict_ret2))
        processes.append(t)
        t.start()
    for one_process in processes:
        one_process.join()
    print("The number of devices on which " + device_current_username + " password change is being verified : "),
    print(len(device_complete_list))
    print('\n')
    print("The number of devices on which " + device_current_username + " password change is successful : "),
    print(len(dict_ret2.keys()))
    print(len(dict_ret2))

    fm = FM(fm_ip, fmUser, fmPasswd)
    for ip in device_complete_list:
        fm_update = fm.update_node_credential(ip, device_current_username, device_new_password)
        if fm_update == 0:
            print('\n')
            print("FM node update for " + ip + " successful")
    user_input = str(input("Do you want to delete backup user(yes/no): "))
    if user_input == "yes":
        dict_ret3 = manager.dict()
        processes = []
        count = 0
        device_complete_list = dict_ret1.keys()
        print(device_complete_list)
        for ip in device_complete_list:
            count += 1
            t = multiprocessing.Process(target=user_delete,
                                        args=(ip, device_current_username, device_new_password, new_user,
                                              dict_ret3))
            processes.append(t)
            t.start()
        for one_process in processes:
            one_process.join()
        print("The number of devices on which " + new_user + " is being deleted : "),
        print(len(device_complete_list))
        print('\n')
        print("The number of devices on which " + new_user + " deletion is successful : "),
        print(len(dict_ret3.keys()))
        print(dict_ret3.keys())