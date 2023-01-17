from essentials import *
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

if __name__ == "__main__":
    node_user = str(input("Enter GVOS username:"))
    currentPwd = getpass.getpass("Enter GVOS user password:")
    user_info_file = str(input("Enter path to input csv file:"))
    node_info_df = pandas.read_csv(user_info_file)
    df = node_info_df
    command_dict = {}
    for k in range(0, len(df)):
        command_dict[df["HostIP"][k]] = df["Command File Path"][k]
    processes = []
    manager = multiprocessing.Manager()
    dict_ret1 = manager.dict()
    dict_ret2 = manager.dict()
    c = 0
    count = 0
    device_ip_list = [ip for ip in df["HostIP"]]
    while True:
        if len(device_ip_list) - c > 50:
            x = 50
        else:
            x = len(device_ip_list) - c
        for ip in device_ip_list[c:c + x]:
            count += 1
            t = multiprocessing.Process(target=do_config, args=(ip, node_user, currentPwd, command_dict,))
            processes.append(t)
            t.start()
        for one_process in processes:
            one_process.join()
        if c + x < len(device_ip_list):
            c = c + x
        else:
            break
