from essential import *


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("\nUsage: " + sys.argv[0] + " <path_to_input_node_csv>\n")
        print("Examples: \n")
        print("     $ python " + sys.argv[0] + " NodeList.csv ")
        sys.exit(1)
    else:
        input_csv = sys.argv[1]
        print(input_csv)
    df = pandas.read_csv(input_csv)
    command_list = []
    manager = multiprocessing.Manager()
    count = 0
    processes = []
    node_username = str(input("Enter Username for GVOS node: "))  # User is prompted for gigamon node username
    node_passwd = getpass.getpass("Enter GVOS node password: ")  # User is prompted for gigamon node password
    for node in range(0, len(df)):
        count += 1
        node_ip = df["HostIP"][node]
        hostname = df["HostName"][node]
        t = multiprocessing.Process(target=do_config, args=(node_ip, node_username, node_passwd, hostname))
        processes.append(t)
        t.start()
        print(count)
    for one_process in processes:
        one_process.join()
