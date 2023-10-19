from essential import *

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("\nUsage: " + sys.argv[0] + " <user_info_csv_file_path>\n")
        print("Examples: \n")
        print("     $ python " + sys.argv[0] + " User_Info.csv")
        sys.exit(1)

    else:

        user_info_file = sys.argv[1]
    device_current_admin_username = str(input("GVOS node username: "))  # GVOS admin username
    device_current_admin_password = getpass.getpass("GVOS node password: ")  # GVOS admin password
    user_df = pandas.read_csv(user_info_file)
    df = user_df
    exec_dict = {}
    for cluster in df["ClusterIP"].unique():
        out_df = df[df["ClusterIP"] == cluster]
        out_df = out_df.reset_index(drop=True)
        print(out_df)
        out_list = []
        for i in range(0, len(out_df)):
            out_list.append([df["User_Name"][i], df["User_Password"][i], df["User_Full_Name"][i], df["User_Role"][i]])
        exec_dict[cluster] = out_list
    #print(exec_dict)
    #print(df)
    for cl_ip in exec_dict.keys():
        create_user(cl_ip, device_current_admin_username, device_current_admin_password, exec_dict[cl_ip])
