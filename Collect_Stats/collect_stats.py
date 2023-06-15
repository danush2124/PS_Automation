from essential import *

if __name__ == "__main__":
    FM_IP = str(input("Enter FM IP Address: "))
    FM_Username = str(input("Enter FM Username: "))
    FM_Password = str(getpass.getpass("Enter FM Password: "))
    Hostname = str(input("Enter Hostname: "))
    Port_ID = str(input("Enter Port ID: "))
    portID = Port_ID.replace("/", "_")
    fm_dict = {"FM":FM_IP}
    df_out = create_reports(fm_dict, Hostname, portID, FM_Username, FM_Password)
    timest = datetime.now().strftime("%Y_%m_%d_%H_%M")
    df_out.to_csv(timest + "_" + hostname + "_" + portID + "_Port_Util_Report.csv", index=False)
