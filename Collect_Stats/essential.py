import json
import multiprocessing
import pandas
import requests
import sys
import time
import getpass
import warnings
from datetime import datetime
from multiprocessing import Manager

warnings.filterwarnings("ignore")


def convert_to_csv(response):
    type_list = []
    alias_list = []
    tx_util_list = []
    rx_util_list = []
    cluster_list = []
    vendorname_list = []
    vendorpn_list = []
    node_list = []
    time_stamp_list = []
    sfp_min_list = []
    sfp_max_list = []
    port_id_list = []
    for j in response:
        try:
            alias_list.append(j[u'_source'][u'alias'])
        except:
            alias_list.append("Unknown")
        try:
            tx_util_list.append(j[u'_source'][u'port'][u'tx'][u'utilztn'])
        except:
            tx_util_list.append("Unknown")
        try:
            rx_util_list.append(j[u'_source'][u'port'][u'rx'][u'utilztn'])
        except:
            rx_util_list.append("Unknown")
        try:
            port_id_list.append(j[u'_source'][u'resource'][u'id'][u'entityId'])
        except:
            port_id_list.append("Unknown")
        try:
            cluster_list.append(j[u'_source'][u'resource'][u'id'][u'clusterId'])
        except:
            cluster_list.append(j[u'_source'][u'clusterId'])
        try:
            vendorname_list.append(j[u'_source'][u'vendorName'])
        except:
            vendorname_list.append("Unknown")
        try:
            vendorpn_list.append(j[u'_source'][u'vendorPn'])
        except:
            vendorpn_list.append("Unknown")
        try:
            type_list.append(j[u'_source'][u'portType'])
        except:
            type_list.append("unknown")
        try:
            time_stamp_list.append(j[u'_source'][u'timestamp'])
        except:
            time_stamp_list.append("Unknown")
        try:
            sfp_min_list.append(j[u'_source'][u'port'][u'rx'][u'sfpPowerMin'])
        except:
            sfp_min_list.append("Unknown")
        try:
            sfp_max_list.append(j[u'_source'][u'port'][u'rx'][u'sfpPowerMax'])
        except:
            sfp_max_list.append("Unknown")
        try:
            node_list.append(j[u'_source'][u'hostName'])
        except:
            node_list.append("Unknown")
    df = pandas.DataFrame({"TimeStamp": time_stamp_list, "ClusterId": cluster_list, "Node": node_list,
                           "PortID": port_id_list, "PortAlias": alias_list, "TX_Util": tx_util_list,
                           "RX_Util": rx_util_list,
                           "Port_type": type_list})
    df["Site_list"] = [i[3:6] for i in df["Node"]]
    df["TimeStamp"] = [datetime.fromtimestamp(i) for i in df["TimeStamp"]]
    df = df.sort_values(by='TimeStamp', ascending=False)
    return df


def create_reports(fm_dict, hostname, portID, fmuser, fmpasswd):
    response_out = []
    for fm in fm_dict.keys():
        try:
            print(fm)
            session = requests.Session()
            session.auth = (fmuser, fmpasswd)
            auth = session.post('https://' + fm_dict[fm], verify=False)
            response = session.get('https://' + fm_dict[
                fm] + '/api/0.9/elasticUtils/queryIndices?since=1-week&indexPattern=fmstats&fm.tags=%7BhostName%3D' + hostname + '%2CportId%3D' + portID + '%7D&size=10000&queryObjects=port',
                                   verify=False)
            response = response.json()
            response = response[u'hits'][u'hits']
            response_out.extend(response)
        except:
            Print("Data not present")
            pass

    df_out = convert_to_csv(response_out)
    return df_out
