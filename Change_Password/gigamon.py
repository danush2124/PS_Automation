#!/usr/bin/env python

import argparse
import json
import logging
import os
import re
import requests
import sys
from collections import defaultdict
from requests.packages import urllib3

urllib3.disable_warnings()


def logger(logfile):
    try:
        logger = logging.getLogger(__name__)
        path = "{}/{}".format(os.getcwd(), logfile)
        # file handler
        try:
            handler = logging.FileHandler(path, mode='w')
        except Exception as e:
            handler = logging.FileHandler(os.path.join("/tmp/", logfile), mode='w')

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setFormatter(formatter)
        stdout_handler.setLevel(logging.DEBUG)
        logger.addHandler(stdout_handler)
        logger.setLevel(logging.DEBUG)
        return logger
    except Exception as e:
        raise e


class FM(object):

    def __init__(self, fmip="", user="", password="", logfile=None, certchain=None):
        if not logfile:
            logfile = "{}.log".format(sys.argv[0].split("/")[-1].split(".")[0])
        self.logger = logger(logfile)
        if not fmip or not user or not password:
            self.logger.error("Usage: %s <FM IP> <FM USER> <FM PASSWORD>", sys.argv[0])
            sys.exit(1)
        self.ip = fmip
        self.urlpref = "https://" + fmip + "/api/v1.3"
        self.username = user
        self.password = password
        self.chain = certchain
        self.device_list = []

    def _find_match(self, devicefilter={}, nodes=[]):

        '''
            Returns matching device list (from nodes) that matches all the filter criteria
        '''

        match = []
        for node in nodes:
            try:
                for key, value in devicefilter.items():
                    if value.strip() in node.get(key):
                        if node not in match:
                            match.append(node)
                    else:
                        if node in match:
                            match.remove(node)
                        break

            except KeyError as err:
                pass

        return match

    def add_device_to_FM(self, deviceIp="", deviceUser="", devicePasswd=""):

        clusterId = ""

        if not deviceIp:
            self._create_device_list()

        if not deviceIp or not deviceUser or not devicePasswd:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, deviceUser and devicePasswd")

        url = self.urlpref + '/nodes'

        payload = {
            "nodeAddSpecs": [
                {
                    "nodeAddress": deviceIp,
                    "username": deviceUser,
                    "password": devicePasswd
                }
            ]
        }

        obj = requests.post(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok or obj.status_code == 409:
            return 0
        else:
            self.logger.error("Error while adding device, status_code {}".format(obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def get_device_inventory(self, devicefilter={}):

        '''
            Get device inventory from FM based on the device filter

        Parameters:
            devicefilter: dictionary with one or more of the keys ( 'deviceIp', 'operStatus', 
                          'swVersion', 'hostname', 'clusterMode', 'deviceId', 'healthState', 'model' )

        Return:
            node_list: List of matched devices

        Example:

            out = client.get_device_inventory(devicefilter={'hostname' : 'TA40'})
            out = client.get_device_inventory(devicefilter={'hostname' : 'TA40'})
            out = client.get_device_inventory(devicefilter={'deviceIp': '10.115.32', 'model': 'HD8'})
            out = client.get_device_inventory(devicefilter={'deviceIp': '10.115.32', 'hostname': 'HD8', 'model': 'HD8'})
        '''

        node_list = []
        obj = requests.get(self.urlpref + '/nodes/flat', auth=(self.username, self.password), verify=False)

        if obj.ok:
            js = obj.json()

            if not devicefilter:
                return js.get('nodes')

            node_list = self._find_match(devicefilter, js.get('nodes'))
            return node_list
        else:
            self.logger.error("Error while getting device inventory, status_code {}".format(obj.status_code))
            self.logger.error("{}".format(obj.content))
            return []

    def _create_device_list(self):

        '''
             Creates device list for all the devices managed by FM
        '''

        obj = requests.get(self.urlpref + '/nodes/flat', auth=(self.username, self.password), verify=False)
        if obj.ok:
            js = obj.json()
            for node in js.get('nodes'):
                buf = []
                buf = '{deviceIp}:{hostname}:{clusterId}:{model}:{swVersion}:{clusterMode}:{discOutcome}'.format(**node)
                self.device_list.append(buf)
            return self.device_list
        else:
            raise SystemExit("Error while creating device list, {} {}".format(obj.url, obj.status_code))

    def _get_cluster_id(self, devstr=""):

        '''
             Returns cluster ID from device hostname or ipaddress
        '''

        cluster_id = "None"

        for l in self.device_list:
            if devstr in l:
                m1 = l.split(":")
                cluster_id = m1[2]
                return cluster_id

        return cluster_id

    def _get_port_config(self, port, host):

        '''
            Get portConfig for a particular port
        '''

        obj_port = requests.get(self.urlpref + '/portConfig/portConfigs/' + port + '?clusterId=' + host,
                                auth=(self.username, self.password), verify=False)
        if obj_port.ok:
            port_config = obj_port.json()
            return (port_config)
        else:
            self.logger.error("Error while getting port config, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return {}

    def get_clusterID(self, deviceIp):
        c_id = self._get_cluster_id(deviceIp.strip())
        return c_id

    def get_ports_by_type(self, deviceIp=[], portfilter=[]):

        ''' 

        Get port inventory based on one or more types for the specified device(s)

        Parameters:
            deviceIp: one or more device ip (or) cluster id
            portfilter: one or more of port type ("network" or "tool" or "stack" or "gateway" or "inline-net" or
                   "inline-tool" or "hybrid" or "gigasmart")

        Return:
            match: dictionary of devices and the matching ports by type dictionary (based on the portfilter)

        Example:

            out = client.get_ports_by_type(deviceIp="10.115.32.5")
            out = client.get_ports_by_type(deviceIp="3219")
            out = client.get_ports_by_type(deviceIp="10.115.32.5, 3219", portfilter="network")
            out = client.get_ports_by_type(deviceIp="10.115.32.5, 3219", portfilter="tool, gigasmart")

        '''

        clusters = []
        cluster_ports = {}

        if len(self.device_list) == 0:
            self._create_device_list()

        if deviceIp:
            for node in deviceIp:
                c_id = self._get_cluster_id(node.strip())
                clusters.append(c_id)

        else:
            raise SystemExit("ERROR: Invalid argument for get_ports_by_type")

        for clusterId in clusters:
            ports_by_type = defaultdict(list)
            if clusterId == "None":
                self.logger.error("Invalid clusterId %s", clusterId)
                continue

            obj = requests.get(self.urlpref + '/inventory/ports?clusterId=' + clusterId,
                               auth=(self.username, self.password), verify=False)

            if obj.ok:
                js = json.loads(obj.content.decode('utf-8'))
                portList = []
                portList = js['ports']

                for port in portList:
                    if port['portType'] == "gigasmart":
                        ports_by_type[port['portType']].append(port)
                    else:
                        port_config_dict = {}
                        p_ort = port['portId'].replace('/', '_')
                        port_config_dict = self._get_port_config(p_ort, clusterId)
                        port.update(port_config_dict['portConfig']['alarmThresholds'])
                        port['neighborDiscovery'] = port_config_dict['portConfig']['neighborDiscovery']
                        ports_by_type[port['portType']].append(port)

            else:
                self.logger.error("Error while get ports by type, {} {}".format(obj.url, obj.status_code))
                self.logger.error("{}".format(obj.content))
                return {}

            return_list = []
            if not portfilter:
                for key, value in ports_by_type.items():
                    return_list = return_list + value
                cluster_ports[clusterId] = return_list
            else:
                for f in portfilter:
                    return_list = return_list + ports_by_type[f.strip()]
                cluster_ports[clusterId] = return_list

        return cluster_ports

    def get_port_stats(self, clusterId):
        # self.urlpref=self.urlpref = "https://" + self.fmip + "/api/v1.3"
        obj_port = requests.get(self.urlpref + '/nodeCounters/ports?clusterId=' + clusterId,
                                auth=(self.username, self.password), verify=False)
        if obj_port.ok:
            js = json.loads(obj_port.content.decode('utf-8'))
            # port_stats = obj_port.json()
            return (js)
        else:
            self.logger.error("Error while getting port status, {} {}".format(obj_port.url, obj_port.status_code))
            self.logger.error("{}".format(obj_port.content))
            return {}

    def get_GSport_stats(self, clusterId):
        # self.urlpref=self.urlpref = "https://" + self.fmip + "/api/v1.3"
        obj_GSport = requests.get(self.urlpref + '/nodeCounters/gsGroups?clusterId=' + clusterId,
                                  auth=(self.username, self.password), verify=False)
        if obj_GSport.ok:
            js = json.loads(obj_GSport.content.decode('utf-8'))
            # port_stats = obj_port.json()
            return (js)
        else:
            self.logger.error("Error while getting port status, {} {}".format(obj_GSport.url, obj_GSport.status_code))
            self.logger.error("{}".format(obj_GSport.content))
            return {}

    def get_vport_stats(self, clusterId):
        # self.urlpref=self.urlpref = "https://" + self.fmip + "/api/v1.3"
        obj_port = requests.get(self.urlpref + '/nodeCounters/vports?clusterId=' + clusterId,
                                auth=(self.username, self.password), verify=False)
        if obj_port.ok:
            js = json.loads(obj_port.content.decode('utf-8'))
            # port_stats = obj_port.json()
            return (js)
        else:
            self.logger.error("Error while getting port status, {} {}".format(obj_port.url, obj_port.status_code))
            self.logger.error("{}".format(obj_port.content))
            return {}

    def get_gsGroups_filterFlow(self, clusterId, gs_alias):
        # self.urlpref=self.urlpref = "https://" + self.fmip + "/api/v1.3"
        obj_gsGroup = requests.get(
            self.urlpref + '/gsGroups/' + (gs_alias) + '/flowOpsReport/flowFiltering/summary?clusterId=' + clusterId,
            auth=(self.username, self.password), verify=False)
        if obj_gsGroup.ok:
            js = json.loads(obj_gsGroup.content.decode('utf-8'))
            # port_stats = obj_port.json()
            return (js)
        else:
            self.logger.error("Error while getting port status, {} {}".format(obj_gsGroup.url, obj_gsGroup.status_code))
            self.logger.error("{}".format(obj_gsGroup.content))
            return {}

    def get_chassis_inventory(self, clusterId):
        obj_chassis_inventory = requests.get(self.urlpref + '/inventory/chassis?clusterId=' + clusterId,
                                             auth=(self.username, self.password), verify=False)
        if obj_chassis_inventory.ok:
            js = json.loads(obj_chassis_inventory.content.decode('utf-8'))
            # port_stats = obj_port.json()
            return (js)
        else:
            # self.logger.error("Error while getting chassis status, {} {}".format(obj_chassis_inventory.url, obj_chassis_inventory.status_code))
            # self.logger.error("{}".format(obj_chassis_inventory.content))
            return {}

    def get_port_inventory(self, clusterId):
        obj_port_inventory = requests.get(self.urlpref + '/inventory/ports?clusterId=' + clusterId,
                                          auth=(self.username, self.password), verify=False)
        if obj_port_inventory.ok:
            js = json.loads(obj_port_inventory.content.decode('utf-8'))
            # port_stats = obj_port.json()
            return (js)
        else:
            self.logger.error(
                "Error while getting port status, {} {}".format(obj_port_inventory.url, obj_port_inventory.status_code))
            self.logger.error("{}".format(obj_port_inventory.content))
            return {}

    def get_map_stats(self, clusterId):
        obj_map_stats = requests.get(self.urlpref + '/nodeCounters/maps?clusterId=' + clusterId,
                                     auth=(self.username, self.password), verify=False)
        if obj_map_stats.ok:
            js = json.loads(obj_map_stats.content.decode('utf-8'))
            # port_stats = obj_port.json()
            return (js)
        else:
            self.logger.error(
                "Error while getting port status, {} {}".format(obj_map_stats.url, obj_map_stats.status_code))
            self.logger.error("{}".format(obj_map_stats.content))
            return {}

    def delete_port_stats(self, clusterId):
        # self.urlpref=self.urlpref = "https://" + self.fmip + "/api/v1.3"
        obj = requests.delete(self.urlpref + '/nodeCounters/ports?clusterId=' + clusterId,
                              auth=(self.username, self.password), verify=False)
        if obj.ok:
            return 0
        else:
            self.logger.error("Error while getting port status, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return {}

    def get_port_gdpneighbor(self, clusterId):

        obj_gdp = requests.get(self.urlpref + '/gdp/cluster?clusterId=' + clusterId,
                               auth=(self.username, self.password), verify=False)
        if obj_gdp.ok:
            js = json.loads(obj_gdp.content.decode('utf-8'))
            # port_stats = obj_port.json()
            return (js)
        else:
            self.logger.error("Error while getting port status, {} {}".format(obj_gdp.url, obj_gdp.status_code))
            self.logger.error("{}".format(obj_gdp.content))
            return {}

    def get_port_neighbor(self, clusterId):

        obj = requests.get(self.urlpref + '/neighborDiscovery/cluster?clusterId=' + clusterId,
                           auth=(self.username, self.password), verify=False)
        if obj.ok:
            js = json.loads(obj.content.decode('utf-8'))
            # port_stats = obj_port.json()
            return (js)
        else:
            self.logger.error("Error while getting port status, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return {}

    def get_gsGroups(self, clusterId):

        obj = requests.get(self.urlpref + '/gsGroups?clusterId=' + clusterId, auth=(self.username, self.password),
                           verify=False)
        if obj.ok:
            js = json.loads(obj.content.decode('utf-8'))
            # port_stats = obj_port.json()
            return (js)
        else:
            self.logger.error("Error while getting gsGroups, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return {}

    def get_vPorts(self, clusterId):

        obj = requests.get(self.urlpref + '/vports?clusterId=' + clusterId, auth=(self.username, self.password),
                           verify=False)
        if obj.ok:
            js = json.loads(obj.content.decode('utf-8'))
            # port_stats = obj_port.json()
            return (js)
        else:
            self.logger.error("Error while getting gsGroups, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return {}

    def _expand(self, ports):

        '''
           Expand the dotted or comma separated port ranges to list of ports
        '''

        result = []
        pattern = re.compile(r"^(.*?)(\d+)$")
        if ".." in ports:
            # get the borders and the common reusable part
            borders = [pattern.match(border).groups() for border in ports.split('..')]
            (common_part, start), (_, end) = borders

            for x in range(int(start), int(end) + 1):
                result.append("%s%d" % (common_part, x))

        elif "," in ports.strip():
            result = ports.split(",")

        return result

    def update_portconfig(self, deviceIp="", portId="", neighborDiscovery="none", alarmThreshold=0,
                          alarmThresholdLow=0):

        '''

        Update portConfig properties for the given port

        Parameters:
            deviceIp: device ip
            portId: port id 
            neighborDiscovery: none, all, cdp or lldp (default is "none")
            alarmThreshold: 0 to 100 (default is 0)
            alarmThresholdLow: 0 to 100 (default is 0)

        Return:
            True: For success

        Example:

           ret = client.update_portconfig( deviceIp="10.115.32.5", portId="1/1/x1", portType="network", neighborDiscovery="all", alarmThreshold=90, alarmThresholdLow=10 )

        '''

        if deviceIp and portId:
            clusterId = self._get_cluster_id(deviceIp.strip())
        else:
            raise SystemExit("ERROR: Mandatory arguments deviceIp and portId required")

        payload = {
            "portId": portId,
            "neighborDiscovery": neighborDiscovery,
            "alarmThresholds": {
                "alarmThreshold": alarmThreshold,
                "alarmThresholdLow": alarmThresholdLow
            }
        }

        p_ortId = re.sub("/", "_", portId)
        url = self.urlpref + '/portConfig/portConfigs/' + p_ortId + '?clusterId=' + clusterId

        obj = requests.put(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0
        else:
            self.logger.error("Error while update port config, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def enable_gdp(self, deviceIp="", portId="", neighborDiscovery="none", alarmThreshold=0, alarmThresholdLow=0):

        '''

        Update portConfig properties for the given port

        Parameters:
            deviceIp: device ip
            portId: port id 
            neighborDiscovery: none, all, cdp or lldp (default is "none")
            alarmThreshold: 0 to 100 (default is 0)
            alarmThresholdLow: 0 to 100 (default is 0)

        Return:
            True: For success

        Example:

           ret = client.update_portconfig( deviceIp="10.115.32.5", portId="1/1/x1", portType="network", neighborDiscovery="all", alarmThreshold=90, alarmThresholdLow=10 )

        '''

        if deviceIp and portId:
            clusterId = self._get_cluster_id(deviceIp.strip())
        else:
            raise SystemExit("ERROR: Mandatory arguments deviceIp and portId required")

        payload = {
            "portId": portId,
            "neighborDiscovery": neighborDiscovery,
            "alarmThresholds": {
                "alarmThreshold": alarmThreshold,
                "alarmThresholdLow": alarmThresholdLow
            },
            "egressVlanTag": "none",
            "gdp": true,
            "fec": "default_val"
        }

        p_ortId = re.sub("/", "_", portId)
        url = self.urlpref + '/portConfig/portConfigs/' + p_ortId + '?clusterId=' + clusterId

        obj = requests.put(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0
        else:
            self.logger.error("Error while update port config, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def configure_ports(self, deviceIp, portId, **kwargs):

        ''' 

        Configure single or multiple ports on a given device

        Parameters:
            deviceIp: device ip (or) cluster id
            portId: port id (can be 1/1/x1 or 1/1/x1..1/1/x3 or 1/1/x1,1/1/x2,1/1/x3)
            adminStatus: "up" or "down"

        Return:
            0: For pass
            1: For fail

        Example:

           ret = client.configure_ports(deviceIp="10.115.32.5", portId="1/1/x1", portType="network", adminStatus="up")
           ret = client.configure_ports(deviceIp="10.115.32.5", portId="1/1/x2", portType="tool", adminStatus="up")
           ret = client.configure_ports(deviceIp="10.115.32.5", portId="1/1/x1..1/1/x3", portType="network", adminStatus="up")
           ret = client.configure_ports(deviceIp="10.115.32.5", portId="1/1/x1,1/1/x2,1/1/x3", portType="tool", adminStatus="up")

        '''

        clusterId = ""
        portList = []

        if not self.device_list:
            self._create_device_list()

        if deviceIp and portId:
            clusterId = self._get_cluster_id(deviceIp.strip())
            if "," in portId or ".." in portId:
                portList = self._expand(portId)
            else:
                portList.append(portId)

        else:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, portId and adminStatus required")

        payload = {}

        fail = 0
        for port in portList:

            payload["portId"] = port

            for k, v in kwargs.items():
                if k:
                    payload[k] = v

            p_ort = re.sub("/", "_", port)
            url = self.urlpref + '/inventory/ports/' + p_ort + '?clusterId=' + clusterId
            obj = requests.patch(url=url, auth=(self.username, self.password), data=json.dumps(payload), timeout=60,
                                 verify=False)
            if obj.ok:
                if 'neighborDiscovery' in kwargs.keys() or 'alarmThreshold' in kwargs.keys() or 'alarmThresholdLow' in kwargs.keys():
                    self.update_portconfig(clusterId, portId, neighborDiscovery, alarmThreshold, alarmThresholdLow)
            else:
                self.logger.error("Error while configuring port, {} {}".format(obj.url, obj.status_code))
                self.logger.error("{}".format(obj.content))
                fail += 1

        if fail:
            return 1
        else:
            return 0

    def get_maps_inventory(self, deviceIp=""):

        '''

        Get map inventory from FM for one or more devices

        Parameters:
            deviceIp: device ip (or) cluster id

        Return:
            cluster_maps: dictionary of devices and the list of maps associated with it

        Example:
            out = client.get_maps_inventory(deviceIp="10.115.32.5")
            out = client.get_maps_inventory(deviceIp="3219")
            out = client.get_maps_inventory(deviceIp="10.115.32.5, 3219")

        '''

        clusters = []
        cluster_maps = {}

        if not self.device_list:
            self._create_device_list()

        if deviceIp:
            nodes = deviceIp.split(",")
            for node in nodes:
                c_id = self._get_cluster_id(node.strip())
                clusters.append(c_id)

        else:
            raise SystemExit("ERROR: Invalid argument for get_maps_inventory")

        for clusterId in clusters:
            obj = requests.get(self.urlpref + '/maps?clusterId=' + clusterId, auth=(self.username, self.password),
                               verify=False)

            if obj.ok:
                js = obj.json()
                mapList = []
                mapList = js['maps']
                cluster_maps[clusterId] = mapList

            else:
                self.logger.error("Error while get map inventory, {} {}".format(obj.url, obj.status_code))
                self.logger.error("{}".format(obj.content))
                return {}

        return cluster_maps

    def get_second_level_maps_inventory(self, deviceIp=""):

        '''

        Get map inventory from FM for one or more devices

        Parameters:
            deviceIp: device ip (or) cluster id

        Return:
            cluster_maps: dictionary of devices and the list of maps associated with it

        Example:
            out = client.get_maps_inventory(deviceIp="10.115.32.5")
            out = client.get_maps_inventory(deviceIp="3219")
            out = client.get_maps_inventory(deviceIp="10.115.32.5, 3219")

        '''

        clusters = []
        cluster_maps = {}

        if not self.device_list:
            self._create_device_list()

        if deviceIp:
            nodes = deviceIp.split(",")
            for node in nodes:
                c_id = self._get_cluster_id(node.strip())
                clusters.append(c_id)

        else:
            raise SystemExit("ERROR: Invalid argument for get_maps_inventory")

        for clusterId in clusters:
            obj = requests.get(self.urlpref + '/maps?clusterId=' + clusterId + '&mapTypes=secondLevel',
                               auth=(self.username, self.password), verify=False)

            if obj.ok:
                js = obj.json()
                mapList = []
                mapList = js['maps']
                cluster_maps[clusterId] = mapList

            else:
                self.logger.error("Error while get map inventory, {} {}".format(obj.url, obj.status_code))
                self.logger.error("{}".format(obj.content))
                return {}

        return cluster_maps

    def get_first_level_maps_inventory(self, deviceIp=""):

        '''

        Get map inventory from FM for one or more devices

        Parameters:
            deviceIp: device ip (or) cluster id

        Return:
            cluster_maps: dictionary of devices and the list of maps associated with it

        Example:
            out = client.get_maps_inventory(deviceIp="10.115.32.5")
            out = client.get_maps_inventory(deviceIp="3219")
            out = client.get_maps_inventory(deviceIp="10.115.32.5, 3219")

        '''

        clusters = []
        cluster_maps = {}

        if not self.device_list:
            self._create_device_list()

        if deviceIp:
            nodes = deviceIp.split(",")
            for node in nodes:
                c_id = self._get_cluster_id(node.strip())
                clusters.append(c_id)

        else:
            raise SystemExit("ERROR: Invalid argument for get_maps_inventory")

        for clusterId in clusters:
            obj = requests.get(self.urlpref + '/maps?clusterId=' + clusterId + '&mapTypes=firstLevel',
                               auth=(self.username, self.password), verify=False)

            if obj.ok:
                js = obj.json()
                mapList = []
                mapList = js['maps']
                cluster_maps[clusterId] = mapList

            else:
                self.logger.error("Error while get map inventory, {} {}".format(obj.url, obj.status_code))
                self.logger.error("{}".format(obj.content))
                return {}

        return cluster_maps

    def create_map(self, deviceIp="", payload={}):

        '''

        Get all map aliases for one or more devices from FM.

        Parameters:
           deviceIp: device ip (or) cluster id
           payload: map specific input in dictionary format (like below)

                    data = {
                      'alias': 'test-map-1',
                      'subType': 'byRule',
                      'srcPorts': ['1/1/x1'],
                      'type': 'regular',
                      'dstPorts': ['1/1/x2'],
                      'rules': {
                         'dropRules': [],
                         'passRules': [
                           {
                            'comment': '',
                            'bidi': False,
                            'matches': [{
                              'type': 'ipVer',
                              'value': 'v4'
                            }],
                            'ruleId': 1
                           },
                           {
                            'comment': '',
                            'bidi': False,
                            'matches': [{
                              'type': 'ipVer',
                              'value': 'v6'
                            }],
                            'ruleId': 2
                           }
                         ]
                      }
                    }

        Return:
            True: For success

        Example:
            out = client.create_map(deviceIp="3219", payload=data)
            out = client.create_map(deviceIp="10.115.32.5", payload=data)

        '''

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not payload:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, payload required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/maps?clusterId=' + clusterId

        obj = requests.post(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while creating map, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def get_map_alias_by_device(self, deviceIp=""):

        '''

        Get all map aliases for one or more devices from FM.

        Parameters:
            deviceIp: device ip (or) cluster id

        Return:
            cluster_map_alias: dictionary of devices and the list of maps aliases associated with it

        Example:

            out = client.get_map_alias_by_device(deviceIp="10.115.32.5")
            out = client.get_map_alias_by_device(deviceIp="3219")
            out = client.get_map_alias_by_device(deviceIp="10.115.32.5, 3219")

        '''

        clusters = []
        cluster_map_alias = {}

        if not self.device_list:
            self._create_device_list()

        if deviceIp:
            nodes = deviceIp.split(",")
            for node in nodes:
                c_id = self._get_cluster_id(node.strip())
                clusters.append(c_id)

        else:
            raise SystemExit("ERROR: Invalid argument for get_map_alias_by_device")

        for clusterId in clusters:
            obj = requests.get(self.urlpref + '/maps?clusterId=' + clusterId, auth=(self.username, self.password),
                               verify=False)

            if obj.ok:
                js = obj.json()
                ma_list = []
                map_list = js['maps']
                for m in map_list:
                    for k, v in m.items():
                        if k == "alias":
                            ma_list.append(v)

                cluster_map_alias[clusterId] = ma_list

            else:
                self.logger.error("Error while get map alias by device, {} {}".format(obj.url, obj.status_code))
                self.logger.error("{}".format(obj.content))
                return {}

        return cluster_map_alias

    def get_map_by_alias(self, deviceIp="", map_alias=""):

        '''

        Get map details for a specified device from FM

        Parameters:
            deviceIp: device ip (or) cluster id
            map_alias: map alias

        Return:
            map_dict: map details in dictionary format

        Example:
            out = client.get_map_by_alias(deviceIp="10.115.32.5", map_alias="testMap")
            out = client.get_map_by_alias(deviceIp="3219", map_alias="testMap")

        '''

        clusterId = ""
        map_dict = {}
        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not map_alias:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, map_alias required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/maps/' + map_alias + '?clusterId=' + clusterId

        obj = requests.get(url=url, auth=(self.username, self.password), verify=False)

        if obj.ok:
            js = obj.json()
            map_dict = js.get('map')
            return map_dict

        else:
            self.logger.error("Error while get map by alias, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return {}

    def update_map(self, deviceIp="", map_alias="", payload={}):

        '''

        Incremental updates to an existing map

        Parameters:
            deviceIp: device ip (or) cluster id
            map_alias: map alias
            payload:

                    data = {
                      'alias': 'test-map-1',
                      'subType': 'byRule',
                      'srcPorts': ['1/1/x1'],
                      'type': 'regular',
                      'dstPorts': ['1/1/x2'],
                      'rules': {
                         'dropRules': [],
                         'passRules': [
                           {
                            'comment': '',
                            'bidi': False,
                            'matches': [{
                              'type': 'ipVer',
                              'value': 'v4'
                            }],
                            'ruleId': 1
                           },
                           {
                            'comment': '',
                            'bidi': False,
                            'matches': [{
                              'type': 'ipVer',
                              'value': 'v6'
                            }],
                            'ruleId': 2
                           }
                         ]
                      }
                    }

        Return:
            True: For success
            
        Example:

            out = client.update_map(deviceIp="3219", payload=data)
            out = client.update_map(deviceIp="10.115.32.5", payload=data)

        '''

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not map_alias or not payload:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, map_alias and payload required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/maps/' + map_alias + '?clusterId=' + clusterId

        obj = requests.patch(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while updating map, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def add_map_rule(self, deviceIp="", map_alias="", rule_type="pass", payload={}):

        '''

        Using FM, add rules to an existing map on a device

        Parameters:
            deviceIp: device ip (or) cluster id
            map_alias: map alias
            payload: map rule specific input in dictionary format (like below)

                    data = {
                      'ruleId': 3,
                      'comment': '',
                      'bidi': False,
                      'matches': [
                        {
                          'type': 'macSrc',
                          'value': '00:11:22:33:44:55'
                        }
                      ]
                    }

        Return:
            True: For success

        Example:
           ret = client.add_map_rules(deviceIp="10.115.32.5", map_alias="Map_RSA_Traffic", payload=data)

        '''

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not map_alias or not payload:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, map_alias and payload required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/maps/' + map_alias + '/rules/' + rule_type + '?clusterId=' + clusterId

        obj = requests.post(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while adding map rule, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def create_gigastream(self, deviceIp="", alias=None, ports=None):

        clusterId = ""
        portList = []

        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not alias or ports is None:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, alias and ports required")

        if "," in ports or ".." in ports:
            portList = self._expand(ports)
        else:
            portList.append(ports)

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/portConfig/gigastreams?clusterId=' + clusterId

        payload = {
            "alias": alias,
            "ports": portList
        }

        # print(payload)

        obj = requests.post(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while creating gigastream, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def update_gigastream(self, deviceIp="", alias=None, ports=None):

        clusterId = ""
        portList = []

        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not alias or ports is None:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, alias and ports required")

        if "," in ports or ".." in ports:
            portList = self._expand(ports)
        else:
            portList.append(ports)

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/portConfig/gigastreams/' + alias + '?clusterId=' + clusterId

        payload = {
            "alias": alias,
            "ports": portList
        }

        # print(payload)

        obj = requests.patch(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while updating gigastream, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def delete_gigastream(self, deviceIp=None, alias=None):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not alias:
            raise SystemExit("ERROR: Mandatory arguments deviceIp and alias required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/portConfig/gigastreams/' + alias + '?clusterId=' + clusterId

        obj = requests.delete(url=url, auth=(self.username, self.password), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while deleting gigastreams, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def get_gigastream(self, deviceIp=""):

        '''
 
        Using FM, get the list of gigastreams configured on one ore more devices

        Parameters:
            deviceIp: device ip (or) cluster id

        Return:
            device_gigasmart: dictionary of devices and the list of gigastreams associated with it

        Example:
            out = client.get_gigastream(deviceIp="10.115.32.5")
            out = client.get_gigastream(deviceIp="3219")
            out = client.get_gigastream(deviceIp="10.115.32.5, 3219")
        '''

        clusters = []
        device_gigasmart = {}

        if not self.device_list:
            self._create_device_list()

        if deviceIp:
            nodes = deviceIp.split(",")
            for node in nodes:
                c_id = self._get_cluster_id(node.strip())
                clusters.append(c_id)

        else:
            raise SystemExit("ERROR: Invalid argument for get_gigastream")

        for clusterId in clusters:
            obj = requests.get(self.urlpref + '/portConfig/gigastreams?clusterId=' + clusterId,
                               auth=(self.username, self.password), verify=False)

            if obj.ok:
                js = obj.json()
                gsList = []
                gsList = js['gigastreams']
                device_gigasmart[clusterId] = gsList

            else:
                self.logger.error("Error while getting gigastream, {} {}".format(obj.url, obj.status_code))
                self.logger.error("{}".format(obj.content))
                return {}

        return device_gigasmart

    def create_stacklink(self, deviceIp=None, alias=None, type=None, endpoint1=None, endpoint2=None):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not alias or not type or not endpoint1 or not endpoint2:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, alias, endpoint1, endpoint2 required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/portConfig/stackLinks?clusterId=' + clusterId

        payload = {
            "clusterId": clusterId,
            "alias": alias,
            "type": type,
            "endpoint1": endpoint1,
            "endpoint2": endpoint2
        }

        obj = requests.post(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while creating stackLinks, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def delete_stacklink(self, deviceIp=None, alias=None):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not alias:
            raise SystemExit("ERROR: Mandatory arguments deviceIp and alias required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/portConfig/stackLinks/' + alias + '?clusterId=' + clusterId

        obj = requests.delete(url=url, auth=(self.username, self.password), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while deleting stack link, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def create_spinelink(self, deviceIp=None, alias=None, gigastreams=None):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not alias or not gigastreams:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, alias and gigastreams required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/spineLinks?clusterId=' + clusterId

        payload = {
            "alias": alias,
            "gigastreams": [gigastreams]
        }

        obj = requests.post(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while creating spineLinks, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def update_spinelink(self, deviceIp=None, alias=None, gigastreams=None):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not alias or not gigastreams:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, alias and gigastreams required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/spineLinks/' + alias + '?clusterId=' + clusterId

        payload = {
            "alias": alias,
            "gigastreams": [gigastreams]
        }

        obj = requests.patch(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while updating spineLinks, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def delete_spinelink(self, deviceIp=None, alias=None):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not alias:
            raise SystemExit("ERROR: Mandatory arguments deviceIp and alias required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/spineLinks/' + alias + '?clusterId=' + clusterId

        obj = requests.delete(url=url, auth=(self.username, self.password), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while deleting spine link, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def delete_all_spinelink(self, deviceIp=None):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp:
            raise SystemExit("ERROR: Mandatory arguments deviceIp required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/spineLinks?clusterId=' + clusterId

        obj = requests.delete(url=url, auth=(self.username, self.password), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while deleting all spine links, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def create_gsgroup(self, deviceIp="", alias="", ports=None):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not alias or ports is None:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, alias and ports required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/gsGroups?clusterId=' + clusterId

        payload = {
            "alias": alias,
            "ports": [ports]
        }

        obj = requests.post(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while creating gsgroup, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def create_vport(self, deviceIp="", alias="", gsGroup="", exporters=[]):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not gsGroup:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, gsGroup required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/vports?clusterId=' + clusterId

        payload = {
            "alias": alias,
            "gsGroup": gsGroup
        }

        if len(exporters):
            d = {
                "metadataMonitoring": {
                    "action": "enable",
                    "exporters": exporters
                }
            }
            payload.update(d)

        obj = requests.post(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while creating vport, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def create_gsop_apf(self, deviceIp="", alias="", gsGroup=""):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not gsGroup:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, gsGroup required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/gsops?clusterId=' + clusterId

        payload = {
            "alias": alias,
            "gsGroup": gsGroup,
            "gsApps": {
                "apf": {
                    "enabled": "enabled"
                }
            }
        }

        obj = requests.post(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while creating gsop, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def create_gsop_metadata(self, deviceIp="", alias="", gsGroup="", cache=""):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not gsGroup:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, gsGroup, alias, cache required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/gsops?clusterId=' + clusterId

        payload = {
            "alias": alias,
            "gsGroup": gsGroup,
            "gsApps": {
                "metadataExport": {
                    "cache": cache
                }
            }
        }

        obj = requests.post(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while creating gsop metadata, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def create_tunnel_port(self, deviceIp, tunnelPort, tunnelIp, tunnelIPMask, tunnelGW, gsGroup=""):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not gsGroup:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, gsGroup required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/portConfig/tunneledPorts?clusterId=' + clusterId

        payload = {
            "portId": tunnelPort,
            "gsGroup": gsGroup,
            "ipAddress": tunnelIp,
            "ipMask": tunnelIPMask,
            "gateway": tunnelGW,
            "mtu": 1500,
        }

        obj = requests.post(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while creating tunnel port, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def create_apps_exporter(self, deviceIp, alias, exporter_type, tunnelPort, tunnelDestIp, appProfiles):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not tunnelPort:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, tunnelPort required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/apps/metadata/exporters?clusterId=' + clusterId

        payload = {}

        if exporter_type == "monitor":
            l4PortDst = 2056
        elif exporter_type == "cef":
            l4PortDst = 514

        payload = {
            "alias": alias,
            "type": exporter_type,
            "description": "",
            "applicationProfiles": [appProfiles],
            "cef": {
                "activeTimeout": 1800,
                "inactiveTimeout": 15
            },
            "destination": {
                "dscp": 0,
                "ipv4Address": tunnelDestIp,
                "l4PortDst": l4PortDst,
                "l4PortSrc": 65432,
                "l4Protocol": "udp",
                "ttl": 64
            },
            "monitor": {
                "timeout": 60
            },
            "netflow": {
                "activeTimeout": 1800,
                "inactiveTimeout": 15,
                "templateRefresh": 1,
                "version": "ipfix"
            },
            "snmp": {
                "enabled": False
            },
            "source": {
                "tunnelPort": tunnelPort
            }
        }

        obj = requests.post(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while creating exporter, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def create_apps_cache(self, deviceIp, alias, exporters):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, tunnelPort required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/apps/metadata/cache?clusterId=' + clusterId

        payload = {
            "match": {
                "transport": {
                    "srcPort": True,
                    "dstPort": True
                },
                "ipv4": {
                    "protocol": True,
                    "source": {
                        "address": True
                    },
                    "destination": {
                        "address": True
                    }
                },
                "ipv6": {
                    "nextHeader": True,
                    "source": {
                        "address": True
                    },
                    "destination": {
                        "address": True
                    }
                }
            },
            "exporters": [exporters],
            "networkProfiles": [],
            "alias": alias,
            "description": "",
            "event": "none",
            "flowBehavior": "bidir",
            "size": {
                "flows": 1
            },
            "timeout": {
                "idle": 1800
            }
        }

        obj = requests.post(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while creating metadata cache, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def create_application_profile(self, deviceIp, alias):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not alias:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, alias required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/apps/metadata/applicationProfiles?clusterId=' + clusterId

        payload = {
            "alias": alias, "description": "", "type": "export", "applications": [{"name": "dns",
                                                                                   "attributes": [{"name": "ancount"},
                                                                                                  {"name": "arcount"},
                                                                                                  {"name": "class"},
                                                                                                  {"name": "flags"},
                                                                                                  {"name": "host"},
                                                                                                  {"name": "host-addr"},
                                                                                                  {
                                                                                                      "name": "host-class"},
                                                                                                  {"name": "host-raw"},
                                                                                                  {"name": "host-type"},
                                                                                                  {
                                                                                                      "name": "krb5-enc-data"},
                                                                                                  {
                                                                                                      "name": "krb5-enc-data-type"},
                                                                                                  {
                                                                                                      "name": "krb5-err-cname-name"},
                                                                                                  {
                                                                                                      "name": "krb5-err-cname-type"},
                                                                                                  {
                                                                                                      "name": "krb5-err-crealm"},
                                                                                                  {
                                                                                                      "name": "krb5-err-data"},
                                                                                                  {
                                                                                                      "name": "krb5-err-realm"},
                                                                                                  {
                                                                                                      "name": "krb5-err-sname-name"},
                                                                                                  {
                                                                                                      "name": "krb5-err-sname-type"},
                                                                                                  {
                                                                                                      "name": "krb5-err-text"},
                                                                                                  {
                                                                                                      "name": "krb5-error-code"},
                                                                                                  {
                                                                                                      "name": "krb5-kdcoptions"},
                                                                                                  {
                                                                                                      "name": "krb5-message-type"},
                                                                                                  {
                                                                                                      "name": "krb5-pa-data-type"},
                                                                                                  {
                                                                                                      "name": "krb5-pa-data-value-buffer"},
                                                                                                  {
                                                                                                      "name": "krb5-realm"},
                                                                                                  {
                                                                                                      "name": "krb5-server"},
                                                                                                  {
                                                                                                      "name": "krb5-service"},
                                                                                                  {
                                                                                                      "name": "krb5-ticket-enc-part"},
                                                                                                  {
                                                                                                      "name": "krb5-ticket-name"},
                                                                                                  {
                                                                                                      "name": "krb5-ticket-name-type"},
                                                                                                  {"name": "name"},
                                                                                                  {"name": "opcode"},
                                                                                                  {"name": "qdcount"},
                                                                                                  {"name": "query"}, {
                                                                                                      "name": "query-type"},
                                                                                                  {
                                                                                                      "name": "reply-code"},
                                                                                                  {
                                                                                                      "name": "response-time"},
                                                                                                  {
                                                                                                      "name": "reverse-addr"},
                                                                                                  {
                                                                                                      "name": "transaction-id"},
                                                                                                  {"name": "ttl"}, {
                                                                                                      "name": "tunneling"}]},
                                                                                  {"name": "http",
                                                                                   "attributes": [{"name": "code"},
                                                                                                  {"name": "host"},
                                                                                                  {"name": "method"},
                                                                                                  {"name": "rtt"},
                                                                                                  {"name": "server"}, {
                                                                                                      "name": "server-agent"},
                                                                                                  {
                                                                                                      "name": "smb-client"},
                                                                                                  {"name": "uri"}, {
                                                                                                      "name": "uri-decoded"},
                                                                                                  {"name": "uri-full"},
                                                                                                  {"name": "uri-path"},
                                                                                                  {
                                                                                                      "name": "uri-path-decoded"},
                                                                                                  {
                                                                                                      "name": "user-agent"},
                                                                                                  {"name": "version"}]},
                                                                                  {"name": "krb5",
                                                                                   "attributes": [{"name": "login"}]},
                                                                                  {"name": "rdp", "attributes": [
                                                                                      {"name": "default-username"},
                                                                                      {"name": "username-ascii"},
                                                                                      {"name": "username-raw"}]},
                                                                                  {"name": "ssl", "attributes": [
                                                                                      {"name": "cipher-suite-id"},
                                                                                      {"name": "common-name"},
                                                                                      {"name": "issuer"},
                                                                                      {"name": "validity-not-after"},
                                                                                      {"name": "validity-not-before"}]},
                                                                                  {"name": "telnet",
                                                                                   "attributes": [{"name": "login"},
                                                                                                  {"name": "password"},
                                                                                                  {"name": "rtt"}, {
                                                                                                      "name": "term-type"}]}],
            "applicationId": False, "flow": {"endReason": True},
            "timestamp": {"flowEndMsec": True, "flowEndsec": False, "flowStartMsec": True, "flowStartsec": False,
                          "sysUpTimeFirst": False, "sysUpTimeLast": False},
            "ipv4": {"destination": {"address": False}, "dscp": False,
                     "fragmentation": {"flags": False, "id": False, "offset": False}, "headerLen": False,
                     "optionMap": False, "precedence": False, "protocol": True, "source": {"address": False},
                     "tos": False, "totalLength": False, "ttl": False}, "transport": {"dstPort": True,
                                                                                      "icmp": {"ipv4Code": False,
                                                                                               "ipv4Type": False,
                                                                                               "ipv6Code": False,
                                                                                               "ipv6Type": False},
                                                                                      "srcPort": True,
                                                                                      "tcp": {"ackNumber": False,
                                                                                              "dstPort": False,
                                                                                              "flags": False,
                                                                                              "headerLen": False,
                                                                                              "seqNumber": False,
                                                                                              "srcPort": False,
                                                                                              "urgentPtr": False,
                                                                                              "windowSize": False},
                                                                                      "udp": {"dstPort": False,
                                                                                              "msgLen": False,
                                                                                              "srcPort": False}}
        }

        obj = requests.post(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while creating application profile, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def update_gsgroup_params(self, deviceIp="", gsgroup_alias=""):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp:
            raise SystemExit("ERROR: Mandatory arguments deviceIp or clusterId and gsgroup_alias")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/gsGroups/' + gsgroup_alias + '/params?clusterId=' + clusterId

        payload = {
            "resource": {
                "metadata": 1
            }
        }

        obj = requests.patch(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while updating map, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def create_exporter(self, deviceIp, tunnelPort, alias, tunnelDestIp):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp or not tunnelPort:
            raise SystemExit("ERROR: Mandatory arguments deviceIp, tunnelPort required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/apps/metadata/exporters?clusterId=' + clusterId

        payload = {
            "alias": alias,
            "type": "monitor",
            "description": "",
            "cef": {
                "activeTimeout": 1800,
                "inactiveTimeout": 15
            },
            "destination": {
                "dscp": 0,
                "ipv4Address": tunnelDestIp,
                "l4PortDst": 2056,
                "l4PortSrc": 65432,
                "l4Protocol": "udp",
                "ttl": 64
            },
            "monitor": {
                "timeout": 60
            },
            "netflow": {
                "activeTimeout": 1800,
                "inactiveTimeout": 15,
                "templateRefresh": 1,
                "version": "ipfix"
            },
            "snmp": {
                "enabled": False
            },
            "source": {
                "tunnelPort": tunnelPort
            }
        }

        obj = requests.post(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while creating exporter, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def clear_device_config(self, deviceIp="", keepStack="false"):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp:
            raise SystemExit("ERROR: Mandatory arguments deviceIp required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + '/system/config/traffic?clusterId=' + clusterId + '&keepStack=' + keepStack

        obj = requests.delete(url=url, auth=(self.username, self.password), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while clearing device config, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def rediscover_cluster(self, deviceIp=""):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp:
            raise SystemExit("ERROR: Mandatory arguments deviceIp required")

        clusterId = self._get_cluster_id(deviceIp.strip())

        url = self.urlpref + 'nodes?clusterId=' + clusterId

        obj = requests.put(url=url, auth=(self.username, self.password), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while rediscovering cluster {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1

    def update_node_credential(self, deviceIp, username, password):

        clusterId = ""
        if not self.device_list:
            self._create_device_list()

        if not deviceIp:
            raise SystemExit("ERROR: Mandatory arguments deviceIprequired")

        url = self.urlpref + '/nodeCredentials/' + deviceIp

        payload = {
            "deviceAddress": deviceIp,
            "httpUsername": username,
            "httpPassword": password,
            "hostname": "string",
            "snmpVersion": "v2"
        }

        obj = requests.patch(url=url, auth=(self.username, self.password), data=json.dumps(payload), verify=False)

        if obj.ok:
            return 0

        else:
            self.logger.error("Error while updating spineLinks, {} {}".format(obj.url, obj.status_code))
            self.logger.error("{}".format(obj.content))
            return 1


if __name__ == '__main__':
    gigamon()
