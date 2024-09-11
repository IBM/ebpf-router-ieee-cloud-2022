################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################

############################################
# data:
#     r0: |
#       type=cidr
#       from="172.17.0.0/18"
#       to="172.17.0.0/18"
#     r1: |
#       type=cidr
#       from="172.17.22.64/26"
#       to="172.17.63.64/26"
#       reverse=True
#     r2: |
#       type=podLabel
#       name=app
#       value=network-intense
#     r3: |
#       type=nodeLabel --> map to cidr by operator
###########################################

###############################################################

import os
import sys
import json
import subprocess
import stat
import threading

from util.logging import getlogger
logger = getlogger(__name__)


if "DISABLE_LABEL_FILTER" not in os.environ:
    DISABLE_LABEL_FILTER=1
else:
    DISABLE_LABEL_FILTER=int(os.environ["DISABLE_LABEL_FILTER"])


LABEL="ebpf-grafting-enable"
LABEL_VALUE="true"

if "CONTAINER_LABEL" in os.environ:
    LABEL=os.environ["CONTAINER_LABEL"]
if "CONTAINER_LABEL_VALUE" in os.environ:
    LABEL_VALUE=os.environ["CONTAINER_LABEL_VALUE"]

MAX_CACHED_CONTAINER=100
MAX_CACHED_POD=100
ROOT_DIRECTORIES=["/sys/fs/cgroup/pids/kubepods/besteffort","/sys/fs/cgroup/pids/kubepods/burstable"]

########################################################################
## Label Filter: Pod/Container

def get_container_info(id_num):
    try:
        out = subprocess.check_output(["crictl", "inspect", id_num], stderr=subprocess.STDOUT)
        logger.debug("Get container info: {}".format(id_num))
        return json.loads(out)
    except subprocess.CalledProcessError:
        return None

def get_pod_info(id_num):
    try:
        out = subprocess.check_output(["crictl", "inspectp", id_num], stderr=subprocess.STDOUT)
        logger.debug("Get pod info: {}".format(id_num))
        return json.loads(out)
    except subprocess.CalledProcessError:
        return None

def validate_label(container_info):
    if container_info is None:
        return "false"
    if LABEL in container_info["status"]["labels"]:
        return container_info["status"]["labels"][LABEL]
    return "false"

def list_pid(container_path):
    proc_path = container_path+"/cgroup.procs"
    if not os.path.exists(proc_path):
        return []
    try:
        with open(proc_path, "r") as f:
            pids = f.read().splitlines()
            return pids
    except:
        return []


class LabelFilter():
    def __init__(self, invalid_containers, container_path_map, pod_map, label_name, label_value, pod_level=True):
        self.invalid_containers = invalid_containers
        self.container_path_map = container_path_map
        self.pod_map = pod_map
        self.label_name = label_name
        self.label_value = label_value
        self.pod_level = pod_level


    def filter(self, pid):
        for _, pid_list in self.container_path_map.items():
            if str(pid) in pid_list:
                return True
        return self._try_find_new_container(str(pid))

    def _check_invalid(self, pid):
        for container_dir in self.invalid_containers:
            pid_list = list_pid(container_dir)
            if pid in pid_list:
                return False


    def _validate_label(self, container_info):
        if container_info is None:
            return False
        if self.pod_level:
            pod_id = container_info["info"]["sandboxID"]
            if pod_id not in self.pod_map:
                info = get_pod_info(pod_id)
                if info is not None:
                    self.pod_map[pod_id] = info
                else:
                    # cannot find pod
                    return False
            else:
                info = self.pod_map[pod_id]
        else:
            info == container_info
        
        if self.label_name in info["status"]["labels"]:
            return info["status"]["labels"][self.label_name] == self.label_value
        return False

    def _try_find_new_container(self, pid):
        for directory in ROOT_DIRECTORIES:
            for pod_path in os.listdir(directory):
                pod_dir = "/".join([directory,pod_path])
                if "pod" not in pod_path or not os.path.isdir(pod_dir):
                    continue
                
                for container_path in os.listdir(pod_dir):
                    valid = False
                    container_dir = "/".join([pod_dir, container_path])
                    if os.path.isdir(container_dir):
                        if container_path not in self.invalid_containers:
                            if container_path not in self.container_path_map.keys():
                                container_info = get_container_info(container_path)
                                if container_info is not None and self._validate_label(container_info):
                                    valid = True
                            else:
                                valid = True

                        pid_list = list_pid(container_dir)
                        if valid:
                            self.container_path_map[container_path] = pid_list
                            if pid in pid_list:
                                return True
                            else:
                                continue

                        self.invalid_containers.append(container_path)
                        if pid in pid_list:
                            return False
        return False

        if len(self.container_path_map) > MAX_CACHED_CONTAINER:
            self._garbage_collect()
        return False

    def _garbage_collect(self):
        to_remove_list = []
        for container_path in self.container_path_map.keys():
            if get_container_info(container_path) is None:
                to_remove_list.append(container_path)
        logger.info("Garbage collect {}".format(to_remove_list))
        for container_path in to_remove_list:
            del self.container_path_map[container_path]
            self.invalid_containers.remove(container_path)

########################################################################
## Address Filter

############## overlay address checking #####################

from socket import AF_INET, AF_INET6
def binary_to_dec(binary):
    return int(binary, 2)

ANY_ADDRESS="0.0.0.0"
SERVICE_DOMAIN_ADDRESS="172.21.0.1"
IPV6_ANY_ADDRESS="::"
LOCAL_ADDRESS="127.0.0.1"

HOST_IF = "ens3"
if "HOST_IF" in os.environ:
    HOST_IF = os.environ["HOST_IF"]

import netifaces as ni
HOST_ADDRESS = ni.ifaddresses(HOST_IF)[ni.AF_INET][0]['addr']


def get_mask(cidr):
    overlay_mask_addr, overlay_mask_count = cidr.split("/")
    overlay_mask_count = int(overlay_mask_count)
    overlay_mask_str = "".join([str(1)]*overlay_mask_count+[str(0)]*(32-overlay_mask_count))
    overlay_mask_addr_split = overlay_mask_addr.split(".")
    overlay_mask_int = [binary_to_dec(overlay_mask_str[8*i:8*i+8])&int(overlay_mask_addr_split[i]) for i in range(0,4)]
    return overlay_mask_addr, overlay_mask_int, overlay_mask_count

def is_local_addr(addr):
    if addr == LOCAL_ADDRESS or addr == SERVICE_DOMAIN_ADDRESS:
        return True
    return False

def is_any_addr(addr, protocol): # for listenning
    if (protocol == AF_INET6 and addr == IPV6_ANY_ADDRESS) or addr == ANY_ADDRESS or addr is None:
        return True
    return False

def check_addr(addr, protocol, cidr):
    if is_any_addr(addr, protocol):
        return True

    if is_local_addr(addr):
        return False
    
    overlay_mask_addr, overlay_mask_int, overlay_mask_count = get_mask(cidr)

    if protocol == AF_INET6: 
        addr = addr.split("::ffff:")[1] # IPV6 in the form ::ffff:[IPV4]

    addr_split = addr.split(".")
    for i in range(4):
        if overlay_mask_count >= 8:
            if overlay_mask_int[i] != int(addr_split[i]):
                return False
            overlay_mask_count -= 8
        else:
            return overlay_mask_int[i]&int(addr_split[i]) == overlay_mask_int[i]
    return False


class AddressFilter():

    def __init__(self, from_cidr, to_cidr):
        self.from_cidr = from_cidr
        self.to_cidr = to_cidr
    
    def filter(self, from_overlay_addr, to_overlay_addr, protocol):
        from_valid = check_addr(from_overlay_addr, protocol, self.from_cidr)
        if to_overlay_addr is not None:
            to_valid = check_addr(to_overlay_addr, protocol, self.to_cidr)
        else:
            to_valid = True
        return from_valid and to_valid

########################################################################################
## High-level Part

class CIDRFilter():
    def __init__(self, name, ruler, config):
        self.name = name
        from_cidr = config["from"].replace('"','')
        to_cidr = config["to"].replace('"','')
        self.addr_filter = AddressFilter(from_cidr, to_cidr)
        if "reverse" in config:
            self.reverse = bool(config["reverse"])
        else:
            self.reverse = False
        
    def filter(self, pid, from_overlay_addr, to_overlay_addr, protocol):
        if self.addr_filter.filter(from_overlay_addr, to_overlay_addr, protocol):
            return True
        if self.reverse and self.addr_filter.filter(to_overlay_addr, from_overlay_addr, protocol):
            return True
        return False

    def summary(self):
        return "CIDR Filter {0}: from (server) {1} to (client) {2} (reverse={3})\n".format(self.name, self.addr_filter.from_cidr, self.addr_filter.to_cidr, self.reverse)

class PodLabelFilter():
    def __init__(self, name, ruler, config):
        self.name = name
        label_name = config["name"]
        label_value = config["value"]
        self.label_filter = LabelFilter(ruler.invalid_containers, ruler.container_path_map, ruler.pod_map, label_name, label_value, pod_level=True)

    def filter(self, pid, from_overlay_addr, to_overlay_addr, protocol):
        return self.label_filter.filter(pid)

    def summary(self):
        return "Pod Filter {0}: {1}={2}\n".format(self.name, self.label_filter.label_name, self.label_filter.label_value)

class ContainerLabelFilter():
    def __init__(self, name, ruler, config):
        self.name = name
        label_name = config["name"].replace('"','')
        label_value = config["value"].replace('"','')
        self.label_filter = LabelFilter(ruler.invalid_containers, ruler.container_path_map, ruler.pod_map, label_name, label_value, pod_level=False)

    def filter(self, pid, from_overlay_addr, to_overlay_addr, protocol):
        return self.label_filter.filter(pid)

    def summary(self):
        return "Container Filter {0}: {1}={2}\n".format(self.name, self.label_filter.label_name, self.label_filter.label_value)


RULE_MAP = {"cidr": CIDRFilter, "podLabel": PodLabelFilter, "containerLabel": ContainerLabelFilter}

def get_configs(folder, name):
    configs = dict()
    with open(folder + "/" + name) as f:
        lines = f.readlines()
        for line in lines:
            k, v = line.strip().split("=")
            configs[k] = v
    return configs

class Ruler():

    def __init__(self, config_folder):
        self.invalid_containers = []
        self.container_path_map = dict()
        self.pod_map = dict()

        self.filter_rules = []
        self.validate_rules = []

        logger.debug("Base Filter Addresses: {}".format([addr for addr in [LOCAL_ADDRESS, SERVICE_DOMAIN_ADDRESS, HOST_ADDRESS]]))

        if not os.path.exists(config_folder):
            logger.warning("No rule configured: {}".format(config_folder))
        else:
            filename = [name for name in os.listdir(config_folder) if os.path.isfile(config_folder + "/" + name)]
            for name in filename:
                config = get_configs(config_folder, name)
                
                rule = RULE_MAP[config["type"].replace('"','')](name, self, config)
                if isinstance(rule, CIDRFilter):
                    self.validate_rules.append(rule)
                else:
                    self.filter_rules.append(rule)

    def _self_filter(self, from_overlay_addr, to_overlay_addr):
        for addr in [LOCAL_ADDRESS, SERVICE_DOMAIN_ADDRESS, HOST_ADDRESS]:
            if addr in from_overlay_addr or (to_overlay_addr is not None and addr in to_overlay_addr):
                return False
        return True

    # return pass/fail condition    
    def filter(self, pid, from_overlay_addr, to_overlay_addr, protocol):
        if not self._self_filter(from_overlay_addr, to_overlay_addr):
            return False

        filtered = False
        for rule in self.filter_rules:
            filtered = rule.filter(pid, from_overlay_addr, to_overlay_addr, protocol)
            if filtered:
                logger.debug("Filtered by Rule {0} for pid={1},from={2},to={3}".format(rule.name, pid, from_overlay_addr, to_overlay_addr))
                break

        if filtered or len(self.filter_rules) == 0:
            if len(self.validate_rules) == 0:
                return True
            for rule in self.validate_rules:
                validated = rule.filter(pid, from_overlay_addr, to_overlay_addr, protocol)
                if validated:
                    logger.debug("Validated by Rule {0} for pid={1},from={2},to={3}".format(rule.name, pid, from_overlay_addr, to_overlay_addr))
                    return True
        # logger.debug("No matching rule for pid={0},from={1},to={2}".format(pid, from_overlay_addr, to_overlay_addr))
        return False

    def summary(self):
        out = "Filter Rules\n"
        for rule in self.filter_rules:
            out += rule.summary()
        out += "Validate Rules\n"
        for rule in self.validate_rules:
            out += rule.summary()
        return out

########################################################################################


if __name__ == "__main__":
    from subprocess import check_output

    # def get_pid(name):
    #     return check_output(["pidof",name]).decode().strip()
    # pid = get_pid("iperf3")
    # config_folder = "/root/eBPF-Router/python-test/rules"
    # ruler = Ruler(config_folder)
    # res = ruler.filter(pid, "172.17.63.94", "172.17.30.145", AF_INET)
    # logger.debug(ruler.summary())
    
    addr_filter = AddressFilter("172.17.23.64/26", "172.17.0.128/26")
    res = addr_filter.filter("172.17.23.110", "172.17.0.187", AF_INET)
    print(res)

