################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################

import os
import socket

from util.logging import getlogger
logger = getlogger(__name__)

###############################################################################
## method: ipv6_to_ipv4, ipv4_to_ipv6
## to convert between simple ipv6 and ipv4
###############################################################################

def ipv6_to_ipv4(ipv6_addr):
    return (ipv6_addr[0].split(":")[-1], ipv6_addr[1])

def ipv4_to_ipv6(ipv4_addr):
    return '::ffff:{}'.format(ipv4_addr)

###############################################################################
## method: get_route
## to get tunnel ip from client overlay address
###############################################################################

import netifaces as ni
if "OVERLAY_IF" not in os.environ:
    logger.error("OVERLAY_IF is not set")
    exit()

from pyroute2 import IPRoute

def get_route(dest_ip, protocol):
    with IPRoute() as ipr:
        if protocol == socket.AF_INET:
            ipv4_addr = dest_ip
        else:
            ipv4_addr = dest_ip.split(":")[-1]
        
        attr_values = ipr.route('get', dst=ipv4_addr)[0]["attrs"]
        for (key,value) in attr_values:
            if key == "RTA_GATEWAY":
                return value
    return None

###############################################################################
## method: transfer_fd
## to transfer fd from router process to overlay process via unix socket
## reference: https://gist.github.com/alanjcastonguay/69148d471bdd1b60ba66d17b26a02afd
###############################################################################

import array
import subprocess
import time

def send_fd(unix_sock, accept_fd, overlay_pid, overlay_fd):
    return unix_sock.sendmsg(["{0},{1}".format(overlay_pid, overlay_fd).encode()], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [accept_fd]))])

def try_connect(unix_sock, path):
    try:
        unix_sock.connect(path)
        return True
    except:
        return False

def transfer_fd(pid, listen_fd, accept_fd):
    path = "/tmp/transfer.sock"
    logger.debug("Transferring {0} to process {3} via {1}, listen{2}.sock".format(accept_fd, path, listen_fd, pid))
    unix_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    max_try = 3
    for c in range(max_try):
        if(try_connect(unix_sock, path)):
            break
        logger.warning("Wait to transfer")
        time.sleep(1)
    if c == max_try:
        logger.warning("Failed to tranfer")
    else:
        send_fd(unix_sock, accept_fd, pid, listen_fd)
        fd = unix_sock.recv(5)
        return int(fd.decode())
    return -1
###############################################################################
## method: update_fd
## 1. update fd and inode list
## 2. check waiting client address (overlay, host)
## 3. if found mapped inode to the inode list in 1, can map to host fd from 1. too
## return 
## - inodes: inode indexed by fd
## - ready map: (pid, overlay fd) --> host fd
## - ready client: clinet overlay address list
###############################################################################

def get_inode(pid, fd):
    try:
        socket_link = os.readlink("/proc/{0}/fd/{1}".format(pid, fd))
        try:
            key, inode = socket_link[0:-1].split(":[")
            if key == "socket":
                return int(inode)
            else:
                return 0
        except:
            return 0
    except FileNotFoundError:
        return -1

def update_fd(pid, addr_in_queue, host_inodes, overlay_fd_map):
    ready_map = dict()
    ready_clients = []
    inodes = [0,0,0]
    fd = 3
    cmp_inode = get_inode(pid, fd)

    try:
        fd_list = [int(fd) for fd in os.listdir("/proc/{}/fd".format(pid))]
        if len(fd_list) == 0:
            return inodes, ready_map, ready_clients
        max_fd = max(fd_list)
    except FileNotFoundError:
        logger.warning("Cannot update fd for {}".format(pid))
        return inodes, ready_map, ready_clients

    while fd <= max_fd:
        inodes.append(cmp_inode)
        fd += 1
        cmp_inode = get_inode(pid, fd)
    logger.debug("Inodes: {}".format(inodes))
    for (client_overlay_addr, client_host_addr) in addr_in_queue.copy():
        target_inode = host_inodes[client_host_addr]
        if target_inode in inodes:
            host_fd = inodes.index(target_inode)
            if client_overlay_addr not in overlay_fd_map:
                continue
            overlay_conn_fd = overlay_fd_map[client_overlay_addr]
            if overlay_conn_fd > 0:
                logger.debug("Found match {0}, {1}".format((pid, overlay_conn_fd), host_fd))
                ready_map[(pid, overlay_conn_fd)] = host_fd
                addr_in_queue.remove((client_overlay_addr, client_host_addr))
                ready_clients.append(client_overlay_addr)
    return inodes, ready_map, ready_clients

###############################################################################
## method: check_poll, get_epoll_fd
## to deal with polling list (In Progress)
###############################################################################

def check_poll(pids, pid):
    for k in pids.keys():
        if pid == k.value:
            return True
    return False

def get_epoll_fd(pid):
    lsof_ps = subprocess.Popen(("lsof", "-p", str(pid)), stdout=subprocess.PIPE)
    grep_ps= subprocess.Popen(("grep", "eventpoll"), stdin=lsof_ps.stdout, stdout=subprocess.PIPE)
    output = subprocess.check_output(("awk", "{{ print $4 }}"), stdin=grep_ps.stdout)
    epfd = output.decode().split("u\n")[0]
    if epfd == "":
        return "0"
    return epfd



###############################################################################
## method: get_info
## to get socket address from pid and fd via network file
###############################################################################
from pandas import read_csv

SOCKET_FILENAME="/proc/net/tcp"
UNKNOWN_ADDR = ("0.0.0.0", -1)

def get_file(pid, fd):
    proc = "/proc/%d/fd/%d" % (pid, fd)
    try:
        return os.readlink(proc)
    except OSError as err:
        return "N/A"

def get_addr(data, inode):
    hexaddr = list(data[data["inode"]==int(inode)]["local_address"])
    if len(hexaddr) == 0:
        return None
    hexaddr = hexaddr[0]
    hexip, hexport = hexaddr.split(":")
    decip = ".".join([str(int(hexip[start_i:start_i+2], 16)) for start_i in range(4)])
    decport = int(hexport, 16)
    return (decip, decport)

def get_socket_data():
    with open(SOCKET_FILENAME, "r") as f:
        data = read_csv(SOCKET_FILENAME, delimiter=r"\s+")
        old_columns = list(data.columns)
        fixed_columns = old_columns[0:4] + [":".join(old_columns[4:6]),":".join(old_columns[6:8])]+ old_columns[8:] + 7*["-"]
        data = data.reset_index()
        data.columns = fixed_columns
    return data[["inode", "local_address"]]

def get_info(pid, fd, socket_data=None):
    link = get_file(pid, fd)
    try:
        socket, inode = link[0:-1].split(":[")
    except:
        return UNKNOWN_ADDR
    if socket != "socket":
        logger.warning("Wrong Input ({0}, {1}): {2} -- Linked file is not socket".format(pid, fd, link))
        return UNKNOWN_ADDR
    if socket_data is None:
        data = get_socket_data()
    addr = get_addr(data, inode)
    if addr is None:
        logger.warning("Wrong Input ({0}, {1}): {2} -- Socket {3} doesn't exist in {4}".format(pid, fd, link, inode, SOCKET_FILENAME))
        return UNKNOWN_ADDR
    return addr

###############################################################################