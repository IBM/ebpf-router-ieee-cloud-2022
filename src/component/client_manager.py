################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################

#######################################################################
## client_manager.py
## 
## 1. create connection when server host address and client overlay fd are available
## 1.1 when handle server info and overlay already connects (manage server info)
## 1.2 when handle overlay connect and server info already received (manage overlay connect)
## 2. duplicate sockets 
## 2.1 when get server ready signal and transfer is complete (manage server ready)
## 2.2 when has an update from recvmsg and ready signal is already received  (manage recvmsg)
##
## components:
## - DummyClient: individually create connection and keep fd map information
## - utility method in socket_info
##
## environments: 
## - ROUTER_LOGLEVEL (default: WARNING)
##
#######################################################################


from util.socket_info import transfer_fd, update_fd,  get_route, get_inode
import os
import socket
from socket import AF_INET, AF_INET6, SOCK_STREAM

import threading

import logging
import sys

from util.logging import getlogger
logger = getlogger(__name__)

def server_protocol(server_host_addr):
    if ":" in server_host_addr[0]:
        return AF_INET6
    return AF_INET

class DummyClient():
    def __init__(self, pid, duplicator):
        self.overlay_pid = pid
        self.overlay_fd_map = dict()
        self.fd_overlay_map = dict()
        self.addr_in_queue = [] # (client overlay addr, client host addr)
        self.host_fds = dict()
        self.duplicator = duplicator

    # (client overlay fd <--> client overlay addr)
    def set_fd_map(self, client_overlay_fd, client_overlay_addr):
        self.overlay_fd_map[client_overlay_addr] = client_overlay_fd
        self.fd_overlay_map[client_overlay_fd] = client_overlay_addr

    # create socket and connect to server host address
    # (client overlay addr <--> client overlay fd <--> host inode)
    def create_connection(self, client_overlay_fd, client_overlay_addr, server_host_addr):
        logger.debug("Create connection {0}->{1}".format(client_overlay_addr, server_host_addr))
        protocol = server_protocol(server_host_addr)
        client_sock = socket.socket(protocol, SOCK_STREAM)
        try:
            client_sock.connect(server_host_addr)
            
            client_host_addr =  client_sock.getsockname()
            dummy_fd =  client_sock.fileno()
            inode =  os.stat(dummy_fd).st_ino
            
            detached_tid = self.duplicator.transferring_start(self.overlay_pid)
            host_fd = transfer_fd(detached_tid, client_overlay_fd, dummy_fd)
            self.duplicator.transferring_done(self.overlay_pid)
            if host_fd < 0:
                logger.warning("Transferring failed (host fd < 0)")
                return None
            else:
                self.host_fds[client_overlay_fd] = host_fd
                logger.debug("Connect server {0} host fd: {1}".format(server_host_addr, host_fd))
                return (client_host_addr, protocol)
        except ConnectionRefusedError:
            logger.warning("Cannot connect to host server")
            return None

    def close_fd(self, fd):
        if fd not in self.fd_overlay_map:
            return
        closed_client_overlay = self.fd_overlay_map[fd]
        for (client_overlay_addr, client_host_addr) in self.addr_in_queue:
            if client_overlay_addr == closed_client_overlay:
                self.addr_in_queue.remove((client_overlay_addr, client_host_addr))
                if client_overlay_addr in self.host_fds:
                    del self.host_fds[client_overlay_addr]
                break
        if closed_client_overlay in self.overlay_fd_map:
            del self.overlay_fd_map[closed_client_overlay]
        del self.fd_overlay_map[fd]


##################################################
## 
## inode_map: used for handling fd overwritten
##
##
class ClientManager():
    def __init__(self, duplicator):
        self.dummy_clients = dict()
        self.server_host_adrr_map = dict()
        self.server_info_map = dict()
        self.overlay_pid_fd_map = dict()
        self.inode_map = dict()
        self.delay_ready_clients = dict()
        self.duplicator = duplicator

        self.fd_update_lock = threading.Lock()

    def manage_overlay_connect(self, client_overlay_pid, client_overlay_fd, client_overlay_addr):
        if client_overlay_pid not in self.dummy_clients:
            new_client = DummyClient(client_overlay_pid, self.duplicator)
            self.dummy_clients[client_overlay_pid] = new_client

        self.dummy_clients[client_overlay_pid].set_fd_map(client_overlay_fd, client_overlay_addr)
        self.overlay_pid_fd_map[client_overlay_addr] = (client_overlay_pid, client_overlay_fd)
        self.inode_map[client_overlay_addr] = get_inode(client_overlay_pid, client_overlay_fd)

        if client_overlay_addr in self.server_info_map: # server info before overlay connect
            server_info = self.server_info_map[client_overlay_addr]
            client_host_addr_proto = self._call_create_connection(self.dummy_clients[client_overlay_pid], client_overlay_fd, client_overlay_addr, server_info.server)
            if client_host_addr_proto is None: # cannot connect host server
                return (None, None), None

            del self.server_info_map[client_overlay_addr]
            return client_host_addr_proto, server_info

        logger.debug("No server info registered for {}".format(client_overlay_addr))
        return (None, None), None # never get server info before

    def manage_server_info(self, server_info):
        client_overlay_addr = server_info.overlay.caddr
        for _, client in self.dummy_clients.items(): 
            if client_overlay_addr in client.overlay_fd_map: # overlay connect before server info
                client_overlay_fd = client.overlay_fd_map[client_overlay_addr]
                client_host_addr_proto = self._call_create_connection(client, client_overlay_fd, client_overlay_addr, server_info.server)
                return client_host_addr_proto
        logger.debug("Register server info to {}".format(client_overlay_addr))
        self.server_info_map[client_overlay_addr] = server_info
        return None

    def manage_server_ready(self, client_overlay_addr, sync_port_str, pair_ip):
        if client_overlay_addr not in self.overlay_pid_fd_map:
            logger.debug("Add {} to delay list".format(overlay_pid_fd))
            self.delay_ready_clients[overlay_pid_fd] = (client_overlay_addr, sync_port_str, pair_ip)
        else:
            overlay_pid_fd = self.overlay_pid_fd_map[client_overlay_addr]
            logger.debug("Server Ready for {0} ({1})".format(client_overlay_addr, overlay_pid_fd))
            self._call_duplicate(overlay_pid_fd, client_overlay_addr, int(sync_port_str), pair_ip)

    def manage_close(self, pid, fd):
        self.duplicator.terminate_duplicate_from_overlay_pid_fd((pid, fd))
        if pid not in self.dummy_clients:
            return False
        self.dummy_clients[pid].close_fd(fd)
        return True

    def _call_create_connection(self, client, client_overlay_fd, client_overlay_addr, server_info_server):
        client_host_addr_proto = client.create_connection(client_overlay_fd, client_overlay_addr, server_info_server)
        overlay_pid_fd = (client.overlay_pid, client_overlay_fd)
        if overlay_pid_fd in self.delay_ready_clients:
            (client_overlay_addr, sync_port_str, pair_ip) = self.delay_ready_clients[overlay_pid_fd]
            del self.delay_ready_clients[overlay_pid_fd]
            self._call_duplicate(overlay_pid_fd, client_overlay_addr, sync_port_str, pair_ip)
        return client_host_addr_proto
    

    def _call_duplicate(self, overlay_pid_fd, client_overlay_addr, sync_port_str, pair_ip):
        (pid, overlay_fd) = overlay_pid_fd
        if pid in self.dummy_clients:
            client = self.dummy_clients[pid]
            if overlay_fd in client.host_fds:
                host_fd = client.host_fds[overlay_fd]
                overlay_inode = self.inode_map[client_overlay_addr]
                dup_args = (overlay_pid_fd, overlay_inode, host_fd, 0, client_overlay_addr, sync_port_str, pair_ip)
                self.duplicator.insert_duplicate(dup_args)
            else:
                logger.debug("Add {} to delay list".format(overlay_pid_fd))
                self.delay_ready_clients[overlay_pid_fd] = (client_overlay_addr, sync_port_str, pair_ip)
        else:
            logger.warning("Cannot find client {} for duplication".format(pid))