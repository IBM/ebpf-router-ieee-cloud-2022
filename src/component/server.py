################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################

#######################################################################
## server.py
## 
## steps:
## 1. act as dumb server listening for new connection
## 2. transfer accepted socket to overlay process
## 3. call ptrace duplication when mapping information is ready which can be
## either of the following cases
## 3.1 when get client info and inode is ready (handle coordinate data)
## 3.2 when inode is read and has client info (handle recv msg)
##
## components:
## - utility method in socket_info
##
## environments: 
## - ROUTER_LOGLEVEL (default: WARNING)
##
#######################################################################

import traceback

from util.socket_info import transfer_fd, update_fd, ipv6_to_ipv4, ipv4_to_ipv6, get_route, get_inode
import socket
from socket import SOCK_STREAM, AF_INET, AF_INET6
import netifaces as ni
import os
import threading

import logging
import sys

from util.logging import getlogger
logger = getlogger(__name__)

SERVER_SYNC_PORT = "0"

class ServerThread(threading.Thread):

    def __init__(self, duplicator, server_overlay_addr, server_overlay_pid, server_overlay_fd, listen_backlog, protocol, interface):
        threading.Thread.__init__(self) 
        self.protocol = protocol
        self.socket = socket.socket(protocol, SOCK_STREAM)
        ipaddr = ni.ifaddresses(interface)[protocol][0]['addr']
        bind_addr = socket.getaddrinfo(ipaddr, None, protocol, socket.SOCK_STREAM, 0, socket.AI_PASSIVE)[0][4]
        if protocol == AF_INET6:
            ipv4_addr = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
            bind_addr = (ipv4_to_ipv6(ipv4_addr), bind_addr[1], bind_addr[2], bind_addr[3])
        self.socket.bind(bind_addr)
        self.socket.listen(listen_backlog)
        self.addr = self.socket.getsockname()
        self.overlay_addr = server_overlay_addr
        self.overlay_pid = server_overlay_pid
        self.overlay_fd = server_overlay_fd

        self.client_host_fds = dict() # client host address -> host fd
        self.client_overlay_fds = dict() # client overlay ipv4 address --> accept overlay fd
        self.client_fd_overlay_addr = dict() # client accept overlay fd --> client overlay ipv4 address
        self.client_inode = dict() # client overlay address --> inode
        self.client_in_queue = [] # client overlay address without host connection
        self.inode_in_queue = [] # inode values indexed by fd of overlay process

        self.ready_map = dict()

        self.stop_event = threading.Event() 
        self.delay_accept_client = dict()

        self.duplicator = duplicator

        logger.debug("Create socket {0} ({1}) for {2}-{3}".format(self.addr, self.socket.fileno(), self.overlay_pid, self.overlay_fd))

    # client host addr --> inode
    def run(self):
        logger.info("Server is listening {0},{1}".format(self.overlay_pid, self.overlay_fd))
        self.socket.settimeout(1)
        try:
            while True:
                if self.stop_event.isSet():
                    break
                try:
                    client, client_host_addr = self.socket.accept()
                except socket.timeout:
                    continue
                
                # transfer to overlay process
                detached_tid = self.duplicator.transferring_start(self.overlay_pid)
                host_fd = transfer_fd(detached_tid, self.overlay_fd, client.fileno())
                if host_fd < 0:
                    logger.warning("Transferring failed (host fd < 0)")
                else:
                    self.client_host_fds[client_host_addr] = host_fd
                    logger.debug("Accept client {0} host fd: {1}".format(client_host_addr, host_fd))
                    
                    if client_host_addr in self.delay_accept_client:
                        client_overlay_addr = self.delay_accept_client[client_host_addr]
                        del self.delay_accept_client[client_host_addr]
                        self.save_accept_host_client(client_overlay_addr, client_host_addr)
                self.duplicator.transferring_done(self.overlay_pid)
                client.close()
        except Exception as err:
            logger.warning("Server {0} error: {1}".format(self.overlay_pid, err))
            traceback.print_exc()
        finally:
            self.socket.close()
            logger.debug("Close dummy server of {0}".format(self.overlay_addr))

    def stop(self):
        for client_fd in self.client_fd_overlay_addr.keys():
            self.duplicator.terminate_duplicate_from_overlay_pid_fd((self.overlay_pid, int(client_fd)))
        self.duplicator.terminate_duplicate_from_overlay_pid_fd((self.overlay_pid, self.overlay_fd))
        self.stop_event.set()

    def handle_close(self, client_fd):
        if client_fd in self.client_fd_overlay_addr.keys():
            self.duplicator.terminate_duplicate_from_overlay_pid_fd((self.overlay_pid, int(client_fd)))
            del self.client_fd_overlay_addr[client_fd]
            return True
        return False
    
    # called when coordinator handle accept (overlay addr <--> overlay fd)
    def save_accept_overlay_fd(self, client_overlay_addr, accept_overlay_fd):
        client_ipv4_addr = ipv6_to_ipv4(client_overlay_addr)
        self.client_overlay_fds[client_ipv4_addr] = accept_overlay_fd
        self.client_fd_overlay_addr[accept_overlay_fd] = client_ipv4_addr
        overlay_inode = get_inode(self.overlay_pid, accept_overlay_fd)
        assert overlay_inode > 0, "overlay inode is not valid: {}".format(overlay_inode)
        self.client_inode[client_ipv4_addr] = overlay_inode
        

    # called when cooridnator handle client info (client overlay addr <--> client host addr)
    # call duplication if ready
    def save_accept_host_client(self, client_overlay_addr, client_host_addr): 
        if client_host_addr in self.client_host_fds:
            host_fd = self.client_host_fds[client_host_addr]
            overlay_accept_fd = self._get_overlay_accept_fd(client_overlay_addr)
            assert overlay_accept_fd != -1, "overlay accept fd should be found at this state (overlay accept then host can send addr and accept)"
            overlay_pid_fd = (self.overlay_pid, overlay_accept_fd)
            pair_ip = get_route(client_overlay_addr[0], AF_INET)
            self._call_duplicate(overlay_pid_fd, host_fd, client_overlay_addr, pair_ip)
        else: # server has not accept yet
            self.delay_accept_client[client_host_addr] = client_overlay_addr

    def _get_overlay_accept_fd(self, client_overlay_addr):
        if client_overlay_addr not in self.client_overlay_fds:
            return -1
        return self.client_overlay_fds[client_overlay_addr]

    def _call_duplicate(self, overlay_pid_fd, host_fd, client_overlay_addr, pair_ip):
        overlay_inode = self.client_inode[client_overlay_addr]
        dup_args = (overlay_pid_fd, overlay_inode, host_fd, 1, client_overlay_addr, SERVER_SYNC_PORT, pair_ip)
        self.duplicator.insert_duplicate(dup_args)

        if overlay_pid_fd in self.ready_map:
            del self.ready_map[overlay_pid_fd]  

