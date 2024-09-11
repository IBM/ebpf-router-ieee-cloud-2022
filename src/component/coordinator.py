################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################

#######################################################################
## coordinator.py
## 
## data plane: mainly handle the following events
## - listen: create server thread for newly detected pid, listen fd
## - accept: send corresponding host server address to client coordinator
## - connect: call client manager to manage connect 
##            send client host address to corresponding server coordinator 
##            (if connection found) 
## - recvmsg: call clinet manager to manage recvmsg
##            call corresponding server to manage recvmsg
##
## control place: communicate between hosts 
## SERVER --> CLIENT --> SERVER_READY
## - SERVER: call client manager to manage server info
##           send client host address to corresponding server coordinator 
##           (if connection found)       
## - CLIENT: find and call corresponding server to save accepted host client
## - SERVER READY: call client manager to manage server ready
##
## components:
## - ServerThread: respond to listen, accept events for each server
## - ClientManager: manage all connect events
## - utility method in socket_info
##
## environments: 
## - ROUTER_LOGLEVEL (default: WARNING)
## - HOST_IF (default: ens3)
##
#######################################################################

import socket
from socket import AF_INET, AF_INET6, SOCK_STREAM
import netifaces as ni

from component.server import ServerThread
from component.client_manager import ClientManager
from component.duplicator import Duplicator

from util.socket_info import ipv6_to_ipv4, get_route

import os
import sys
import pickle
import enum
import threading
import queue

from util.logging import getlogger
logger = getlogger(__name__)


HOST_IF = "ens3"
if "HOST_IF" in os.environ:
    HOST_IF = os.environ["HOST_IF"]

BUFFER_SIZE=1024
MAX_CACHED_PIDS=100

class CoordinateType(enum.IntEnum):
    SERVER=0
    CLIENT=1

class ConnectInfo:
    # overlay mapping info
    def __init__(self, server_addr, client_addr):
        self.saddr = server_addr
        self.caddr = client_addr

class ServerInfo:
    # server host address with connect info
    def __init__(self, addr, server_overlay_addr, client_overlay_addr, protocol):
        if protocol == AF_INET6:
            client_overlay_addr = ipv6_to_ipv4(client_overlay_addr)
        self.server = addr
        self.overlay = ConnectInfo(server_overlay_addr, client_overlay_addr)

class ClientInfo:
    # client host address with corresponding server info
    def __init__(self, client_host_addr, server_info):
        self.chost = client_host_addr
        self.sinfo = server_info

class CoordinateData:
    def __init__(self, coordinate_type, coordinate_info):
        self.type = coordinate_type
        self.info = coordinate_info

#################### Coordinator Thread ###############################

class CoordinatorThread(threading.Thread):

## Data Plane 

    def __init__(self, port, interface, rw_memo_map, set_opt_detail_map):
        threading.Thread.__init__(self) 
        self.port = port
        logger.info("Overlay IF: {}".format(interface))
        try:
            self.socket = socket.socket(AF_INET, SOCK_STREAM)
            self.ipaddr = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
            self.socket.bind((self.ipaddr,self.port))
            logger.debug("Create Coordinator Listen at {0}:{1}".format(self.ipaddr,port))
        except socket.error as err:
            logger.error("Socket creating and binding failed with error: {}".format(err))

        self.duplicator = Duplicator(rw_memo_map, set_opt_detail_map)
        self.client_manager = ClientManager(self.duplicator)
        self.host_servers = dict() # (pid) --> server map (listen fd --> ServerThread)

        self.accept_addr_fd_map = dict() # server overlay address -> (pid, fd)

        self.recv_lock = threading.Lock()
        self.server_info_lock = threading.Lock()
        self.client_info_lock = threading.Lock()

        self.stop_event = threading.Event() 

        self.request_queue = queue.Queue()

    def _remove_server(self, pid, fd):
        self.host_servers[pid][fd].stop()
        self.host_servers[pid][fd].join()
        del self.host_servers[pid][fd]

    def _garbage_collect(self):
        if len(self.host_servers) > MAX_CACHED_PIDS:
            logger.debug("Clean host servers")
            for pid in self.host_servers.keys():
                if not os.path.exists("/proc/{}".format(pid)):
                    for fd in self.host_server[pid].keys():
                        self._remove_server(pid, fd)
                    del self.host_servers[pid]
        if len(self.client_manager.dummy_clients) > MAX_CACHED_PIDS:
            logger.debug("Clean clients")
            for pid in self.client_manager.dummy_clients.keys():
                if not os.path.exists("/proc/{}".format(pid)):
                    del self.client_manager.dummy_clients[pid]
        
    def handle_listen(self, server_overlay_addr, server_overlay_pid, server_overlay_fd, listen_backlog, protocol):
        with self.client_info_lock:
            logger.debug("Handle Listen {}".format((server_overlay_pid, server_overlay_fd, listen_backlog)))
    
            if server_overlay_pid in self.host_servers and server_overlay_fd in self.host_servers[server_overlay_pid]:
                self._remove_server(server_overlay_pid, server_overlay_fd) # close the previous listen 

            host_server = ServerThread(self.duplicator, server_overlay_addr, server_overlay_pid, server_overlay_fd, listen_backlog, protocol, interface=HOST_IF)
            if server_overlay_pid not in self.host_servers:
                self.host_servers[server_overlay_pid] = dict()
            self.host_servers[server_overlay_pid][server_overlay_fd] = host_server
            host_server.start()
    
    def handle_accept(self, server_overlay_pid, listen_overlay_fd, accept_overlay_fd, server_overlay_addr, client_overlay_addr, protocol):
        with self.client_info_lock:
            logger.debug("Handle Accept {}".format((server_overlay_pid, listen_overlay_fd, accept_overlay_fd, server_overlay_addr, client_overlay_addr)))
            # get host server address
            if server_overlay_pid not in self.host_servers or listen_overlay_fd not in self.host_servers[server_overlay_pid]:
                logger.warning("Server is not listening ({0},{1})".format(server_overlay_pid, listen_overlay_fd))
                return
            host_server = self.host_servers[server_overlay_pid][listen_overlay_fd]
            self.host_servers[server_overlay_pid][listen_overlay_fd].save_accept_overlay_fd(client_overlay_addr, accept_overlay_fd)
            self.accept_addr_fd_map[server_overlay_addr] = (server_overlay_pid, listen_overlay_fd)
            server_host_addr = host_server.addr
            # create coordinate data
            server_info = ServerInfo(server_host_addr, server_overlay_addr, client_overlay_addr, protocol)
            send_data = CoordinateData(CoordinateType.SERVER, server_info)
            (client_overlay_ip,_) = client_overlay_addr
        self.send_to_router(send_data, client_overlay_ip, protocol)

    def handle_connect(self, client_overlay_pid, client_overlay_fd, client_overlay_addr, server_overlay_addr, protocol):
        logger.debug("Handle Connect {}".format((client_overlay_pid, client_overlay_fd, client_overlay_addr, server_overlay_addr)))
        with self.server_info_lock:
            if protocol == AF_INET6:
                client_overlay_addr = ipv6_to_ipv4(client_overlay_addr)
            (client_host_addr, protocol), server_info = self.client_manager.manage_overlay_connect(client_overlay_pid, client_overlay_fd, client_overlay_addr)
        if client_host_addr is not None:
            self.send_client_info_to_router(server_info, client_host_addr, protocol)

    def handle_close(self, pid, fd):
        logger.info("Handle Close {0}, {1}".format(pid,fd))
        if not self.client_manager.manage_close(pid, fd):
            if pid in self.host_servers:
                if fd in self.host_servers[pid]:
                    self._remove_server(pid, fd)
                else:
                    for host_server in self.host_servers[pid].values():
                        if host_server.handle_close(fd):
                            break

## Control Plane

    def send_to_router(self, send_data, destination_overlay_ip, protocol):
        send_msg = pickle.dumps(send_data)
        destination_gateway = get_route(destination_overlay_ip, protocol)
        info_msg = "Send data {0} to {1} with {2}".format(send_data.type, (destination_overlay_ip, self.port), (destination_gateway, self.port))
        logger.debug(info_msg)
        if destination_gateway == None:
            res = self._handle(send_data, self.ipaddr)
        else:
            try_count = 0
            while try_count < 3:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as coor_client:
                    try:
                        coor_client.connect((destination_gateway, self.port))
                        coor_client.sendall(send_msg)
                    except:
                        try_count += 1 
                        continue
                break

    def send_client_info_to_router(self, server_info, client_host_addr, protocol):
        client_info = ClientInfo(client_host_addr, server_info)
        send_data = CoordinateData(CoordinateType.CLIENT, client_info)
        (server_overlay_ip, _) = server_info.overlay.saddr
        self.send_to_router(send_data, server_overlay_ip, protocol)

    def _handle(self, data, pair_ip):
        if data.type == CoordinateType.SERVER: # client work
            info_msg = "Handle Server Info: {0}, overlay-{1}".format(data.info.server, data.info.overlay.caddr)
            logger.debug(info_msg)
            with self.server_info_lock:
                client_host_addr_proto = self.client_manager.manage_server_info(data.info)
                logger.debug("Client Host Address: {0}".format(client_host_addr_proto))
            if client_host_addr_proto is not None:
                (client_host_addr, protocol) = client_host_addr_proto
                self.send_client_info_to_router(data.info, client_host_addr, protocol)
        elif data.type == CoordinateType.CLIENT: # server work
            info_msg = "Handle Client Info:" + str([data.info.sinfo.overlay.saddr, data.info.sinfo.overlay.caddr, data.info.sinfo.server, data.info.chost])
            logger.debug(info_msg)
            server_overlay_addr = data.info.sinfo.overlay.saddr
            if server_overlay_addr in self.accept_addr_fd_map:
                (server_overlay_pid, server_overlay_fd) = self.accept_addr_fd_map[server_overlay_addr]
                if server_overlay_pid in self.host_servers and server_overlay_fd in self.host_servers[server_overlay_pid]:
                    host_server = self.host_servers[server_overlay_pid][server_overlay_fd]
                    host_server.save_accept_host_client(data.info.sinfo.overlay.caddr, data.info.chost)
                else:
                    logger.warning("Cannot find host {}".format(server_overlay_addr))
            else:
                logger.warning("Cannot find host {}".format(server_overlay_addr))
        else:
            logger.warning("Wrong coordiante data: {}".format(data))

    def process_request(self):
        while True:
            (ipaddr, port, msg) = self.request_queue.get()
            self._garbage_collect()
            if ipaddr is None:
                break
            try:
                data = pickle.loads(msg)
                self._handle(data, ipaddr)
            except (TypeError, pickle.UnpicklingError) as typeerr:
                info_msg = "Handle Server Ready: {}".format(msg)
                logger.debug(info_msg)
                try:
                    client_overlay_ip, client_overlay_port, sync_port_str = msg.decode("utf-8").split(",")
                except Exception as error: 
                    self.running = False
                    logger.exception("Cannot process coordinate data: {}".format(typeerr))
                    continue
                
                client_overlay_addr  = (client_overlay_ip, int(client_overlay_port))
                self.client_manager.manage_server_ready(client_overlay_addr, sync_port_str, ipaddr)
        logger.warning("Request process thread dies")
        
    def run(self):
        threading.Thread(target=self.process_request).start()
        self.socket.listen(128)
        self.socket.settimeout(1)
        logger.info("Coordinator is listening")
        try:    
            while True:
                if self.stop_event.isSet():
                    logger.info("Coordinator is stopped, Please wait")
                    break
                try:
                    client, (ipaddr, port) = self.socket.accept()
                except socket.timeout:
                    continue
                with client:
                    msg = client.recv(BUFFER_SIZE)
                    self.request_queue.put((ipaddr, port, msg))
        finally:
            self.request_queue.put((None, None, None))
            self.clear()
            logger.warning("Coordinator closed")

    def stop(self):
        self.stop_event.set()

    def release_lock(self, lock):
        try:
            lock.release()
        except:
            pass

    def clear(self):
        pid_list = list(self.host_servers.keys())
        for pid in pid_list:
            fd_list = list(self.host_servers[pid].keys())
            for fd in fd_list:
                self._remove_server(pid, fd)
        self.release_lock(self.client_manager.fd_update_lock)
        self.release_lock(self.recv_lock)
        self.release_lock(self.server_info_lock)
        self.release_lock(self.client_info_lock)
        self.socket.close()
        self.duplicator.clear()

#######################################################################