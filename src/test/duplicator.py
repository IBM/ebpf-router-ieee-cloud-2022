################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################

import unittest

import os
import sys
import time

################# environment set ######################

def set_or_init(key, value):
    if key not in os.environ:
        os.environ[key] = value
        return value
    else:
        return os.environ[key]

ROUTER_PORT = int(set_or_init("ROUTER_PORT", "1234"))
OVERLAY_IF = set_or_init("OVERLAY_IF", "vxlan.calico")
TRACE_ALL_THREADS = bool(set_or_init("TRACE_ALL_THREADS", "True"))
NO_INTRA_HOST_DUP = bool(set_or_init("NO_INTRA_HOST_DUP", "True"))
ROUTER_LOGLEVEL = set_or_init("ROUTER_LOGLEVEL", "WARNING")
BPF_SOKCNAME_ENABLE = bool(set_or_init("BPF_SOKCNAME_ENABLE", "False"))
BPF_PEERNAME_ENABLE = bool(set_or_init("BPF_PEERNAME_ENABLE", "False"))
BPF_RW_MEMO_ENABLE = bool(set_or_init("BPF_RW_MEMO_ENABLE", "True"))
ROUTER_TOP_FOLDER = set_or_init("ROUTER_TOP_FOLDER", "/root/eBPF-Router")

BUFFER_SIZE=1024
LOCAL_ADDRESS="127.0.0.1"
OVERLAY_SERVER_PORT=1235


import random
import string
def generate_random_message(n):
    return "".join([random.choice(string.ascii_letters) for _ in range(n)])

fixed_message = bytes(generate_random_message(BUFFER_SIZE), 'ascii')


import netifaces as ni
TUNNEL_IP = ni.ifaddresses(os.environ["OVERLAY_IF"])[ni.AF_INET][0]['addr']

import util

#######################################
## Mockup Flow:
## Dummy Server/Client connected --> Duplicate at server
## --> Dummy Client Coordinator --> Duplicate at client
##
## Mockup Components:
##      Dummy Server:
##          - create one mock-up host fd
##          - create another mock-up overlay fd to listen and accept connection at port 1235
##          - activate duplication with local pair ip
##      Dummy Client:
##          - create one mock-up host fd
##          - create another mock-up overlay fd to connect to port 1235
##      Dummy Client Coordinator:
##          - listen to common port 1234 
##          - activate duplication with local pair ip
##
#######################################
from multiprocessing import Process, JoinableQueue, Manager
import threading
import string


import socket




SERVER_NODELAY = 0
CLIENT_NODELAY = 15



class DetailIndex:
    def __init__(self, pid, fd, optname):
        self.pid = pid
        self.fd =fd
        self.optname = optname

class DetailValue:
    def __init__(self, level, optval, optlen):
        self.level =level
        self.optval = optval
        self.optlen = optlen




def coordinator_task(notify_queue, shared_dict):
    try:
        coor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        address = (TUNNEL_IP, ROUTER_PORT)
        assert coor_socket.connect_ex(address) != 0, "Port is already in-use"
        coor_socket.bind(address)
        coor_socket.listen()
        notify_queue.put(True)
        client, _ = coor_socket.accept()
        msg = client.recv(BUFFER_SIZE)
        print(msg)
        client_overlay_ip, client_overlay_port, sync_port_str = msg.decode("utf-8").split(",")
        shared_dict["sync_port_str"] = sync_port_str
    finally:
        coor_socket.close()
        try:
            client.close()
        except:
            pass
        print("Coordinator Task End")

def simple_server_task(notify_queue, shared_dict):
    host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    overlay_listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    address = (LOCAL_ADDRESS, OVERLAY_SERVER_PORT)
    assert overlay_listen_socket.connect_ex(address) != 0, "Port is already in-use"
    overlay_listen_socket.bind(address)
    overlay_listen_socket.listen()
    notify_queue.put(host_socket.fileno())
    client, _ = overlay_listen_socket.accept()
    client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, SERVER_NODELAY)
    print("Server port = ", client.getsockname())
    print("Get server sockopt before = ", client.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))
    shared_dict["server_overlay_fd"] = client.fileno()
    try:
        while True:
            client.send(fixed_message)
            client.recv(BUFFER_SIZE)
            time.sleep(1)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            host_socket.close()
        except:
            pass
        print("Get server sockopt after = ", client.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))
        overlay_listen_socket.close()
        client.close()
        print("Server Task End")

def select_server_task(notify_queue, shared_dict, backlog):
    host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    overlay_listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    address = (LOCAL_ADDRESS, OVERLAY_SERVER_PORT)
    assert overlay_listen_socket.connect_ex(address) != 0, "Port is already in-use"
    overlay_listen_socket.bind(address)
    overlay_listen_socket.listen(backlog)
    notify_queue.put(host_socket.fileno())



def client_task(notify_queue):
    host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    overlay_connect_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    overlay_connect_socket.connect((LOCAL_ADDRESS, OVERLAY_SERVER_PORT))
    overlay_connect_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, CLIENT_NODELAY)
    print("Client port = ", overlay_connect_socket.getsockname())
    print("Get client sockopt before = ", overlay_connect_socket.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))
    notify_queue.put((host_socket.fileno(), overlay_connect_socket.fileno()))
    try:
        while True:
            overlay_connect_socket.recv(BUFFER_SIZE)
            overlay_connect_socket.send(fixed_message)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            host_socket.close()
        except:
            pass
        print("Get client sockopt after = ", overlay_connect_socket.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))
        overlay_connect_socket.close()
        print("Client Task End")

def base_scenario(shared_dict):
    notify_queue = JoinableQueue()
    server = Process(target=simple_server_task, args=(notify_queue, shared_dict, ))
    server.start()
    ## wait for server ready
    (server_host_fd) = notify_queue.get()
    client = Process(target=client_task, args=(notify_queue,))
    client.start()
    ## wait for client ready
    (client_host_fd, client_overlay_fd)= notify_queue.get()

    while "server_overlay_fd" not in shared_dict:
        time.sleep(1)
        print("Wait for server_overlay_fd available")
            

    server_overlay_fd = shared_dict["server_overlay_fd"]
    coordinator = Process(target=coordinator_task, args=(notify_queue, shared_dict, ))
    coordinator.start()
    ## wait for coordinator ready
    notify_queue.get()
    notify_queue.close()
    return server, client, coordinator, (server_host_fd, server_overlay_fd), (client_host_fd, client_overlay_fd)


def call_insert(dupthread, overlay_pid_fd, host_fd, server, pair_ip, sync_port):
    overlay_inode = util.get_inode(overlay_pid_fd[0], overlay_pid_fd[1])
    tid_specific = overlay_pid_fd[0]
    client_overlay_addr_str = "0.0.0.0,0"
    dupthread.insert_all(overlay_pid_fd, overlay_inode, host_fd, server, pair_ip, sync_port, client_overlay_addr_str, tid_specific)


from pt.tracer import TracerConnector
from pt.static import ProcessCommand

class TestHandler(unittest.TestCase):

    def test_connect(self):
        mgr = Manager()
        shared_dict = mgr.dict()
        server, client, coordinator, (server_host_fd, server_overlay_fd), (client_host_fd, client_overlay_fd) = base_scenario(shared_dict)
        server_pid = server.pid
        handler = TracerConnector(server_pid)
        try:
            assert handler.process != None, "Fail to create process"
            assert handler.connected, "Handler is not connected"
            cmd = ProcessCommand.UPDATE_PROCESSING_TIDS
            args = [server_pid]
            success, ret = handler.request(cmd, args)
            assert success, "Fail to update processing tids tid"
            assert ret != None, "Wrong return"
        finally:
            handler.terminate()
            coordinator.terminate()
            coordinator.join()
            client.terminate()
            client.join()
            server.terminate()
            server.join()

from pt.ptrace_dup import PtraceDupThread
from pt.static import ThreadState

class TestDupThread(unittest.TestCase):

    def test_init(self):
        mgr = Manager()
        shared_dict = mgr.dict()
        try:
            handler_lock = threading.Lock()
            server, client, coordinator, (server_host_fd, server_overlay_fd), (client_host_fd, client_overlay_fd) = base_scenario(shared_dict)
            server_pid = server.pid
            client_pid = client.pid
            server_overlay_pid_fd = (server_pid, server_overlay_fd)
            client_overlay_pid_fd = (client_pid, client_overlay_fd)

            set_opt_detail_map = dict()
            set_opt_detail_map[DetailIndex(server_pid, server_overlay_fd, socket.TCP_NODELAY)] = DetailValue(socket.IPPROTO_TCP, SERVER_NODELAY, 4)
            set_opt_detail_map[DetailIndex(client_pid, client_overlay_fd, socket.TCP_NODELAY)] = DetailValue(socket.IPPROTO_TCP, CLIENT_NODELAY, 4)

            server_dupthread = PtraceDupThread(server_pid, handler_lock, set_opt_detail_map)
            server_dupthread.start()
            client_dupthread = PtraceDupThread(client_pid, handler_lock, set_opt_detail_map)
            client_dupthread.start()
            time.sleep(2)
            assert server_dupthread.state != ThreadState.DIE_STATE, "Server DupThread must be alive"
            assert client_dupthread.state != ThreadState.DIE_STATE, "Client DupThread must be alive"

        finally:
            coordinator.terminate()
            coordinator.join()
            client.terminate()
            client.join()
            server.terminate()
            server.join()

            try:
                print("Cleaning")
                handler_lock.release()
                server_dupthread.clear()
                client_dupthread.clear()
            except:
                pass

    def test_duplicate(self):
        mgr = Manager()
        shared_dict = mgr.dict()
        try:
            handler_lock = threading.Lock()
            server, client, coordinator, (server_host_fd, server_overlay_fd), (client_host_fd, client_overlay_fd) = base_scenario(shared_dict)
            server_pid = server.pid
            client_pid = client.pid
            server_overlay_pid_fd = (server_pid, server_overlay_fd)
            client_overlay_pid_fd = (client_pid, client_overlay_fd)

            set_opt_detail_map = dict()
            set_opt_detail_map[DetailIndex(server_pid, server_overlay_fd, socket.TCP_NODELAY)] = DetailValue(socket.IPPROTO_TCP, SERVER_NODELAY, 4)
            set_opt_detail_map[DetailIndex(client_pid, client_overlay_fd, socket.TCP_NODELAY)] = DetailValue(socket.IPPROTO_TCP, CLIENT_NODELAY, 4)

            server_dupthread = PtraceDupThread(server_pid, handler_lock, set_opt_detail_map)
            server_dupthread.start()
            call_insert(server_dupthread, server_overlay_pid_fd, server_host_fd, 1, TUNNEL_IP, "0")
            assert len(server_dupthread.tracking_map) == 1, "Fail to Insert"
            
            while "sync_port_str" not in shared_dict:
                time.sleep(1)
                print("Wait for sync port available")
            
            client_dupthread = PtraceDupThread(client_pid, handler_lock, set_opt_detail_map)
            client_dupthread.start()
            call_insert(client_dupthread, client_overlay_pid_fd, client_host_fd, 0, TUNNEL_IP, int(shared_dict["sync_port_str"]))
            assert len(client_dupthread.tracking_map) == 1, "Fail to Insert"
            
            time.sleep(10)

            assert len(server_dupthread.tracking_map) == 0, "Fail to Duplicate"
            assert len(client_dupthread.tracking_map) == 0, "Fail to Duplicate"

            assert server_dupthread.handler.process != None, "Server fail to reset handler"
            assert client_dupthread.handler.process != None, "Client fail to reset handler"

            server_dupthread.clear()
            client_dupthread.clear()

        finally:
            coordinator.terminate()
            coordinator.join()
            client.terminate()
            client.join()
            server.terminate()
            server.join()

            try:
                print("Cleaning")
                handler_lock.release()
                server_dupthread.clear()
                client_dupthread.clear()
            except:
                pass
            print("Done")

            

if __name__ == "__main__":
    unittest.main()
    