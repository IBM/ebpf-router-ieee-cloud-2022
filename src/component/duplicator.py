################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################

###############################################################################
## Duplicator module
##
## call ptrace duplicate that will activate a synchronization process
## 1. wait for unlock state
## if server, 
## 2. create sync socket, listen and send server ready to client pair ip and router port
## 3. when accept sync connection and message, duplicate fd
## if client,
## 2. duplicate fd and set original sockopt
## 3. send sync message back to server pair ip and sync port
###############################################################################
import os
import time
import sys
import gc
import logging

from pt.ptrace_dup import PtraceDupThread
from util.rw_memo import MemoChecker

from util.logging import getlogger
logger = getlogger(__name__)

if "ROUTER_TOP_FOLDER" not in os.environ:
    ROUTER_TOP_FOLDER=os.getcwd()
else:
    ROUTER_TOP_FOLDER=os.environ["ROUTER_TOP_FOLDER"]

if "ROUTER_PORT" not in os.environ:
    logger.error("ROUTER_PORT is not set")
    exit()

if "OVERLAY_IF" not in os.environ:
    logger.error("OVERLAY_IF is not set")
    exit()

import netifaces as ni
TUNNEL_IP = ni.ifaddresses(os.environ["OVERLAY_IF"])[ni.AF_INET][0]['addr']

import threading
import subprocess
import psutil


####################################################
## Duplicator
## ================================================
## to manage all duplication
## - duplicating_map keeps the current duplicating DuplicateThread
##
## Duplicate
##   This will create a new DuplicateThread for each request
##
## Termination/Interruption
##   Duplicate thread can be terminated if server dies
##
####################################################


class Duplicator:
    def __init__(self, rw_memo_map, set_opt_detail_map):
        self.duplicating_map = dict() # dupthread
        
        self.lock = threading.Lock() # between capture result and inserted for up
        self.transferring_pids = []
        self.handler_lock = threading.Lock()

        self.rw_memo_map = rw_memo_map
        self.set_opt_detail_map = set_opt_detail_map

        self.memo_checker = dict()

    def insert(self, dup_args, tid):
        with self.lock:
            (overlay_pid_fd, overlay_inode, host_fd, server, client_overlay_addr, sync_port, pair_ip) = dup_args

            client_overlay_addr_str = client_overlay_addr[0] + "," + str(client_overlay_addr[1])
            if pair_ip is None:
                pair_ip = TUNNEL_IP

            overlay_pid = overlay_pid_fd[0]
            if  overlay_pid not in self.duplicating_map:
                self._create_new_and_insert(overlay_pid, overlay_pid_fd, overlay_inode, host_fd, server, pair_ip, sync_port, client_overlay_addr_str, tid)
            else:
                ret = self.duplicating_map[overlay_pid].insert_all(overlay_pid_fd, overlay_inode, host_fd, server, pair_ip, sync_port, client_overlay_addr_str, tid)
                if not ret: # existing one is already terminated
                    self._create_new_and_insert(overlay_pid, overlay_pid_fd, overlay_inode, host_fd, server, pair_ip, sync_port, client_overlay_addr_str, tid)


    def transferring_start(self, overlay_pid):
        print("transferring start", end=" ")
        with self.lock:
            logger.debug("Duplicator set transferring start {}".format(overlay_pid))
            self.transferring_pids.append(overlay_pid)
            if overlay_pid in self.duplicating_map:
                detached_tid = self.duplicating_map[overlay_pid].transferring_start()
                return detached_tid
            else:
                return overlay_pid

    def transferring_done(self, overlay_pid):
        print("transferring done", end=" ")
        with self.lock:
            logger.debug("Duplicator set transferring done {}".format(overlay_pid))
            if overlay_pid in self.transferring_pids:
                self.transferring_pids.remove(overlay_pid)
            if overlay_pid in self.duplicating_map and overlay_pid not in self.transferring_pids:
                self.duplicating_map[overlay_pid].transferring_done()


    def _create_new_and_insert(self, overlay_pid, overlay_pid_fd, overlay_inode, host_fd, server, pair_ip, sync_port, client_overlay_addr_str, tid_specific):
        dupthread = PtraceDupThread(overlay_pid, self.handler_lock, self.set_opt_detail_map)
        self.duplicating_map[overlay_pid] = dupthread
        self.duplicating_map[overlay_pid].start()

        logger.debug("Duplicator call insert {}".format(overlay_pid_fd))
        ret = self.duplicating_map[overlay_pid].insert_all(overlay_pid_fd, overlay_inode, host_fd, server, pair_ip, sync_port, client_overlay_addr_str, tid_specific)
        assert ret, "New dupthread must return true for insert function"
        if overlay_pid in self.transferring_pids:
            self.duplicating_map[overlay_pid].transferring_start()
        

    def insert_duplicate(self, dup_args): 
        overlay_pid_fd = dup_args[0]
        self.memo_checker[overlay_pid_fd] = MemoChecker(self, self.rw_memo_map, dup_args, sleep_window=1, timeout=5)
        self.memo_checker[overlay_pid_fd].start()

    def terminate_duplicate_from_overlay_pid_fd(self, overlay_pid_fd):
        with self.lock:
            if overlay_pid_fd[0] in self.duplicating_map:
                dupthread = self.duplicating_map[overlay_pid_fd[0]]
                dupthread.cancel(overlay_pid_fd, interrupt=True)
                if dupthread.empty():
                    logger.debug("Remove {} from duplicating map".format(dupthread.pid))
                    dupthread.clear()
                    del self.duplicating_map[dupthread.pid]

    def release_lock(self, lock):
        try:
            lock.release()
        except:
            pass

    def clear(self):
        logger.debug("Clear all running ({})".format(len(self.duplicating_map)))
        for dupthread in self.duplicating_map.values():
            dupthread.clear()
        for memo in self.memo_checker.values():
            memo.terminate()



####################################################