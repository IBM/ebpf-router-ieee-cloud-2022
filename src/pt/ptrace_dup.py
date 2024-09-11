################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################

from pt.sync_server import SyncServerThread
from pt.sync_client import SyncClient
from pt.static import is_traceable, get_all_tids, process_died
from pt.static import ProcessCommand, ThreadState, SyncState, ClientState, ServerState
from pt.tracer import TracerConnector

import threading 
import time
import queue

import socket 

from multiprocessing import Process, JoinableQueue

from util.logging import getlogger
logger = getlogger(__name__)

SET_TCP_NODELAY = True

class PtraceDupThread(threading.Thread):


    def __init__(self, pid, handler_lock, set_opt_detail_map):
        threading.Thread.__init__(self)

        ########## @control    ##########
        self.terminate = False
        

        self.control_queue = queue.Queue()
        self.control_block = True
        self.transfer_lock = threading.Lock()


        ########## @identifier    ##########

        logger.debug("Create new PtraceDupThread {0}".format(pid))
        self.pid = pid
        
        ########## @status    ##########
        self.state = ThreadState.PAUSE_STATE

        self.tracking_map = dict()
        self.overwrote_pid_fd = []
        self.sync_servers = dict() #overlay_pid_fd
        self.sync_clients = dict()

        self.active_tids = []
        self.all_tids = []

        self.tid_memo = dict()
        self.last_processing_tids = []

        self.to_close_host_fd = []
        self.to_set_nodelay = []
        self.tcp_nodelay_flag = dict()

        self.server_sync_report = queue.Queue()

        self.is_transferring = False
        self.detached_tid = self.pid

        self.read_write_memo = dict()

        self.activate = False

        self.set_opt_detail_map = set_opt_detail_map


        ########## @ptrace handler  ##########
        self.handler_lock = handler_lock
        with self.handler_lock:
            self._new_handler()
        

    def _handler_request(self, cmd, args):
        success, ret = self.handler.request(cmd, args)
        if not success:
            logger.warning("Handler dieded {0} at {1}: {2}".format(self.pid, cmd, ret))
            return None
        return ret

    def _new_handler(self):
        logger.debug("{0} wait for handler to start".format(self.pid))
        self.handler = TracerConnector(self.pid)
        self.handler_process = self.handler.process
        if self.handler_process is not None:
            logger.debug("Create handler {0} started - ptracePID={1}".format(self.pid,self.handler_process.pid))
            self.handler_ready = True
        else:
            logger.warning("Cannot create handler {0}".format(self.pid))
            self.handler_ready = False

    def _terminate_handler(self):
        self.handler_ready = False
        if self.handler.is_alive():
            logger.info("Reset handler terminating {}".format(self.pid))
            self.handler.terminate()
            logger.debug("Terminate {0} completed (alive={1})".format(self.pid, self.handler.is_alive()))

    def _reset_handler(self):
        with self.handler_lock:
            self._terminate_handler()
            self._new_handler()
        

###################################################################################################
### Sockopt Part
###################################################################################################

    def _set_original_nodelay_flag(self, overlay_fd, val):
        logger.debug("TCP_NODELAY is set by overlay app to {}".format(val))
        self.tcp_nodelay_flag[overlay_fd] = val

    def set_any_sockopt(self, tid, overlay_fd):
        for k, v in self.set_opt_detail_map.items():
            logger.debug("Map Sockopt {0},{1}: {2}-{3}={4}".format(k.pid, k.fd, v.level, k.optname, v.optval))
            if k.pid == self.pid and k.fd == overlay_fd:
                # case TCP_NODELAY is set after router set
                if v.level == socket.IPPROTO_TCP and k.optname == socket.TCP_NODELAY:
                    if not SET_TCP_NODELAY or v.optval != 1:
                        self._set_original_nodelay_flag(overlay_fd, v.optval)

                self._handler_request(ProcessCommand.SET_ANY_SOCKOPT, (tid, overlay_fd, v.level, k.optname, v.optval))

    def get_original_nodelay(self, overlay_fd):
        for k, v in self.set_opt_detail_map.items():
            # case TCP_NODELAY is set before router set
            if k.pid == self.pid and k.fd == overlay_fd and v.level == socket.IPPROTO_TCP and k.optname == socket.TCP_NODELAY:
                self._set_original_nodelay_flag(overlay_fd, v.optval)


###################################################################################################
### Duplication Part
###################################################################################################

    def _call_dup(self, available_tid, fd, host_fd):
        nodelay = self.tcp_nodelay_flag[fd] if fd in self.tcp_nodelay_flag else -1
        self._handler_request(ProcessCommand.EPOLL_DUP, (available_tid, fd, host_fd, nodelay))
        self.set_any_sockopt(available_tid, fd)
        
    def _get_server_remaining_list(self):
        remaining_list = [fd for fd in list(self.sync_servers.keys()) if self.sync_servers[fd].client_confirm and not self.sync_servers[fd].dup_done]
        return remaining_list

    def _server_dup(self, available_tid, block=True):

        server_remaining_list = self._get_server_remaining_list() # sync but not confirm list -> confirmed
        
        while len(server_remaining_list) > 0 or not self.server_sync_report.empty():
            try:
                report = self.server_sync_report.get(block=block)
                (fd, status) = report
            except:
                break

            if fd not in self.sync_servers or self.sync_servers[fd].client_revoke:
                if fd in server_remaining_list:
                    server_remaining_list.remove(fd)
                continue

            if status == ServerState.SYNC:
                if fd not in server_remaining_list and not self.sync_servers[fd].client_confirm:
                    logger.debug("Server confirm {0}, {1}".format(self.pid, fd))
                    self.sync_servers[fd].server_confirm()
                    server_remaining_list.append(fd)
            elif status == ServerState.DONE:
                host_fd = self.sync_servers[fd].host_fd
                self._call_dup(available_tid, fd, host_fd)
                self.sync_servers[fd].server_done()
                self.cancel((self.pid, fd))
                server_remaining_list.remove(fd)
            elif status == ServerState.REVOKED:
                self.cancel((self.pid, fd))
                if fd in server_remaining_list:
                    server_remaining_list.remove(fd)
        return server_remaining_list

    def _dup_sync_client(self, to_dup_client):
        available_tid = self._handler_request(ProcessCommand.AVAILABLE_TID, "")
        if available_tid is None:
            logger.warning("no available tid")
            return False
        
        server_remaining_list = self._server_dup(available_tid, block=False)
        
        client_remaining_list = to_dup_client.copy()
        has_duplication = (len(server_remaining_list) > 0) or (len(client_remaining_list) > 0)
        if has_duplication:
            logger.debug("(pid={0}) Server Remaining {1} Client Remaining {2}".format(self.pid, server_remaining_list, client_remaining_list))
            self._handler_request(ProcessCommand.SHOW_PROCESS_STATUS, self.active_tids)
        else:
            return False

        failed_list = []
        logger.debug("Client confirm: {}".format([client[1] for client in client_remaining_list]))
        while len(client_remaining_list) > 0:
            (overlay_pid_fd, fd, host_fd) = client_remaining_list.pop()
            try:
                success = self.sync_clients[fd].wait_server_confirm()
                if not success:
                    failed_list.append(overlay_pid_fd)
                    continue
            except socket.timeout:
                client_remaining_list.append((overlay_pid_fd, fd, host_fd))
                server_remaining_list = self._server_dup(available_tid, block=False)
                continue
            
            self._call_dup(available_tid, fd, host_fd)
            self.sync_clients[fd].notify()

        client_remaining_list = to_dup_client.copy()
        
        logger.debug("Client duplicate: {}".format([client[1] for client in client_remaining_list]))
        while len(client_remaining_list) > 0:
            (overlay_pid_fd, fd, host_fd) = client_remaining_list.pop()
            if overlay_pid_fd in failed_list:
                continue
            try:
                self.sync_clients[fd].wait_server_done()
                self.cancel(overlay_pid_fd)
            except socket.timeout:
                client_remaining_list.append((overlay_pid_fd, fd, host_fd))
                server_remaining_list = self._server_dup(available_tid, block=False)
                continue

        logger.debug("Server duplicate: {}".format(server_remaining_list))        
        server_remaining_list = self._server_dup(available_tid, block=True)
        assert len(server_remaining_list)==0, "All remaining list should be clear by blocking"

        logger.debug("Duplication and Synchronization Done")

        return True

###################################################################################################
### Attachment Part
###################################################################################################

    def check_tabu_sleeping(self, fd):
        if fd not in self.sync_servers:
            return False

        self.read_write_memo = self._handler_request(ProcessCommand.UPDATE_RWMEMO, self.read_write_memo)
        for tid in self.read_write_memo:
            if fd in self.read_write_memo[tid]:
                if tid not in self.last_processing_tids:
                    return True
        return False


###################################################################################################
### Handle Unknown Part
###################################################################################################

    def handle_unknown(self):
        # delete died tid
        for tid in self.active_tids.copy():
            if process_died(tid):
                logger.warning("Remove {0} from active list of {1} because process died".format(tid, self.pid))
                self.active_tids.remove(tid)
                if tid in self.all_tids:
                    self.all_tids.remove(tid)

 
        # add optional tids from pool
        for tid in self.all_tids.copy():
            if process_died(tid):
                self.all_tids.remove(tid)
                continue
            if tid not in self.active_tids:
                logger.debug("Add {1} to active list: {0}".format(self.active_tids, tid))
                self.active_tids.append(tid)
                break

        # notify failure to sync_client
        while not self.server_sync_report.empty():
            try:
                report = self.server_sync_report.get(block=block)
                (fd, status) = report
            except:
                break

            if status == ServerState.SYNC:
                logger.debug("Read Server SYNC")
                if not self.sync_servers[fd].client_confirm:
                    logger.debug("Server not confirm {0},{1}".format(self.pid, fd))
                    self.sync_servers[fd].server_not_confirm()
            elif status == ServerState.REVOKED:
                self.cancel((self.pid, fd))
            else:
                logger.warning("Unexpected report {0}: {1}".format(self.pid, report))

################################################################################################### 

    def print_state(overlay_pid_fd, server, server_state, client_state, read_buffer, write_buffer):
        return "{0}({1}): {2},{3} Read {4} Write {5}".format(overlay_pid_fd, "Server" if server else "Client", SyncState.string(server_state), ClientState.string(client_state), read_buffer, write_buffer)

    def client_job(self, overlay_pid_fd, tid, fd, host_fd, pair_ip, client_overlay_addr, sync_port, read_buffer, write_buffer, writing, reading, to_dup_client, should_block, never_block):
        if fd in self.sync_clients:
            ### update state ###
            self.sync_clients[fd].client_state.set_state(read_buffer, write_buffer)
            client_state = self.sync_clients[fd].client_state.state
            logger.debug("{0} from client_state {1}".format(overlay_pid_fd, client_state))

            ### make decision ###
            if client_state == SyncState.ZERO_READ_ZERO_WRITE:
                
                server_state = self.sync_clients[fd].inquire()
                
                ### decided by server state ###
                if server_state == SyncState.ZERO_READ_ZERO_WRITE:
                    to_dup_client.append((overlay_pid_fd, fd, host_fd))
                elif server_state == SyncState.ZERO_READ or server_state == SyncState.READ_WRITE or server_state == SyncState.UNKNOWN_STATE:
                    never_block = True
                elif server_state == SyncState.ZERO_WRITE:
                    should_block = True
                else:
                    logger.debug("Wrong server state for ({0},{1}): {2}".format(tid, fd, server_state))
                    never_block = True

                logger.debug(PtraceDupThread.print_state(overlay_pid_fd, 0, server_state, client_state, write_buffer, read_buffer))

            elif client_state == SyncState.ZERO_READ or client_state == SyncState.READ_WRITE:
                self.sync_clients[fd].write_block() # writing
                should_block = True
            else:
                self.sync_clients[fd].clear_write() # not writing

            if read_buffer > 0: # the other side can block
                never_block = True

            if writing[fd] is not None: # the other side must not block
                if not never_block:
                    should_block = True
                else:
                    self.sync_clients[fd].write_block() # writing

            logger.debug("client {0} decision never={1}, should={2}".format(overlay_pid_fd, never_block, should_block))

        return should_block, never_block


    def server_job(self, overlay_pid_fd, tid, fd, host_fd, pair_ip, client_overlay_addr, sync_port, read_buffer, write_buffer, writing, reading, to_dup_client, should_block, never_block):
        if fd in self.sync_servers and self.sync_servers[fd].connected:
            ### update state ###
            self.sync_servers[fd].server_state.set_state(read_buffer, write_buffer)
            client_state = self.sync_servers[fd].client_state
            server_state = self.sync_servers[fd].server_state.state
            
            
            ### make decision ###
            if client_state == ClientState.WRITING or read_buffer > 0 or client_state == ClientState.INIT_STATE:
                never_block = True
            elif writing[fd] is not None or server_state == SyncState.ZERO_READ_ZERO_WRITE:
                if not never_block: 
                    should_block = True # the other side must not block

            logger.debug(PtraceDupThread.print_state(overlay_pid_fd, 1, server_state, client_state, write_buffer, read_buffer))
            logger.debug("server {0} decision never={1}, should={2}".format(overlay_pid_fd, never_block, should_block))

        return should_block, never_block

    def _transfer_clear(self):
        for fd in self.sync_clients:
            self.sync_clients[fd].write_block()
        self.control_block = True
        self.control_queue.task_done()  

    def run(self):
        support_tids = []

        try:
            transfer_control = False
            logger.debug("PtraceDupThread {} start".format(self.pid))
            while True:
                try:
                    if not transfer_control:
                        transfer_control = self.control_queue.get(block=self.control_block)

                        if not self.is_transferring:
                            self.control_queue.task_done()
                            self.control_block = False
                    
                    logger.debug("{0} control queue not empty block={1} transfer={2}".format(self.pid, self.control_block, transfer_control))
                # empty queue
                except:
                    pass

                ############ Interrupting for transferring fd ########################

                if transfer_control and self.is_transferring:
                    self.control_block = False
                    sync_list = [fd for fd in list(self.sync_servers.keys()) if self.sync_servers[fd].client_sync]
                    has_duplication = (len(sync_list) > 0)
                    if not has_duplication:
                        if self.terminate:
                            self._reset_handler()
                            self.detached_tid = self.pid
                            self._transfer_clear()
                            transfer_control = False
                            # will break after cleaned
                        else:
                            assert self.handler_ready, "Handler must be always ready"

                            self.detached_tid = self._handler_request(ProcessCommand.TRANSFER_DETACH, self.active_tids)
                            if self.detached_tid == 0:
                                self._reset_handler()
                                self.detached_tid = self.pid

                            logger.info("Detached tid = {0} of {1}".format(self.detached_tid, self.pid))
                            self._transfer_clear()
                            transfer_control = False
                            continue

                ############ Clean canceled fd before continue ########################
                if len(self.to_close_host_fd) > 0:
                    self._handler_request(ProcessCommand.CLEAN_HOST_FD, (self.to_close_host_fd, self.active_tids))
                if self.terminate:
                    logger.warning("{}: terminate set".format(self.pid))
                    break

                ######################################################################

                ############ Update tracking map status ##############################

                if len(self.tracking_map) == 0:
                    if len(self.overwrote_pid_fd) > 0:
                        (overlay_pid_fd, overlay_inode, host_fd, server, pair_ip, sync_port, client_overlay_addr, tid_specific) = self.overwrote_pid_fd.pop()
                        self.insert_all(overlay_pid_fd, overlay_inode, host_fd, server, pair_ip, sync_port, client_overlay_addr, tid_specific)
                    else:
                        self._reset_handler()
                        if not self.is_transferring:
                            self.control_block = True
                            logger.warning("No more in the tracking map in {0} (remaining traced tids: {1})".format(self.pid, [tid for tid in self.all_tids if not is_traceable(tid) and not process_died(tid)]))
                        self.activate = False
                        continue
                else:
                    ### check if any of server is connected or has client --> need attachment and processing
                    if not self.activate:
                        for overlay_pid_fd in self.tracking_map.keys():
                            fd = overlay_pid_fd[1]
                            if fd in self.sync_clients:
                                self.activate = True
                                break
                            if fd in self.sync_servers and self.sync_servers[fd].connected:
                                self.activate = True
                                break
                            
                        if not self.activate:
                            if not self.is_transferring:
                                self.control_block = True
                                logger.debug("PtraceDupThread {} inactive".format(self.pid))
                            continue

                if len(self.active_tids) == 0:
                    logger.warning("No tid in active list of {}".format(self.pid))

                ######################################################################

                ############# Find available tid  #####################################

                self.last_processing_tids = self._handler_request(ProcessCommand.UPDATE_PROCESSING_TIDS, self.active_tids)
                # no tid ready to process yet
                if len(self.last_processing_tids) == 0:
                    self.handle_unknown()
                    continue

                has_unknown_tid = len(self.last_processing_tids) < len(self.active_tids)
                never_block = False
                should_block = False

                tid = self.last_processing_tids[0]
                
                ######################################################################

                ############# Update status      #####################################
                total_write = 0
                total_read = 0

                reading = dict()
                writing = dict()
                to_dup_client = []

                processing_fd = []

                for overlay_pid_fd, dup_args in self.tracking_map.copy().items():
                    
                    (overlay_inode, host_fd, server, pair_ip, sync_port, client_overlay_addr, tid_specific) = dup_args
                    
                    fd = overlay_pid_fd[1]

                   

                    if fd in self.sync_servers and self.sync_servers[fd].client_revoke:
                        self.cancel((self.pid, fd))
                        continue

                    if fd in processing_fd:
                        continue

                    processing_fd.append(fd)

                    (reading[fd], writing[fd]) = self._handler_request(ProcessCommand.CHECK_RW, (self.active_tids, fd))

                    if len(self.tracking_map) > 1 and has_unknown_tid and self.check_tabu_sleeping(fd):
                        logger.debug("Skip and clear fd {}".format(fd))
                        self.sync_servers[fd].clear_server_state()
                        continue   

                    alive = self._handler_request(ProcessCommand.CONFIRM_SOCKET_ALIVE, (tid, overlay_inode, host_fd, fd))
                    if alive:
                        (read_buffer, write_buffer) = self._handler_request(ProcessCommand.CHECK_RWBUFFER, (tid, fd))

                        total_read += read_buffer
                        total_write += write_buffer

                        if SET_TCP_NODELAY:
                            if fd in self.to_set_nodelay and write_buffer > 0:
                                self.get_original_nodelay(fd)
                                self._handler_request(ProcessCommand.SET_TCP_NODELAY, (tid, fd, 1))
                                self.to_set_nodelay.remove(fd)

                        if server:
                            should_block, never_block = self.server_job(overlay_pid_fd, tid, fd, host_fd, pair_ip, client_overlay_addr, sync_port, read_buffer, write_buffer, writing, reading, to_dup_client, should_block, never_block)
                        else: # client
                            should_block, never_block = self.client_job(overlay_pid_fd, tid, fd, host_fd, pair_ip, client_overlay_addr, sync_port, read_buffer, write_buffer, writing, reading, to_dup_client, should_block, never_block)
                    else:
                        self.cancel((self.pid, fd))
                ######################################################################

                ############# Duplication #############################################
                dup_success = self._dup_sync_client(to_dup_client)

                if dup_success:
                    self._update_overwrote()

                ######################################################################

                ############# Next step   #############################################

                if self.empty():
                    logger.debug("Finish all duplication")
                else:
                    try:
                        if never_block or not should_block:
                            for fd, sync_server in self.sync_servers.items():
                                server_state = sync_server.server_state.state
                                client_state = sync_server.client_state
                                # server_state == SyncState.ZERO_READ: --> READ_WRITE --> no effect
                                # server_state == SyncState.READ_WRITE --> no effect
                                # server_state == SyncState.ZERO_WRITE --> READ_WRITE --> will be updated
                                if server_state == SyncState.ZERO_READ_ZERO_WRITE:
                                     if client_state == ClientState.WRITING or writing[fd] is not None:
                                         logger.debug("Clear state  {0} (never block) {1}".format(fd, sync_server.pair_ip))
                                         sync_server.clear_server_state()

                            for fd, sync_client in self.sync_clients.items():
                                server_state = sync_client.server_state
                                client_state = sync_client.last_report_state
                                if client_state == ClientState.NOT_WRITING and writing[fd] is not None:
                                    sync_client.clear_state()

                            for tid in self.last_processing_tids:
                                (rax, rdi) = self._handler_request(ProcessCommand.CURRENT_REGS, tid)
                                prev_reg = (rax, rdi)
                                (rax, rdi) = self._handler_request(ProcessCommand.NEXT_TRAP, tid)
                                if self.state != ThreadState.RUNNING_STATE or ((rax, rdi) != prev_reg):
                                    logger.debug("Continue {7} running here {0},{1} {2},{3} {4},{5} from {6}".format(rax, rdi, never_block, should_block, total_write, total_read, prev_reg, self.pid))
                            self.state = ThreadState.RUNNING_STATE
                        else:
                            (rax, rdi) = self._handler_request(ProcessCommand.CURRENT_REGS, tid)
                            if self.state != ThreadState.BLOCKING_STATE:
                                logger.debug("Blocking {6} now at {0},{1} {2},{3} {4},{5}".format(rax, rdi, never_block, should_block, total_write, total_read, self.pid))
                            self.state = ThreadState.BLOCKING_STATE
                    except Exception as err:
                        logger.debug("Next call error {}".format(err))

                ######################################################################

            self.state = ThreadState.DIE_STATE
        except Exception as error: 
            self.state = ThreadState.DIE_STATE
            logger.exception(error)
        finally:
            logger.warning("Ptrace Dup {} Dies".format(self.pid))
            self.state = ThreadState.DIE_STATE
            if not self.terminate:
                self.clear()
            self.terminate = True
            self.control_block = True
            self._terminate_handler()
            
###################################################################################################
### Thread control Part
###################################################################################################

    def resume(self):
        if self.control_block:
            logger.debug("{} Try resuming".format(self.pid))
            self.control_block=False
            self.control_queue.put(False)
            self.control_queue.join()
            logger.debug("Dupthread {} resume".format(self.pid))

    def _update_active_tids(self):
        active_tids = []
        for overlay_pid_fd in self.tracking_map.keys():
            new_tids = [tid for tid in self.tid_memo[overlay_pid_fd] if tid not in active_tids and not process_died(tid)]
            active_tids += new_tids
        self.active_tids = active_tids


    def _update_overwrote(self):
        remaining_list = []
        while len(self.overwrote_pid_fd) > 0:
            (overlay_pid_fd, overlay_inode, host_fd, server, pair_ip, sync_port, client_overlay_addr, tid_specific) = self.overwrote_pid_fd.pop()
            if overlay_pid_fd not in self.tracking_map:
                self.insert_all(overlay_pid_fd, overlay_inode, host_fd, server, pair_ip, sync_port, client_overlay_addr, tid_specific)
            else:
                remaining_list.append((overlay_pid_fd, overlay_inode, host_fd, server, pair_ip, sync_port, client_overlay_addr, tid_specific))
        self.overwrote_pid_fd = remaining_list

    def cancel(self, overlay_pid_fd, interrupt=False):
        with self.handler_lock:
            if overlay_pid_fd in self.tracking_map:
                if interrupt:
                    (overlay_inode, host_fd, server, pair_ip, sync_port, client_overlay_addr, tid_specific) = self.tracking_map[overlay_pid_fd]
                    if host_fd not in self.to_close_host_fd:
                        self.to_close_host_fd.append(host_fd)
                del self.tracking_map[overlay_pid_fd]
                self._update_active_tids()
                logger.debug("cancel {0}".format(overlay_pid_fd))
            if overlay_pid_fd[1] in self.sync_servers:
                self.sync_servers[overlay_pid_fd[1]].clear()
                del self.sync_servers[overlay_pid_fd[1]]
            elif overlay_pid_fd[1] in self.sync_clients:
                self.sync_clients[overlay_pid_fd[1]].close()
                del self.sync_clients[overlay_pid_fd[1]]
            self.activate = False

    def transferring_start(self):
        with self.transfer_lock:
            logger.debug("Wait for transfer start {}".format(self.pid))
            with self.handler_lock:
                self.is_transferring = True
                self.control_block=True
                self.control_queue.put(True)

            logger.debug("transferring {} start signaling and wait for join".format(self.pid))
            self.control_queue.join()
            logger.debug("Dupthread {} stop".format(self.pid))

            if not is_traceable(self.detached_tid):
                logger.warning("fail to detach {}".format(self.detached_tid))
            logger.debug("transferring start returned {}".format(self.detached_tid))
            return self.detached_tid

    def transferring_done(self):
        with self.transfer_lock:
            with self.handler_lock:
                self.is_transferring = False
            self.resume()
            logger.debug("{} transferring end".format(self.pid))

    def insert_all(self, overlay_pid_fd, overlay_inode, host_fd, server, pair_ip, sync_port, client_overlay_addr, tid_specific):
        if self.terminate:
            return False
        logger.debug("Wait for insert all {}".format(self.pid))
        with self.handler_lock:
            if overlay_pid_fd in self.tracking_map:
                logger.debug("PtraceDup add {} to overwrote list".format(overlay_pid_fd, host_fd, server, pair_ip, sync_port, client_overlay_addr, tid_specific))
                self.overwrote_pid_fd.append((overlay_pid_fd, overlay_inode, host_fd, server, pair_ip, sync_port, client_overlay_addr, tid_specific))
            else:
                fd = overlay_pid_fd[1]
                ### start sync server/client if not start yet ###
                if server:
                    if fd not in self.sync_servers:
                        server = SyncServerThread(self, fd, host_fd, pair_ip, client_overlay_addr)
                        self.sync_servers[fd] = server
                        self.sync_servers[fd].start()
                else:
                    if fd not in self.sync_clients:
                        self.sync_clients[fd] = SyncClient(pair_ip, sync_port, fd)

                self.tracking_map[overlay_pid_fd] = (overlay_inode, host_fd, server, pair_ip, sync_port, client_overlay_addr, tid_specific)
                logger.info("PtraceDup insert {}".format((overlay_pid_fd, overlay_inode,  host_fd, server, pair_ip, sync_port, client_overlay_addr, tid_specific)))

                all_tids = get_all_tids(self.pid)
                if tid_specific is None:
                    tids = all_tids
                else:
                    tids = [tid_specific]
                    
                self.tid_memo[overlay_pid_fd] = tids
                new_tids = [tid for tid in tids if tid not in self.active_tids]
                self.active_tids += new_tids
                self.all_tids = all_tids
                if SET_TCP_NODELAY:
                    if overlay_pid_fd[1] not in self.to_set_nodelay:
                        self.to_set_nodelay.append(overlay_pid_fd[1])
        if not self.is_transferring:
            self.resume()
        logger.debug("{} insertion done".format(self.pid))
        return True

    def server_activate(self):
        if not self.is_transferring:
            self.resume()

    def clear(self):
        for _, server in self.sync_servers.items():
            server.clear()
        for _, client in self.sync_clients.items():
            client.revoke()

        self.sync_servers = dict()
        self.sync_clients = dict()

        self.terminate = True
        if not self.is_transferring:
            self.resume()

        
        

    def empty(self):
        if len(self.overwrote_pid_fd) == 0 and len(self.tracking_map) == 0:
            return True
        return False


