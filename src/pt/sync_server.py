################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################

from pt.static import ThreadState, SyncState, ClientState, ServerState

import socket 


import threading

import os

from util.logging import getlogger
logger = getlogger(__name__)

if "ROUTER_PORT" not in os.environ:
    logger.error("ROUTER_PORT is not set")
    exit()


import netifaces as ni
TUNNEL_IP = ni.ifaddresses(os.environ["OVERLAY_IF"])[ni.AF_INET][0]['addr']
DUP_TIMEOUT = 1
BUFFER_SIZE=12

class SyncServerThread(threading.Thread):

    def __init__(self, ptrace_dup, fd, host_fd, pair_ip=None, client_overlay_addr=None):
        threading.Thread.__init__(self)
        ########## @control    ##########
        self.ptrace_dup = ptrace_dup
        self.terminate=False

        ########## @identifier ##########
        self.host_fd = host_fd
        self.fd = fd
        self.pair_ip = pair_ip

        ########## @status     ##########
        self.rw = False

        self.client_sync = None
        self.client_state = ClientState.INIT_STATE
        self.client_confirm = False
        self.client_done = False
        self.client_revoke = False

        self.server_state = SyncState(fd)
        self.dup_done = False
        
        ########## @communicate ##########

        self.client = None
        self.coor_msg = None
        
        self.sync_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sync_socket.bind((TUNNEL_IP,0))
        self.sync_port = self.sync_socket.getsockname()[1]
        
        self.coor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.debug("Connect to client's coordinator: {}".format((pair_ip, int(os.environ['ROUTER_PORT']))))
        
        self.coor_socket.connect((pair_ip, int(os.environ['ROUTER_PORT'])))
        self.coor_msg = "{0},{1}".format(client_overlay_addr, self.sync_port).encode()
      
        self.sync_socket.listen(128)
        self.sync_socket.settimeout(1)
        
        self.coor_socket.sendall(self.coor_msg)
        logger.debug("Send {0}".format(self.coor_msg))
        self.coor_socket.close()
        self.connected = False

        self.client_overlay_addr = client_overlay_addr
        
        
    #########################################################
    ## Server state
    ##
    ## clear_server_state: become unknown called when dupthread dies or transferring with rb,wb=0
    ## Continuously listen to client state
    ## SYNC:
    ##    called by inquire()
    ##    return state
    ## ZERO_READ:
    ##    called by write_block()
    ##    return ok
    ## CLEAR_WRITE:
    ##    called by clear_write()
    ##    return ok 
    ## DONE:
    ##     called by notify()
    ##     return nothing
    ## REVOKE:
    ##     called by revoke()
    ##     return nothing
    ##
    #########################################################


    def clear_server_state(self):
        self.server_state.clear()

    def run(self):
        while True:
            if self.terminate:
                break
            try:
                self.client, (ipaddr, port) = self.sync_socket.accept()
                break
            except socket.timeout:
                continue
            except OSError:
                self.revoke()

        logger.debug("SyncServer accept client for {}".format(self.client_overlay_addr))
        self.connected = True
        self.ptrace_dup.server_activate()
        logger.debug("SyncServer {} activate".format(self.client_overlay_addr))

        while True:
            if self.terminate:
                break
            msg = self.client.recv(BUFFER_SIZE)
            msg = msg.decode('utf-8')
            if "SYNC" == msg:
                if self.ptrace_dup.control_block or self.ptrace_dup.state == ThreadState.DIE_STATE:
                    self.clear_server_state()
                    logger.debug("Clear from pause or die")
                elif self.server_state.state == SyncState.ZERO_READ_ZERO_WRITE and self.ptrace_dup.is_transferring:
                    self.clear_server_state()
                    logger.debug("Clear from transfer")
                elif len(self.ptrace_dup.last_processing_tids) == 0:
                    self.clear_server_state()            

                if self.client_revoke:
                    return_state = SyncState.REVOKED_STATE
                else:
                    return_state = self.server_state.state

                msg = "{}".format(return_state)
                try: 
                    self.client.send(msg.encode('utf-8'))
                    if return_state == SyncState.ZERO_READ_ZERO_WRITE:
                        self.client_sync = True
                        logger.debug("Set client sync for {0}, {1}".format(self.pair_ip, self.fd))
                        self.ptrace_dup.server_sync_report.put((self.fd, ServerState.SYNC))
                    else:
                        self.client_sync  = False
                    self.client_state = ClientState.NOT_WRITING
                except Exception as e:
                    logger.warning("Server fails to send: {}, Revoke".format(e))
                    self.revoke()

            elif "WRITING" == msg:
                if not self.client_revoke:
                    self.client_state = ClientState.WRITING
                    self.client.send(b"OK")
                else:
                    logger.warning("Already revoked {0},{1}".format(self.pair_ip, self.fd))
                    self.client_state = ClientState.REVOKED
                    self.client.send(b"FAIL")
            elif "CLEAR_WRITE" == msg:
                if not self.client_revoke:
                    self.client_state = ClientState.NOT_WRITING
                    self.client.send(b"OK")
                else:
                    logger.warning("Already revoked {0},{1}".format(self.pair_ip, self.fd))
                    self.client_state = ClientState.REVOKED
                    self.client.send(b"FAIL")
            elif "DONE" == msg:
                if not self.client_revoke:
                    logger.debug("Client {0} returns done for {1}".format(self.pair_ip, self.fd))
                    self.client_done = True
                    self.ptrace_dup.server_sync_report.put((self.fd, ServerState.DONE))
                    self.client_state = ClientState.DONE
                else:
                    logger.warning("Already revoked {0},{1}".format(self.pair_ip, self.fd))
                    self.client_state = ClientState.REVOKED
            elif "REVOKE" == msg:
                self.revoke()
            else:
                if msg != "":
                    logger.debug("SyncServer got wrong format: {0}, {1}".format(self.client_sync, msg))
                continue

        #########################################################
        
    def revoke(self):
        logger.debug("Revoke {0} for {1}".format(self.pair_ip, self.fd))
        self.client_state = ClientState.REVOKED
        self.client_revoke = True
        self.ptrace_dup.server_sync_report.put((self.fd, ServerState.REVOKED))

    def server_confirm(self):
        self.client_confirm = True
        self.client.send(b"CONFIRM")
        self.ptrace_dup.server_sync_report.put((self.fd, ServerState.CONFIRMED))

    def server_not_confirm(self):
        self.client_confirm = False
        self.client.send(b"REJECT")
        
    def server_done(self):
        self.dup_done = True
        self.client.send(b"DONE")
        
    def clear(self):
        self.terminate = True
        logger.debug("Close server socket for fd={0} sync_port={1}".format(self.fd, self.sync_port))
        if self.client is not None:
            self.client.close()
        self.sync_socket.close()