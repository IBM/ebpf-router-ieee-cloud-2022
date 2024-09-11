################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################

import socket

from pt.static import SyncState, ClientState

BUFFER_SIZE=12

import os

from util.logging import getlogger
logger = getlogger(__name__)

class SyncClient():

    def __init__(self, pair_ip, sync_port, fd):
        if pair_ip is None:
            logger.warning("SyncReturn is skipped")
            return
        self.fd = fd
        self.sync_port = sync_port

        self.client_state = SyncState(fd)
        self.server_state = SyncState.UNKNOWN_STATE
        self.last_report_state = ClientState.INIT_STATE

        self.sync_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sync_socket.connect((pair_ip, sync_port))
        self.pair_ip = pair_ip
        
        logger.debug("New SyncClient {0},{1}".format(pair_ip, sync_port))
    
    def inquire(self): # ZERO_READ_ZERO_WRITE
        res = None
        try:
            self.sync_socket.send(b"SYNC")
            msg = self.sync_socket.recv(BUFFER_SIZE)
            self.last_report_state = ClientState.NOT_WRITING
            decoded_msg = msg.decode()
            res = int(decoded_msg)
            self.server_state = res
        except Exception as e:
            logger.debug("wrong inquire return from {1}: {0}".format(e,self.pair_ip))
        except BrokenPipeError:
            return SyncState.REVOKED_STATE
        return res

    def write_block(self): # ZERO_READ or READ_WRITE
        if self.last_report_state == ClientState.WRITING:
            return
        self.sync_socket.send(b"WRITING")
        self.sync_socket.recv(BUFFER_SIZE)
        self.last_report_state = ClientState.WRITING

    def clear_write(self): 
        if self.last_report_state == ClientState.NOT_WRITING:
            return
        self.sync_socket.send(b"CLEAR_WRITE")
        self.sync_socket.recv(BUFFER_SIZE)
        self.last_report_state = ClientState.NOT_WRITING

    def clear_state(self):
        self.write_block()

    def wait_server_confirm(self):
        self.sync_socket.settimeout(1) # set from here
        logger.debug("Wait for server confirm {}".format(self.fd))
        msg = self.sync_socket.recv(BUFFER_SIZE)
        msg = msg.decode('utf-8')
        if msg == "CONFIRM":
            self.last_report_state = ClientState.WAIT_SERVER
            return True
        self.server_state = SyncState.UNKNOWN_STATE
        return False
    
    def reset_timeout(self):
        self.sync_socket.settimeout(None)

    def revoke(self):
        self.sync_socket.send(b"REVOKE")
        self.last_report_state = ClientState.REVOKED

    def notify(self):
        self.sync_socket.send(b"DONE")
        self.last_report_state = ClientState.DONE

    def wait_server_done(self):
        logger.debug("Wait for server done {}".format(self.fd))
        self.sync_socket.recv(BUFFER_SIZE)
        self.last_report_state = ClientState.WAIT_SERVER


    def close(self):
        logger.debug("Close client socket for fd={0} sync_port={1}".format(self.fd, self.sync_port))
        self.sync_socket.close()