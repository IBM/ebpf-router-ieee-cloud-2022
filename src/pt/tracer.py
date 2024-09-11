################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################

import pickle
import socket
import os
import subprocess
import signal

from pt.static import getlogger
logger = getlogger(__name__)


BUFFER_SIZE = 4096


ROUTER_TOP_FOLDER=os.environ["ROUTER_TOP_FOLDER"]
    
class TracerConnector():
    def __init__(self, pid):
        self.pid = pid
        self.tracer_unix_sock_path = "/tmp/trace_sock_{}.sock".format(pid)
        self.tracer_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.tracer_sock.bind(self.tracer_unix_sock_path)
        self.tracer_sock.listen(1)
        self.process = self._new_tracer()
        self.client_sock, _ = self.tracer_sock.accept()
        self.connected = True

    def _new_tracer(self):
        proccess = None
        if os.path.exists("pt/ptrace_handler.py"):
            process = subprocess.Popen(["python3", "pt/ptrace_handler.py", str(self.pid), self.tracer_unix_sock_path])
        else:
            process = subprocess.Popen(["{}/dist/ptrace_handler/ptrace_handler".format(ROUTER_TOP_FOLDER), str(self.pid), self.tracer_unix_sock_path])
        return process


    def request(self, cmd, args):
        if not self.connected:
            return False, None
        req_data = pickle.dumps((cmd, args))
        try:
            self.client_sock.send(req_data)
            res_data = self.client_sock.recv(BUFFER_SIZE)
            result = pickle.loads(res_data)
        except Exception as err:
            return False, err

        return True, result
    
    def terminate(self):
        self.client_sock.send(b'END')
        self.client_sock.recv(10)
        self.connected = False
        self.tracer_sock.close()
        self.client_sock.close()
        os.remove(self.tracer_unix_sock_path)
        if self.is_alive():
            os.kill(self.process.pid, signal.SIGTERM)
            logger.debug("Wait for process dies {}".format(self.pid))
            self.process.wait()
        self.process = None

    def is_alive(self):
        if self.process is not None:
            poll = self.process.poll()
            if poll is None:
                return True
        return False
        

