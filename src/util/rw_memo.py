################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################

import threading
import time

from util.logging import getlogger
logger = getlogger(__name__)

class MemoChecker(threading.Thread):
    def __init__(self, duplicator, memo, args, sleep_window=1, timeout=60):
        threading.Thread.__init__(self)
        self.sleep_window = sleep_window
        self.timeout = timeout
        self.start_time = time.time()
        self.terminated = False

        self.overlay_pid_fd = args[0]
        self.args = args

        self.memo = memo
        self.duplicator = duplicator


    def _rw_memo_lookup(self, overlay_pid_fd):
        for k, v in self.memo.items():
            if k.pid == overlay_pid_fd[0] and k.fd ==overlay_pid_fd[1]:
                tid = v.value
                logger.debug("Found tid in rw memo {0}:{1}".format(overlay_pid_fd, tid))
                return tid
        return None

    def run(self):
        while True:
            time.sleep(self.sleep_window)
            tid = self._rw_memo_lookup(self.overlay_pid_fd)
            if tid is not None:
                self.duplicator.insert(self.args, tid)
                break
            if self.terminated or (time.time() - self.start_time > self.timeout):
                self.duplicator.insert(self.args, tid)
                logger.warning("Cannot find tid in rw memo {0}".format(self.overlay_pid_fd))
                break

    def terminate(self):
        self.terminated = True
        

