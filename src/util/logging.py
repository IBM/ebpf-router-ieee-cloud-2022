################################################
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache-2.0
################################################

###################################################################################################
#### Logging 
###################################################################################################
import logging
import os
import sys

def getlogger(identifier):
    formatter = logging.Formatter(fmt='%(filename)s\t%(asctime)s %(levelname)-8s %(message)s',
                                    datefmt='%Y-%m-%d %H:%M:%S')
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(formatter)

    logger = logging.getLogger(identifier)
    logger.propagate = False
    logger.addHandler(handler)

    if "ROUTER_LOGLEVEL" not in os.environ:
        os.environ["ROUTER_LOGLEVEL"] = "WARNING"
    logger.setLevel(getattr(logging, os.environ["ROUTER_LOGLEVEL"]))
    return logger

###################################################################################################