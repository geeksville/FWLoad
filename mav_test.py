#!/usr/bin/env python
'''
connect to nsh console
'''

import pexpect, sys
from config import *

def mav_test(reflog=None):
    '''connect to test board'''
    print("CONNECTING TO TEST BOARD")
    cmd = "mavproxy.py --master %s --out 127.0.0.1:14551 --aircraft TestBoard" % USB_DEV_TEST
    if REMOTE_MONITOR2:
        cmd += " --out %s" % REMOTE_MONITOR2
    return pexpect.spawn(cmd, logfile=reflog, timeout=10)

if __name__ == '__main__':
    ref = mav_test()
    ref.interact()
