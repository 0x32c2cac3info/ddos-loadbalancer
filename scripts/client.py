#!/usr/bin/python3

import os
import sys
import signal
import numpy as np
import time


def signalHandler(signum, frame):
    raise Exception("Shutdown")


if __name__ == '__main__':

    if len(sys.argv) < 2:
        print('Usage: python3 client.py <IP address>')
        exit()

    address = sys.argv[1]
    signal.alarm(300)
    signal.signal(signal.SIGALRM, signalHandler)
    signal.signal(signal.SIGINT, signalHandler)
    np.random.seed()

    try:
        while True:
            os.system("curl {} &".format(address))
            time.sleep(np.random.poisson(lam=1))
    except Exception as err:
        print(err)
    finally:
    	os.system("pkill curl")