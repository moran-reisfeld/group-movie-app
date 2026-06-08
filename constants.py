__author__ = "moran reisfeld"

import sys
import os

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = 8080
SIZE = 8

VIDEO_PORT   = 8081
FPS_DELAY    = 0.033
UDP_MAX_SIZE = 65507
