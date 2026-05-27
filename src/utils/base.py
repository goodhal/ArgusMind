# -*- coding:utf-8 -*-　　
# @name: base
# @auth: rainy-autumn@outlook.com
# @version:
import os
import sys
import platform
import socket
import uuid
from collections import defaultdict

def get_platform():
    system = platform.system()
    arch = platform.machine().lower()

    if system == "Windows":
        return "windows"
    elif system == "Darwin":
        return "darwin"
    elif system == "Linux":
        return "linux"
    else:
        raise RuntimeError("Unsupported OS")



def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

