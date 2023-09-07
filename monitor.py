import json
import logging
import logging.handlers
import time
import pcapy
from datetime import datetime
from ipaddress import ip_address
import threading
import gzip
import shutil
import os
from pyiface import Interface

def namer(name):
    return name + ".gz"

def rotator(source, dest):
    with open(source, "rb") as f_in, gzip.open(dest, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    os.remove(source)

logger = logging.getLogger("trafficLogger")
logger.setLevel(logging.INFO)

handler = logging.handlers.TimedRotatingFileHandler(
    'logs/traffic_logs.log',
    when="H",
    backupCount=24,
    encoding="utf-8"
)
handler.namer = namer
handler.rotator = rotator
handler.setFormatter(logging.Formatter('%(message)s'))

logger.addHandler(handler)


X_MINUTES = 5

def is_interface_up(dev):
    try:
        iface = Interface(name=dev)
        return iface.flags == 4163 
    except:
        return False

def flush_old_entries(last_seen, last_flush_time, current_time):
    if current_time - last_flush_time > X_MINUTES * 60:
        keys_to_delete = [key for key, last_time in last_seen.items() if current_time - last_time > X_MINUTES * 60]
        for key in keys_to_delete:
            del last_seen[key]
        return current_time
    return last_flush_time


def packet_callback(header, packet_data, dev, last_seen):

    ip_header_offset = 14
    src_ip_offset = 12
    dest_ip_offset = 16

    src_ip = packet_data[ip_header_offset + src_ip_offset : ip_header_offset + src_ip_offset + 4]
    src_ip_str = str(ip_address(src_ip))

    dest_ip = packet_data[ip_header_offset + dest_ip_offset : ip_header_offset + dest_ip_offset + 4]
    dest_ip_str = str(ip_address(dest_ip))

    current_time = time.time()
    src_key = (src_ip_str, dev)

    if src_key not in last_seen or (current_time - last_seen[src_key]) > X_MINUTES * 60:
        record = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": src_ip_str,
            "destination_ip": dest_ip_str,
            "interface": dev,
        }

        logger.info(json.dumps(record))
        last_seen[src_key] = current_time

def capture_on_dev(dev):
    last_seen = {}
    last_flush_time = time.time()

    pc = pcapy.open_live(dev, 65536, True, 0)
    pc.setfilter('ip')

    while True:
        current_time = time.time()
        last_flush_time = flush_old_entries(last_seen, last_flush_time, current_time)

        (header, packet_data) = pc.next()
        if header:
            packet_callback(header, packet_data, dev, last_seen)

devices = pcapy.findalldevs()


for dev in devices:
    if is_interface_up(dev):
        t = threading.Thread(target=capture_on_dev, args=(dev,))
        t.start()
