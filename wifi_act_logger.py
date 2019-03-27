import os
import sys
import time
import json
import pyshark
import sqlite3
import datetime
import argparse
import threading
import traceback
import random
import pymysql
import urllib.request as urllib2

from datetime import datetime

monitor_iface = "wlan0mon"
alreadyStopping = False
last_mac_add = ""


def DBConncetor():
    con = pymysql.connect('192.168.5.51', 'pete', 'lll22013', 'probe_station', autocommit=True)
    cur = con.cursor()

    cur.execute("CREATE TABLE IF NOT EXISTS mac_add_data(mac_add TEXT, vendor TEXT, rssi INT, date TIMESTAMP)")
    cur.execute("CREATE TABLE IF NOT EXISTS mac_add_ssids(mac_add TEXT, ssids TEXT)")

    return cur


cursor = DBConncetor()

def main():
    print("[I] Starting channelhopper")
    chopper = threading.Thread(target=chopping)
    chopper.daemon = True
    chopper.start()
    print("\n[I] Sniffing started!\n")
    statusWidget(len(devices))

    while True:
        capture = pyshark.LiveCapture(interface=monitor_iface, bpf_filter='type mgt subtype probe-req')
        capture.apply_on_packets(packetHandler)

def restart_line():
    sys.stdout.write('\r')
    sys.stdout.flush()


def statusWidget(devices):
    sys.stdout.write("Devices found: [" + str(devices) + "]")
    restart_line()
    sys.stdout.flush()

print("[W] Make sure to use an interface in monitor mode!\n")

devices = []
script_path = os.path.dirname(os.path.realpath(__file__))
script_path = script_path + "/"

externalOptionsSet = False

print("[I] Loading MAC database")
with open(script_path + "MAC_DB.json", 'r') as content_file:
    obj = content_file.read()
resolveObj = json.loads(obj)

def stop():
    global alreadyStopping
    if not alreadyStopping:
        alreadyStopping = True
        print("\n[I] Stopping")
        print("[I] Sniffer stopped.")
        raise SystemExit

def chopping():
    while True:
        if not alreadyStopping:
            channels = [1, 6, 11]
            for channel in channels:
                time.sleep(5)
        else:
            sys.exit()

def resolveMac(mac):
    try:
        global resolveObj
        for macArray in resolveObj:
            if macArray[0] == mac[:8].upper():
                return macArray[1]
        return "RESOLVE-ERROR"
    except:
        return "RESOLVE-ERROR"

def packetHandler(pkt):
    if "wlan_mgt" in pkt:
        nossid = False
        if not str(pkt.wlan_mgt.tag)[:34] == "Tag: SSID parameter set: Broadcast":
            ssid = pkt.wlan_mgt.ssid
        else:
            nossid = True
    else:
        nossid = False
        if not str(pkt[3].tag)[:34] == "Tag: SSID parameter set: Broadcast":
            ssid = pkt[3].ssid
        else:
            nossid = True

    rssi_val = pkt.radiotap.dbm_antsignal
    mac_address = pkt.wlan.ta
    bssid = pkt.wlan.da

    vendor = resolveMac(mac_address)

    inDevices = False
    for device in devices:
        if device == mac_address:
            inDevices = True
    if not inDevices:
        devices.append(mac_address)

    saveToDB(mac_address, vendor, ssid, rssi_val)
    statusWidget(len(devices))
    last_mac_add = mac_address


def saveToDB(mac_add, vendor, ssid, rssi):
    mac_ignore = ['74:da:38:7e:d1:c1']
    try:
        if mac_add not in mac_ignore:
            formated_time = time.strftime('%Y-%m-%d %H-%M-%S')
            cursor.execute("INSERT INTO mac_add_data (mac_add, vendor, rssi, date) VALUES (%s, %s, %s, %s)", (str(mac_add), str(vendor), int(rssi), formated_time))
            if not ssid =="SSID: ":
                print(mac_add + " (" + vendor + ")" + str(rssi) + " ==> " + ssid)
                cursor.execute("SELECT mac_add FROM mac_add_ssids WHERE mac_add=%s", str(mac_add))
                res = cursor.fetchone()
                if res == None:
                    cursor.execute("INSERT INTO mac_add_ssids (mac_add, ssids) VALUES (%s, %s)", (str(mac_add), str(ssid)))
                else:
                    cursor.execute("UPDATE mac_add_ssids SET ssids = CONCAT(ssids, %s) WHERE mac_add = %s", (str(','+ssid), str(mac_add)))
            else:
                print(mac_add + " (" + vendor + ")" + str(rssi) + "-no-ssid")

    except KeyboardInterrupt:
        stop()
        exit()

if __name__ == "__main__":
    main()
