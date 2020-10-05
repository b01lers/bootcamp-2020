#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup


url = "http://chal.ctf.b01lers.com:3003"
flag_page = requests.get(url + "/program/control", headers={'User-Agent': 'Master Control Program 0000'}).text

soup = BeautifulSoup(flag_page, 'html.parser')
flag = soup.find_all('p')

print(flag[0].get_text().rstrip())
