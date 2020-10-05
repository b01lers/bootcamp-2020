#!/usr/bin/env python3

import MySQLdb
import random
import csv
from time import sleep
import os


def get_name(name_list):
    name = name_list[random.randint(0, len(name_list) - 1)]
    name += "-" + str(round(random.random()*9999, 4))
    return name


def get_loc(to_derezz=False):
    value_list = ["unknown", "game-room-stands", "uplink", "building", "carrier-ship", "game-room"]
    rand = random.randint(0, len(value_list) - 1)
    if not to_derezz:
        loc = value_list[rand]
    else:
        loc = "holding-cell"

    if rand < 2 or to_derezz:
        loc += "-" + str(round(random.random()*9999, 4))
    return loc


def get_status():
    value_list = ["derezzed", "unknown", "idle", "running", "suspended", "zombie", "orphan"]
    return value_list[random.randint(0, len(value_list) - 1)]


# Populate name_list while mysql is loading
name_list = []
with open('data/names.csv', 'r', encoding='utf-8') as fd:
    name_reader = csv.reader(fd, delimiter=',')

    # Only 1 row
    for row in name_reader:
        name_list = row


root_pass = os.environ['MYSQL_ROOT_PASSWORD']

connected = False
while not connected:
    try:
        db = MySQLdb.connect(host='localhost', user='root', passwd=root_pass)
        connected = True
    except MySQLdb.OperationalError:
        # Poll
        print("Sleeping...")
        sleep(5)

cur = db.cursor()
root_queries = [
    "CREATE DATABASE grid",
    "CREATE USER 'selection_program'@'localhost' IDENTIFIED BY 'designation2-503';",
    "GRANT SELECT ON grid.* TO 'selection_program'@'localhost';",
    "GRANT SELECT ON information_schema.* TO 'selection_program'@'localhost';",
]

for query in root_queries:
    try:
        cur.execute(query)
    except MySQLdb.OperationalError:
        print("Sleeping...")
        sleep(2)

cur.close()
db.commit()
db.close()

# Connect to grid database
db_grid = MySQLdb.connect(host='localhost', user='root', passwd=root_pass, db='grid')
cur_grid = db_grid.cursor()


# Create tables in grid database
grid_tables = [
    'programs (id VARCHAR(10) NOT NULL, name VARCHAR(50), status VARCHAR(10), location VARCHAR(50))',
    'known_isomorphic_algorithms (id VARCHAR(10) NOT NULL, name VARCHAR(50), status VARCHAR(10), location VARCHAR(50))',
    'to_derezz (id VARCHAR(10) NOT NULL, name VARCHAR(50), status VARCHAR(10), location VARCHAR(50))',
]

for query in grid_tables:
    cur_grid.execute('CREATE TABLE ' + query + ';')

# Put names into programs table
for i in range(0xffff):
    # Add tron at his 'compile date'
    loc = None
    if i == 1980:
        name = "Tron-JA-307020"
        status = "running"
        loc = "flag{I_fight_for_the_users_and_yori}"
    elif i == 1981:
        name = "Clu"
        status = "derezzed"
    elif i == 1982:
        name = "Ram"
        status = "derezzed"
    else:
        name = get_name(name_list)
        status = get_status()

    if status == "derezzed":
        loc = "NULL"
    elif loc is None:
        loc = get_loc()

    cur_grid.execute(
            'INSERT INTO programs (id, name, status, location) VALUES ("' + str(i) + '", "'
            + name + '", "' + status + '", "' + loc + '");')

for i in range(0x1000):
    cur_grid.execute(
            'INSERT INTO known_isomorphic_algorithms (id, name, status, location) VALUES("' + str(i) + '", "'
            + get_name(name_list) + '", "derezzed", "NULL");')

# Insert Quorra into the known_isomorphic_algorithms table
cur_grid.execute(
        'INSERT INTO known_isomorphic_algorithms (id, name, status, location) VALUES("0x21f3", "Quorra",'
        + ' "unknown", "unknown");')

# Insert into to_derezz table
for i in range(0x100):
    cur_grid.execute(
            'INSERT INTO to_derezz (id, name, status, location) VALUES ("' + str(i) + '", "'
            + get_name(name_list) + '", "idle", "' + get_loc(to_derezz=True) + '");')


# Commit changes
cur_grid.close()
db_grid.commit()
db_grid.close()
