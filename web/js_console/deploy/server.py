#!/usr/bin/env python3

from flask import Flask, render_template, request
import threading
import random

app = Flask(__name__)

flag = ""
with open("flag.txt") as flag_file:
    flag = flag_file.read()


def update_token():
    global token
    threading.Timer(10.0, update_token).start()
    token = str(random.randint(100000000, 999999999))


token = ""
update_token()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/maze')
def maze():
    return render_template('maze.html')


@app.route('/token')
def token_route():
    return token, 200


@app.route('/mem', methods=['POST'])
def flag_route():
    if token == request.form['token']:
        return flag, 200
    else:
        return "Try again", 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
