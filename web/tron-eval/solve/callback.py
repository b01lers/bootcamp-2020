#!/usr/bin/env python3

from flask import Flask, request
app = Flask(__name__)


@app.route('/', methods=['POST'])
def flag_route():
    print(request.values["data"].rstrip() + "\n")
    return "Thanks", 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
