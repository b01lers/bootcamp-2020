#!/usr/bin/env python3

from flask import Flask, render_template, request
import MySQLdb

app = Flask(__name__)


def query(query):
    db = MySQLdb.connect(host='localhost', user='selection_program', passwd='designation2-503', db='grid')
    cursor = db.cursor()
    try:
        cursor.execute(query + " LIMIT 20;")
        results = cursor.fetchall()
        cursor.close()
        db.close()
        return results
    except MySQLdb.ProgrammingError as e:
        print(e)
        return 1
    except MySQLdb.OperationalError as e:
        print(e)
        return 2


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        query_str = request.form['query']
        results = query(query_str)

        if results == 1:
            return render_template('index.html', error="Syntax error in query."), 500
        elif results == 2:
            return render_template('index.html', error="MySQLdb.OperationalError."), 500
    else:
        results = None

    return render_template('index.html', results=results)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
