#!/usr/bin/env python3

from flask import Flask, render_template, request, send_file

app = Flask(__name__)

flag = ""
with open("flag.txt") as flag_file:
    flag = flag_file.read()


@app.route('/')
def index():
    return render_template('index.html', user_agent=request.headers["User-Agent"])


@app.route('/tron_city')
def tron_city():
    description = "Tron City is the main city in the Tron system. It is built on the Grid, Kevin Flynn's master creation, and is the pinnacle of his \"digital frontier\". It is constructed in a hexagonal shape, with a deep chasm surrounding its perimeter. Bridges connect it to the surrounding area and form highly defensible choke points against any surface-based aggression. The city, like the Grid around it, matches the darkened environment of the rest of the Tron system. The gloom is offset by brilliant white illumination, meandering throughout the city like circuits on on a printed circuit board."

    return render_template('content_page.html', title="Tron City", image_name="tron_city.jpg", description=description)


@app.route('/sea_of_simulation')
def sos():
    description = "In the Tron system, the Sea of Simulation surrounded the Grid, forming, along with the Outlands, a barrier to prevent programs from finding their way to the Portal. It was a vast expanse of digital liquid racked by storms and broken by jagged islands of code; giant boulders floated above it, supported by single blue light-beams, and geometric arrays of bubbles extended far into its depths."

    return render_template('content_page.html', title="Sea of Simulation", image_name="SeaofSim01.webp", description=description)


@app.route('/disc_arena')
def disk_arena():
    description = "The Disc Arena is a content_page in the Game Grid, where programs play gladiator disc games against other programs. The games usually involve two, four or five players. In the game, the program uses his or her identity disc as a weapon by throwing it at opponents and to block attacks."

    return render_template('content_page.html', title="Disc Arena", image_name="disc_war.png", description=description)


@app.route('/0001001_club')
def club():
    description = "The 0001001 Club is one of the few entertainment areas in Argon City. It features a broad dance floor surrounded by strobing walls of ever-changing patterns and colors. A bar stretches along one wall, and booths with tables are arrayed along the sides. House music is played at all times. The club is extremely popular, and the floor is usually packed with dancing programs. During the Occupation, numerous guards and sentries were also in frequent attendance."

    return render_template('content_page.html', title="0001001 Club", image_name="0001001_Club.webp", description=description)


@app.route('/portal')
def portal():
    description = "The Portal is the gateway that allows digitized users to exit the Tron system to the real world. The structure housing the Portal rises out of the Sea of Simulation on an island pinnacle of rock. A small landing strip provides an approach to the site, and this in turn is connected to a long stairway ascending to the Portal. The top of the stair opens out onto a narrow causeway that spans out into the Portal itself."

    return render_template('content_page.html', title="Portal", image_name="portal.webp", description=description)


@app.route('/program')
def program():
    ua = request.headers["User-Agent"]
    description = "Your user got you down, no need to worry! Programs Only is the newest, lowest latency way to find other down to ground singles! This service is open to all programs, logical, functional, and recursive!\nRegister now and you could be next to jump start your next electric relationship!"

    if ua == "Program" or ua == "Master Control Program 0000":
        return render_template('content_page.html', title="Programs Only", description=description)

    return render_template('content_page.html', title="Unauthorized", description="Users do not have access to this resource."), 403


@app.route('/program/control')
def program_control():
    ua = request.headers["User-Agent"]

    if ua == "Master Control Program 0000":
        return render_template('content_page.html', title="Master Control", description=flag)

    return render_template('content_page.html', title="Unauthorized", description="Users and regular programs do not have access to this resource."), 403


@app.route('/robots.txt')
def robots():
    return send_file('robots.txt')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
