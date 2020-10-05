all: build

PORT_PREFIX = 30
# Also the challenge number
PORT_POSTFIX = 01
NAME = js_console
FNAME = $(PORT_POSTFIX)-$(NAME)

build:
	docker build -t $(FNAME)-build .

run: start
start:
	docker run --rm -itd --name $(FNAME)-run -p $(PORT_PREFIX)$(PORT_POSTFIX):5000 $(FNAME)-build

stop:
	docker kill $(FNAME)-run
