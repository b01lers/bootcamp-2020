all: build

PORT_PREFIX = 30
# Also the challenge number
PORT_POSTFIX = 02
NAME = tron-eval
FNAME = $(PORT_POSTFIX)-$(NAME)

build:
	docker build -t $(FNAME)-build .

run: start
start:
	docker run --rm -itd --name $(FNAME)-run -p $(PORT_PREFIX)$(PORT_POSTFIX):80 $(FNAME)-build

shell:
	docker exec -it $(FNAME)-run /bin/sh

stop:
	docker kill $(FNAME)-run
