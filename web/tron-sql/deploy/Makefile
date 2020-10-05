all: build

PORT_PREFIX = 30
# Also the challenge number
PORT_POSTFIX = 04
NAME = tron_sql
FNAME = $(PORT_POSTFIX)-$(NAME)

build:
	docker build -t $(FNAME)-build .

run: start exec
start:
	docker run --rm -itd --name $(FNAME)-run -p $(PORT_PREFIX)$(PORT_POSTFIX):5000 -e MYSQL_ROOT_PASSWORD=d36beee28ef5770ff82d18250c458a9ba9477616f066b3e75fa5b298cf82356d $(FNAME)-build

exec:
	docker exec -itd $(FNAME)-run /entrypoint.sh

test:
	docker exec -it $(FNAME)-run bash

stop:
	docker kill $(FNAME)-run
