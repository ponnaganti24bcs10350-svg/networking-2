CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -g -O2
TARGETS = bserve bcurl

.PHONY: all clean test test404

all: $(TARGETS)

bserve: bserve.c bhttp_protocol.h
	$(CC) $(CFLAGS) -o $@ bserve.c

bcurl: bcurl.c bhttp_protocol.h
	$(CC) $(CFLAGS) -o $@ bcurl.c

test: all
	@echo "=== Integration test ==="
	@mkdir -p www
	@echo "<html><body>Hello BHTTP!</body></html>" > www/index.html
	@./bserve ./www 19000 &
	@SERVER_PID=$$!; \
	sleep 0.3; \
	./bcurl -v localhost:19000/index.html > /tmp/bhttp_body.txt 2>/tmp/bhttp_log.txt; \
	STATUS=$$?; \
	kill $$SERVER_PID 2>/dev/null; \
	echo "--- Response body ---"; \
	cat /tmp/bhttp_body.txt; \
	echo ""; \
	echo "--- Client log ---"; \
	cat /tmp/bhttp_log.txt; \
	if [ $$STATUS -eq 0 ]; then \
		echo "PASS: bcurl exited 0"; \
	else \
		echo "FAIL: bcurl exited $$STATUS"; exit 1; \
	fi

test404: all
	@echo "=== 404 test ==="
	@mkdir -p www
	@./bserve ./www 19001 &
	@SERVER_PID=$$!; \
	sleep 0.3; \
	./bcurl -v localhost:19001/does_not_exist.html > /dev/null 2>/tmp/bhttp404.txt; \
	STATUS=$$?; \
	kill $$SERVER_PID 2>/dev/null; \
	cat /tmp/bhttp404.txt; \
	if [ $$STATUS -ne 0 ]; then \
		echo "PASS: bcurl exited non-zero on 404"; \
	else \
		echo "FAIL: bcurl should exit non-zero on 404"; exit 1; \
	fi

clean:
	rm -f $(TARGETS)
	rm -f /tmp/bhttp_body.txt /tmp/bhttp_log.txt /tmp/bhttp404.txt
