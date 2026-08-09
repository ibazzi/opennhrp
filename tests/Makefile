CC ?= gcc
CFLAGS ?= -g -O2
CFLAGS += -Wall -Wextra -Werror -std=gnu99 -I../nhrp

.PHONY: all test clean

all: test_extensions test_ha_wire test_ha_auth test_ha_seen test_ha_control test_ha_store test_ha_delta test_ha_failback test_ha_managed test_ha_join test_coordinator

test: all
	./test_extensions
	./test_ha_wire
	./test_ha_auth
	./test_ha_seen
	./test_ha_control
	./test_ha_store
	./test_ha_delta
	./test_ha_failback
	./test_ha_managed
	./test_ha_join
	./test_coordinator

test_extensions: test_extensions.c ../nhrp/nhrp_extension.c
	$(CC) $(CFLAGS) -o $@ $^

test_ha_wire: test_ha_wire.c ../nhrp/nhrp_ha_wire.c
	$(CC) $(CFLAGS) -o $@ $^

test_ha_auth: test_ha_auth.c ../nhrp/nhrp_ha_auth.c
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto

test_ha_seen: test_ha_seen.c ../nhrp/nhrp_ha_seen.c ../nhrp/nhrp_ha_auth.c
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto

test_ha_control: test_ha_control.c ../nhrp/nhrp_ha_control.c ../nhrp/nhrp_ha_auth.c
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto

test_ha_store: test_ha_store.c ../nhrp/nhrp_ha_store.c ../nhrp/nhrp_ha_control.c ../nhrp/nhrp_ha_auth.c
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto

test_ha_delta: test_ha_delta.c ../nhrp/nhrp_ha_delta.c
	$(CC) $(CFLAGS) -o $@ $^

test_ha_failback: test_ha_failback.c ../nhrp/nhrp_ha_failback.c
	$(CC) $(CFLAGS) -o $@ $^

test_ha_managed: test_ha_managed.c ../nhrp/nhrp_ha_managed.c ../nhrp/nhrp_ha_auth.c
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto

test_ha_join: test_ha_join.c ../nhrp/nhrp_ha_join.c ../nhrp/nhrp_ha_managed.c ../nhrp/nhrp_ha_auth.c
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto

test_coordinator: test_coordinator.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f test_extensions test_ha_wire test_ha_auth test_ha_seen test_ha_control test_ha_store test_ha_delta test_ha_failback test_ha_managed test_ha_join test_coordinator
