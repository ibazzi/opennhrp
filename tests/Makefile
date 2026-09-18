CC ?= gcc
CFLAGS ?= -g -O2
CFLAGS += -Wall -Wextra -Werror -std=gnu99 -I../nhrp/core -I../nhrp/ha \
	  -I../nhrp -I../nhrp/platform

BUILD_DIR ?= ../build/tests
TESTS := test_extensions test_ha_wire test_ha_auth test_ha_seen \
	test_ha_control test_ha_store test_ha_delta test_ha_failback \
	test_ha_managed test_ha_join test_coordinator
TEST_BINS := $(addprefix $(BUILD_DIR)/,$(TESTS))

.PHONY: all test clean

all: $(TEST_BINS)

test: all
	@set -e; for test in $(TEST_BINS); do $$test; done

$(TEST_BINS): | $(BUILD_DIR)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/test_extensions: test_extensions.c ../nhrp/core/nhrp_extension.c
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/test_ha_wire: test_ha_wire.c ../nhrp/ha/nhrp_ha_wire.c
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/test_ha_auth: test_ha_auth.c ../nhrp/ha/nhrp_ha_auth.c
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto

$(BUILD_DIR)/test_ha_seen: test_ha_seen.c ../nhrp/ha/nhrp_ha_seen.c ../nhrp/ha/nhrp_ha_auth.c
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto

$(BUILD_DIR)/test_ha_control: test_ha_control.c ../nhrp/ha/nhrp_ha_control.c ../nhrp/ha/nhrp_ha_auth.c
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto

$(BUILD_DIR)/test_ha_store: test_ha_store.c ../nhrp/ha/nhrp_ha_store.c ../nhrp/ha/nhrp_ha_control.c ../nhrp/ha/nhrp_ha_auth.c
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto

$(BUILD_DIR)/test_ha_delta: test_ha_delta.c ../nhrp/ha/nhrp_ha_delta.c
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/test_ha_failback: test_ha_failback.c ../nhrp/ha/nhrp_ha_failback.c
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/test_ha_managed: test_ha_managed.c ../nhrp/ha/nhrp_ha_managed.c ../nhrp/ha/nhrp_ha_auth.c
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto

$(BUILD_DIR)/test_ha_join: test_ha_join.c ../nhrp/ha/nhrp_ha_join.c ../nhrp/ha/nhrp_ha_managed.c ../nhrp/ha/nhrp_ha_auth.c
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto

$(BUILD_DIR)/test_coordinator: test_coordinator.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BUILD_DIR)
