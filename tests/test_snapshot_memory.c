#include "../nhrp/ha/nhrp_ha_coordinator.c"
#include <assert.h>

static void *tracked_delta;
static unsigned int allocations, releases;

int __real_nhrp_ha_delta_build(const uint8_t *, size_t, const uint8_t *, size_t,
                               uint8_t **, size_t *);
int __wrap_nhrp_ha_delta_build(const uint8_t *old, size_t old_length,
                               const uint8_t *current, size_t current_length,
                               uint8_t **delta, size_t *length) {
  int ok;

  tracked_delta = NULL;
  ok = __real_nhrp_ha_delta_build(old, old_length, current, current_length,
                                  delta, length);
  if (ok) {
    tracked_delta = *delta;
    allocations++;
  }
  return ok;
}

void __real_free(void *);
void __wrap_free(void *pointer) {
  if (pointer != NULL && pointer == tracked_delta) {
    releases++;
    tracked_delta = NULL;
  }
  __real_free(pointer);
}

int main(void) {
  struct managed_runtime runtime = {0};
  struct managed_peer peer = {0};
  struct nhrp_ha_control_frame frame;
  uint8_t key[32] = {1}, matched[8], wire[2048];
  uint8_t previous[] = "";
  uint8_t current[] =
      "entry 10.20.0.2 32 192.0.2.2 - 1400 900 0 1 1 1 hub-primary direct\n";
  uint32_t length;
  unsigned int i;
  int fd[2];

  assert(nhrp_ha_auth_key_from_bytes(&runtime.keys.key[0], key));
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
  runtime.previous_snapshot = previous;
  runtime.previous_index = 1;
  runtime.current_snapshot = current;
  runtime.current_snapshot_length = sizeof(current) - 1;
  runtime.local_index = 2;
  runtime.state.term = 1;
  strcpy(runtime.state.local_member, "hub-primary");
  strcpy(runtime.state.leader, "hub-primary");
  peer.fd = fd[0];
  peer.match_index = 1;
  for (i = 0; i < 1000; i++) {
    assert(snapshot_send(&runtime, &peer));
    assert(allocations == releases && allocations == i + 1);
    assert(read_all(fd[1], wire, 4));
    memcpy(&length, wire, 4);
    length = ntohl(length) + 4;
    assert(length <= sizeof(wire) && read_all(fd[1], wire + 4, length - 4));
    assert(nhrp_ha_control_decode(&runtime.keys, wire, length, &frame,
                                  matched) == NHRP_HA_CONTROL_OK);
    assert(frame.type == NHRP_HA_CONTROL_SNAPSHOT);
  }
  close(fd[1]);
  assert(!snapshot_send(&runtime, &peer));
  assert(allocations == releases);
  close(fd[0]);
  nhrp_ha_auth_keys_clear(&runtime.keys);
  puts("snapshot fallback allocation tests passed");
  return 0;
}
