#define OPENNHRP_VERSION "config-test"
#define OPENNHRP_ADMIN_SOCKET "/tmp/opennhrp-config-test-unused.socket"
#define main unused_opennhrp_main
#include "../nhrp/opennhrp.c"
#undef main
#include <assert.h>

void nhrp_log(int level, const char *format, ...) {
  (void)level;
  (void)format;
}

void nhrp_perror(const char *message) { assert(!message); }

static int fail_realloc;
void *__real_realloc(void *pointer, size_t size);
void *__wrap_realloc(void *pointer, size_t size) {
  if (fail_realloc) {
    fail_realloc = 0;
    errno = ENOMEM;
    return NULL;
  }
  return __real_realloc(pointer, size);
}

static void write_config(const char *path, const char *text) {
  FILE *file = fopen(path, "w");
  assert(file != NULL);
  assert(fputs(text, file) >= 0);
  assert(fclose(file) == 0);
}

int main(void) {
  char path[] = "/tmp/opennhrp-config-test.XXXXXX";
  struct nhrp_interface *iface;
  struct nhrp_buffer *auth;
  struct nhrp_address *addresses;
  struct nhrp_peer *peers[2];
  unsigned int i;
  int fd = mkstemp(path);

  ev_default_loop(0);
  assert(fd >= 0 && close(fd) == 0);
  write_config(path, "interface test0\n cisco-authentication first\n"
                     " multicast 239.1.1.1\ninterface test0\n"
                     " multicast 239.1.1.2\n");
  for (i = 0; i < 1000; i++) {
    assert(load_config(path));
    iface = nhrp_interface_get_by_name("test0", FALSE);
    assert(iface != NULL && iface->mcast_numaddr == 2);
    assert(iface->auth_token != NULL && iface->auth_token->length == 9);
  }
  auth = iface->auth_token;
  addresses = iface->mcast_addr;
  for (i = 0; i < 2; i++) {
    peers[i] = nhrp_peer_alloc(iface);
    peers[i]->type = NHRP_PEER_TYPE_HA_ACTIVE;
    peers[i]->flags = NHRP_PEER_FLAG_UP;
    peers[i]->protocol_address = addresses[i];
    peers[i]->prefix_length = 32;
    nhrp_peer_insert(peers[i]);
    nhrp_peer_update_multicast(peers[i]);
    assert(list_hashed(&peers[i]->mcast_list_entry));
  }
  write_config(path, "interface test0\n cisco-authentication second\n"
                     " multicast 239.2.2.2\n");
  fail_realloc = 1;
  assert(!load_config(path) && !fail_realloc);
  assert(iface->auth_token == auth && iface->mcast_addr == addresses);
  assert(iface->mcast_numaddr == 2);
  write_config(path, "interface test0\n cisco-authentication second\n"
                     " multicast 239.2.2.2\n invalid-option\n");
  for (i = 0; i < 1000; i++) {
    assert(!load_config(path));
    assert(iface->auth_token == auth && iface->mcast_addr == addresses);
    assert(iface->mcast_numaddr == 2);
    assert(list_hashed(&peers[0]->mcast_list_entry));
    assert(list_hashed(&peers[1]->mcast_list_entry));
  }
  write_config(path, "interface test0\n multicast 239.1.1.2\n");
  assert(load_config(path));
  assert(!list_hashed(&peers[0]->mcast_list_entry));
  assert(list_hashed(&peers[1]->mcast_list_entry));
  write_config(path, "interface test0\n cisco-authentication second\n"
                     " cisco-authentication third\n multicast nhs\n");
  assert(load_config(path));
  assert(iface->mcast_numaddr == 0 && iface->mcast_addr == NULL);
  assert(iface->mcast_mask != 0);
  assert(list_hashed(&peers[0]->mcast_list_entry));
  assert(list_hashed(&peers[1]->mcast_list_entry));
  assert(iface->auth_token->length == 9);
  assert(memcmp(iface->auth_token->data + 4, "third", 5) == 0);
  write_config(path, "interface test0\n");
  assert(load_config(path));
  assert(iface->auth_token == NULL && iface->mcast_mask == 0);
  assert(iface->mcast_numaddr == 0 && iface->mcast_addr == NULL);
  for (i = 0; i < 2; i++) {
    assert(!list_hashed(&peers[i]->mcast_list_entry));
    peers[i]->flags |= NHRP_PEER_FLAG_REPLACED;
    nhrp_peer_remove(peers[i]);
    nhrp_peer_put(peers[i]);
  }
  nhrp_interface_cleanup();
  ev_loop_destroy();
  assert(unlink(path) == 0);
  puts("configuration reload ownership tests passed");
  return 0;
}
