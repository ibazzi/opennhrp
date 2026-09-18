/* Exercise the real output queue and peer cursor with small Unix socket
 * buffers. */
#include <errno.h>
#include <sys/socket.h>

static int interrupt_send;
static ssize_t test_send(int fd, const void *data, size_t size, int flags) {
  if (interrupt_send) {
    interrupt_send = 0;
    errno = EINTR;
    return -1;
  }
  return send(fd, data, size, flags);
}
#define send test_send
#include "../nhrp/admin.c"
#undef send
#include "../nhrp/core/nhrp_peer.c"
#include <assert.h>

int nhrp_verbose;
void nhrp_log(int level, const char *format, ...) {
  (void)level;
  (void)format;
}

size_t nhrp_ha_render(char *buffer, size_t size, const char *interface_name,
                      int json) {
  (void)interface_name;
  (void)json;
  memset(buffer, 'x', size);
  return size;
}

static struct admin_remote *remote_new(int fd) {
  struct admin_remote *r = calloc(1, sizeof(*r));
  assert(r);
  list_init(&r->monitor_list_entry);
  ev_io_init(&r->io, NULL, fd, EV_READ);
  ev_io_init(&r->output_io, admin_send_cb, fd, EV_WRITE);
  ev_idle_init(&r->enumeration, admin_enumerate_cb);
  ev_timer_init(&r->timeout, admin_timeout_cb, 10., 0.);
  return r;
}

int main(void) {
  int fd[2], small = 1024;
  size_t total = 0, i;
  char *data = malloc(200000), buffer[3001];
  struct admin_remote *r;
  struct nhrp_peer peers[400] = {0};
  struct nhrp_peer_cursor a = {0}, b = {0};

  ev_default_loop(0);
  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) == 0);
  assert(setsockopt(fd[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) == 0);
  r = remote_new(fd[0]);
  for (i = 0; i < 200000; i++)
    data[i] = (char)(i % 251);
  admin_raw_write(r, data, 200000);
  interrupt_send = 1;
  admin_send_cb(&r->output_io, EV_WRITE);
  assert(!interrupt_send);
  assert(r->output_start > 0 && r->output_start < r->output_end);
  i = r->output_start;
  admin_send_cb(&r->output_io, EV_WRITE);
  assert(r->output_start == i); /* EAGAIN preserves pending bytes. */
  while (total < 200000) {
    ssize_t n = recv(fd[1], buffer, sizeof(buffer), 0);
    if (n > 0) {
      assert(memcmp(buffer, data + total, n) == 0);
      total += n;
    } else {
      assert(errno == EAGAIN);
    }
    admin_send_cb(&r->output_io, EV_WRITE);
  }
  assert(r->output_start == r->output_end);
  admin_finish(r);
  assert(recv(fd[1], buffer, sizeof(buffer), 0) == 0);
  close(fd[1]);

  /* Temporary reply peers need not have been inserted in the cache. */
  list_init(&peers[0].enumeration_entry);
  enumeration_remove(&peers[0]);
  assert(list_empty(&enumeration_peers));

  /* Removing the next peer repairs all live cursors; additions are not
   * revisited. */
  for (i = 0; i < 400; i++) {
    peers[i].type = NHRP_PEER_TYPE_CACHED;
    list_add(&peers[i].enumeration_entry, &enumeration_peers);
  }
  nhrp_peer_cursor_open(&a);
  nhrp_peer_cursor_open(&b);
  assert(nhrp_peer_cursor_next(&a) == &peers[399]);
  enumeration_remove(&peers[398]);
  assert(nhrp_peer_cursor_next(&a) == &peers[397]);
  assert(nhrp_peer_cursor_next(&b) == &peers[399]);
  assert(nhrp_peer_cursor_next(&b) == &peers[397]);
  list_add(&peers[398].enumeration_entry, &enumeration_peers);
  for (i = 397; i > 0; i--)
    assert(nhrp_peer_cursor_next(&a) == &peers[i - 1]);
  assert(nhrp_peer_cursor_next(&a) == NULL);
  nhrp_peer_cursor_close(&a);
  nhrp_peer_cursor_close(&b);

  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) == 0);
  r = remote_new(fd[0]);
  r->selector.type_mask = BIT(NHRP_PEER_TYPE_CACHED);
  nhrp_peer_cursor_open(&r->cursor);
  admin_enumerate_cb(&r->enumeration, 0);
  assert(r->cursor.next != NULL && !r->complete); /* Only 128 examined. */
  admin_free_remote(r);
  assert(list_empty(&enumeration_cursors));
  close(fd[1]);
  for (i = 0; i < 400; i++)
    enumeration_remove(&peers[i]);

  /* Deferred replies flush before close; dead clients cannot raise SIGPIPE. */
  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) == 0);
  r = remote_new(fd[0]);
  r->deferred = TRUE;
  admin_ha_activate_done(r, 0, "activated", 7);
  assert(r->complete && !r->deferred);
  admin_send_cb(&r->output_io, EV_WRITE);
  assert(recv(fd[1], buffer, sizeof(buffer), 0) > 0);
  assert(recv(fd[1], buffer, sizeof(buffer), 0) == 0);
  close(fd[1]);
  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) == 0);
  r = remote_new(fd[0]);
  close(fd[1]);
  admin_raw_write(r, "test", 4);
  admin_send_cb(&r->output_io, EV_WRITE);

  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) == 0);
  r = remote_new(fd[0]);
  r->monitor = TRUE;
  list_add_tail(&r->monitor_list_entry, &ha_monitors);
  admin_raw_write(r, data, 200000);
  assert(r->output_capacity <= ADMIN_OUTPUT_LIMIT);
  for (i = 0; i < 4; i++)
    admin_ha_notify(NULL);
  assert(list_empty(&ha_monitors)); /* Overflow closes without EV_WRITE. */
  assert(recv(fd[1], buffer, sizeof(buffer), 0) == 0);
  close(fd[1]);

  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) == 0);
  r = remote_new(fd[0]);
  admin_timeout_cb(&r->timeout, 0);
  assert(recv(fd[1], buffer, sizeof(buffer), 0) == 0);
  close(fd[1]);
  free(data);
  ev_default_destroy();
  puts("PASS: admin short writes, EINTR/EAGAIN, cursor mutation, budgets, "
       "deferred "
       "replies, limits and disconnects");
  return 0;
}
