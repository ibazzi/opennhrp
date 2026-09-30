#include "libev.h"
#include <assert.h>
#include <stdio.h>
#include <unistd.h>

static int pipe_fds[2], received;

static void write_cb(ev_timer *w, int revents) {
  (void)w;
  assert(revents & EV_TIMER);
  assert(write(pipe_fds[1], "x", 1) == 1);
}

static void read_cb(ev_io *w, int revents) {
  char value;
  assert(revents & EV_READ);
  assert(read(w->fd, &value, 1) == 1 && value == 'x');
  received++;
  ev_io_stop(w);
  ev_break(EVBREAK_ALL);
}

static void timeout_cb(ev_timer *w, int revents) {
  (void)w;
  (void)revents;
  assert(!"libev event delivery timed out");
}

int main(void) {
  unsigned int backends[] = {EVBACKEND_EPOLL, EVBACKEND_POLL};
  assert(ev_version_major() == 4 && ev_version_minor() == 33);
  for (unsigned int i = 0; i < sizeof(backends) / sizeof(backends[0]); i++) {
    ev_io reader;
    ev_timer writer, timeout;
    assert(ev_default_loop(backends[i]));
    assert(ev_backend() == backends[i]);
    assert(pipe(pipe_fds) == 0);
    received = 0;
    ev_io_init(&reader, read_cb, pipe_fds[0], EV_READ);
    ev_timer_init(&writer, write_cb, .001, 0.);
    ev_timer_init(&timeout, timeout_cb, 1., 0.);
    ev_io_start(&reader);
    ev_timer_start(&writer);
    ev_timer_start(&timeout);
    ev_run(0);
    assert(received == 1);
    assert(!ev_is_active(&reader) && !ev_is_active(&writer));
    ev_timer_stop(&timeout);
    ev_loop_destroy();
    close(pipe_fds[0]);
    close(pipe_fds[1]);
  }
  puts("libev 4.33 epoll/poll tests passed");
  return 0;
}
