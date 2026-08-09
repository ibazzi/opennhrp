/* sysdep_syslog.c - Logging via syslog
 *
 * Copyright (c) 2007-2012 Timo Teräs <timo.teras@iki.fi>
 *
 * This software is licensed under the MIT License.
 * See MIT-LICENSE.txt for additional details.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "nhrp_common.h"
#include "nhrp_defines.h"

int log_init(void) {
  int options = LOG_PID;

  /* systemd forwards stdout/stderr and syslog to the journal. Avoid
   * duplicating every message there, while retaining foreground logging
   * for direct and test invocations. */
  if (getenv("JOURNAL_STREAM") == NULL)
    options |= LOG_PERROR;
  openlog("opennhrp", options, LOG_DAEMON);

  return TRUE;
}

void nhrp_log(int level, const char *format, ...) {
  va_list va;
  int l;

  switch (level) {
  case NHRP_LOG_ERROR:
    l = LOG_ERR;
    break;
  case NHRP_LOG_INFO:
    l = LOG_INFO;
    break;
  case NHRP_LOG_DEBUG:
  default:
    l = LOG_DEBUG;
    break;
  }

  va_start(va, format);
  vsyslog(l, format, va);
  va_end(va);
}

void nhrp_perror(const char *message) {
  nhrp_error("%s: %s", message, strerror(errno));
}
