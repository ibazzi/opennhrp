/* sysdep_syslog.c - Logging via syslog
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>

#include "nhrp_defines.h"
#include "nhrp_common.h"

int log_init(void)
{
	openlog("opennhrp", LOG_PERROR | LOG_PID, LOG_DAEMON);

	return TRUE;
}

void nhrp_perror(const char *message)
{
	nhrp_error("%s: %s", message, strerror(errno));
}

void nhrp_error(const char *format, ...)
{
	va_list va;

	va_start(va, format);
	vsyslog(LOG_ERR, format, va);
	va_end(va);
}

void nhrp_info(const char *format, ...)
{
	va_list va;

	va_start(va, format);
	vsyslog(LOG_INFO, format, va);
	va_end(va);
}
