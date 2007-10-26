/* nhrp_defines.h - NHRP definitions
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#ifndef NHRP_DEFINES_H
#define NHRP_DEFINES_H

#include <stdint.h>
#include <byteswap.h>

#ifndef NULL
#define NULL 0L
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
#define constant_ntohl(x) (x)
#define constant_ntohs(x) (x)
#define constant_htonl(x) (x)
#define constant_htons(x) (x)
#else
#define constant_ntohl(x) __bswap_constant_32(x)
#define constant_ntohs(x) __bswap_constant_16(x)
#define constant_htonl(x) __bswap_constant_32(x)
#define constant_htons(x) __bswap_constant_16(x)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#endif
