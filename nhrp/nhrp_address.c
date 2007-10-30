/* nhrp_address.c - NHRP address conversion functions
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "afnum.h"
#include "nhrp_address.h"

int nhrp_protocol_address_parse(const char *string, uint16_t *protocol_type,
				struct nhrp_protocol_address *addr, uint8_t *prefix_len)
{
	uint8_t tmp;
	int r;

	/* Try IP address format */
	r = sscanf(string, "%hhd.%hhd.%hhd.%hhd/%hhd",
		   &addr->addr[0], &addr->addr[1],
		   &addr->addr[2], &addr->addr[3],
		   prefix_len ? prefix_len : &tmp);
	if ((r == 4) || (r == 5 && prefix_len != NULL)) {
		*protocol_type = ETHP_IP;
		addr->addr_len = 4;
		if (r == 4 && prefix_len != NULL)
			*prefix_len = 32;
		return TRUE;
	}

	return FALSE;
}

int nhrp_protocol_address_set(
	struct nhrp_protocol_address *addr, uint8_t len, uint8_t *bytes)
{
	if (len > NHRP_MAX_ADDRESS_LEN)
		return FALSE;

	addr->addr_len = len;
	if (len != 0)
		memcpy(addr->addr, bytes, len);
	return TRUE;
}

int nhrp_protocol_address_cmp(struct nhrp_protocol_address *a, struct nhrp_protocol_address *b)
{
	if (a->addr_len > b->addr_len)
		return 1;
	if (a->addr_len < b->addr_len)
		return -1;
	return memcmp(a->addr, b->addr, a->addr_len);
}

const char *nhrp_protocol_address_format(
	uint16_t protocol_type,
	struct nhrp_protocol_address *addr,
	size_t buflen, char *buffer)
{
	switch (protocol_type) {
	case ETHP_IP:
		snprintf(buffer, buflen, "%d.%d.%d.%d",
			 addr->addr[0], addr->addr[1],
			 addr->addr[2], addr->addr[3]);
		break;
	default:
		snprintf(buffer, buflen, "(unsupported proto 0x%04x)",
			 protocol_type);
		break;
	}

	return buffer;
}

int nhrp_nbma_address_parse(const char *string, uint16_t *afnum,
			    struct nhrp_nbma_address *addr)
{
	struct in_addr inaddr;

	if (inet_aton(string, &inaddr)) {
		*afnum = AFNUM_INET;
		addr->addr_len = 4;
		memcpy(addr->addr, &inaddr.s_addr, 4);
		return TRUE;
	}

	return FALSE;
}

int nhrp_nbma_address_set(
	struct nhrp_nbma_address *addr,
	uint8_t len, uint8_t *bytes,
	uint8_t sublen, uint8_t *subbytes)
{
	if (len > NHRP_MAX_ADDRESS_LEN ||
	    sublen > NHRP_MAX_SUBADDRESS_LEN)
		return FALSE;

	addr->addr_len = len;
	addr->subaddr_len = sublen;
	if (len != 0)
		memcpy(addr->addr, bytes, len);
	if (sublen != 0)
		memcpy(addr->subaddr, subbytes, sublen);
	return TRUE;
}

int nhrp_nbma_address_cmp(
	struct nhrp_nbma_address *a, struct nhrp_nbma_address *b)
{
	int r;

	if (a->addr_len > b->addr_len)
		return 1;
	if (a->addr_len < b->addr_len)
		return -1;
	if (a->subaddr_len > b->subaddr_len)
		return 1;
	if (a->subaddr_len < b->subaddr_len)
		return -1;
	r = memcmp(a->addr, b->addr, a->addr_len);
	if (r != 0)
		return r;
	return memcmp(a->subaddr, b->subaddr, a->subaddr_len);
}

const char *nhrp_nbma_address_format(
	uint16_t afnum,
	struct nhrp_nbma_address *addr,
	size_t buflen, char *buffer)
{
	switch (afnum) {
	case AFNUM_INET:
		snprintf(buffer, buflen, "%d.%d.%d.%d",
			 addr->addr[0], addr->addr[1],
			 addr->addr[2], addr->addr[3]);
		break;
	default:
		snprintf(buffer, buflen, "(unsupported afnum 0x%04x)",
			 afnum);
		break;
	}

	return buffer;
}
