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
#include "nhrp_packet.h"

uint16_t nhrp_protocol_from_pf(uint16_t pf)
{
	switch (pf) {
	case PF_INET:
		return ETHPROTO_IP;
	}
	return 0;
}

uint16_t nhrp_pf_from_protocol(uint16_t protocol)
{
	switch (protocol) {
	case ETHPROTO_IP:
		return PF_INET;
	}
	return PF_UNSPEC;
}

uint16_t nhrp_afnum_from_pf(uint16_t pf)
{
	switch (pf) {
	case PF_INET:
		return AFNUM_INET;
	}
	return AFNUM_RESERVED;
}

uint16_t nhrp_pf_from_afnum(uint16_t afnum)
{
	switch (afnum) {
	case AFNUM_INET:
		return PF_INET;
	}
	return PF_UNSPEC;
}

int nhrp_address_parse(const char *string,
		       struct nhrp_address *addr,
		       uint8_t *prefix_len)
{
	uint8_t tmp;
	int r;

	/* Try IP address format */
	r = sscanf(string, "%hhd.%hhd.%hhd.%hhd/%hhd",
		   &addr->addr[0], &addr->addr[1],
		   &addr->addr[2], &addr->addr[3],
		   prefix_len ? prefix_len : &tmp);
	if ((r == 4) || (r == 5 && prefix_len != NULL)) {
		addr->type = PF_INET;
		addr->addr_len = 4;
		addr->subaddr_len = 0;
		if (r == 4 && prefix_len != NULL)
			*prefix_len = 32;
		return TRUE;
	}

	return FALSE;
}

int nhrp_address_set(struct nhrp_address *addr, uint16_t type, uint8_t len, uint8_t *bytes)
{
	if (len > NHRP_MAX_ADDRESS_LEN)
		return FALSE;

	addr->type = type;
	addr->addr_len = len;
	addr->subaddr_len = 0;
	if (len != 0)
		memcpy(addr->addr, bytes, len);
	return TRUE;
}

int nhrp_address_set_full(struct nhrp_address *addr, uint16_t type,
			  uint8_t len, uint8_t *bytes,
			  uint8_t sublen, uint8_t *subbytes)
{
	if (len + sublen > NHRP_MAX_ADDRESS_LEN)
		return FALSE;

	addr->type = type;
	addr->addr_len = len;
	addr->subaddr_len = 0;
	if (len != 0)
		memcpy(addr->addr, bytes, len);
	if (sublen != 0)
		memcpy(&addr->addr[len], subbytes, sublen);
	return TRUE;
}

int nhrp_address_cmp(struct nhrp_address *a, struct nhrp_address *b)
{
	if (a->addr_len > b->addr_len || a->subaddr_len > b->subaddr_len)
		return 1;
	if (a->addr_len < b->addr_len || a->subaddr_len < b->subaddr_len)
		return -1;
	return memcmp(a->addr, b->addr, a->addr_len + a->subaddr_len);
}

void nhrp_address_mask(struct nhrp_address *addr, int prefix)
{
	int i, bits = 8 * addr->addr_len;

	for (i = prefix; i < bits; i++)
		addr->addr[i / 8] &= ~(0x80 >> (i % 8));
}

const char *nhrp_address_format(struct nhrp_address *addr,
				size_t buflen, char *buffer)
{
	switch (addr->type) {
	case PF_INET:
		snprintf(buffer, buflen, "%d.%d.%d.%d",
			 addr->addr[0], addr->addr[1],
			 addr->addr[2], addr->addr[3]);
		break;
	default:
		snprintf(buffer, buflen, "(proto 0x%04x)",
			 addr->type);
		break;
	}

	return buffer;
}

int nhrp_address_match_cie_list(struct nhrp_address *nbma_address,
				struct nhrp_address *protocol_address,
				struct nhrp_cie_list_head *cie_list)
{
	struct nhrp_cie *cie;

	TAILQ_FOREACH(cie, cie_list, cie_list_entry) {
		if (nhrp_address_cmp(&cie->nbma_address, nbma_address) == 0 &&
		    nhrp_address_cmp(&cie->protocol_address, protocol_address) == 0)
			return TRUE;
	}

	return FALSE;
}

