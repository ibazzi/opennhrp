/* nhrp_address.h - NHRP address structures and helpers
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#ifndef NHRP_ADDRESS_H
#define NHRP_ADDRESS_H

#include <stdint.h>

#define NHRP_MAX_ADDRESS_LEN            6

struct nhrp_address {
	uint16_t type;
	uint8_t addr_len;
	uint8_t subaddr_len;
	uint8_t addr[NHRP_MAX_ADDRESS_LEN];
};

uint16_t nhrp_protocol_from_pf(uint16_t pf);
uint16_t nhrp_pf_from_protocol(uint16_t protocol);
uint16_t nhrp_afnum_from_pf(uint16_t pf);
uint16_t nhrp_pf_from_afnum(uint16_t afnum);

int nhrp_address_parse(const char *string, struct nhrp_address *addr, uint8_t *prefix_len);
void nhrp_address_set_type(struct nhrp_address *addr, uint16_t type);
int nhrp_address_set(struct nhrp_address *addr, uint16_t type, uint8_t len, uint8_t *bytes);
int nhrp_address_set_full(struct nhrp_address *addr, uint16_t type, uint8_t len, uint8_t *bytes, uint8_t sublen, uint8_t *subbytes);
int nhrp_address_cmp(struct nhrp_address *a, struct nhrp_address *b);
void nhrp_address_mask(struct nhrp_address *addr, int prefix);
const char *nhrp_address_format(struct nhrp_address *addr,
				size_t buflen, char *buffer);

#endif