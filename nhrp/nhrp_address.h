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

#define NHRP_MAX_ADDRESS_LEN		8
#define NHRP_MAX_SUBADDRESS_LEN		4
#define NHRP_MAX_EXTENSIONS		10

struct nhrp_nbma_address {
	uint8_t addr_len;
	uint8_t subaddr_len;
	uint8_t addr[NHRP_MAX_ADDRESS_LEN];
	uint8_t subaddr[NHRP_MAX_SUBADDRESS_LEN];
};

struct nhrp_protocol_address {
	uint8_t addr_len;
	uint8_t addr[NHRP_MAX_ADDRESS_LEN];
};

int nhrp_protocol_address_parse(
	const char *string, uint16_t *protocol_type,
	struct nhrp_protocol_address *addr, uint8_t *prefix_len);
int nhrp_protocol_address_set(
	struct nhrp_protocol_address *addr, uint8_t len, uint8_t *bytes);
int nhrp_protocol_address_cmp(
	struct nhrp_protocol_address *a, struct nhrp_protocol_address *b);
const char *nhrp_protocol_address_format(
	uint16_t protocol_type, struct nhrp_protocol_address *addr,
	size_t buflen, char *buffer);

int nhrp_nbma_address_parse(
	const char *string,
	uint16_t *afnum,
	struct nhrp_nbma_address *addr);
int nhrp_nbma_address_set(
	struct nhrp_nbma_address *addr,
	uint8_t len, uint8_t *bytes,
	uint8_t sublen, uint8_t *subbytes);
int nhrp_nbma_address_cmp(
	struct nhrp_nbma_address *a, struct nhrp_nbma_address *ab);
const char *nhrp_nbma_address_format(
	uint16_t afnum, struct nhrp_nbma_address *addr,
	size_t buflen, char *buffer);

#endif
