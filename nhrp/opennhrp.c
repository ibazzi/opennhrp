/* opennhrp.c - OpenNHRP main routines
 *
 * Copyright (C) 2007 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <ctype.h>
#include <stdio.h>
#include <malloc.h>
#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>

#include "nhrp_common.h"
#include "nhrp_peer.h"
#include "nhrp_interface.h"

void nhrp_hex_dump(const char *name, const uint8_t *buf, int bytes)
{
	int i, j;
	int left;

	fprintf(stderr, "%s:\n", name);
	for (i = 0; i < bytes; i++) {
		fprintf(stderr, "%02X ", buf[i]);
		if (i % 0x10 == 0x0f) {
			fprintf(stderr, "    ");
			for (j = 0; j < 0x10; j++)
				fprintf(stderr, "%c", isgraph(buf[i+j-0xf]) ?
					buf[i+j-0xf]: '.');
			fprintf(stderr, "\n");
		}
	}

	left = i % 0x10;
	if (left != 0) {
		fprintf(stderr, "%*s    ", 3 * (0x10 - left), "");

		for (j = 0; j < left; j++)
			fprintf(stderr, "%c", isgraph(buf[i+j-left]) ?
				buf[i+j-left]: '.');
		fprintf(stderr, "\n");
	}
	fprintf(stderr, "\n");
}


int nhrp_parse_protocol_address(const char *string, uint16_t *protocol_type,
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

const char *nhrp_format_protocol_address(
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

int nhrp_parse_nbma_address(const char *string, uint16_t *afnum,
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

const char *nhrp_format_nbma_address(
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

/*
nhrp_parse_protocol_address(addr, &peer->protocol_type,
	&peer->protocol_address,
	&peer->prefix_length);
nhrp_parse_nbma_address(nbma, &peer->afnum, &peer->nbma_address);
*/

static int read_word(FILE *in, int *lineno, size_t len, char *word)
{
	int ch, i;

	ch = fgetc(in);
	while (isspace(ch)) {
		if (ch == EOF)
			return FALSE;
		if (ch == '\n')
			(*lineno)++;
		ch = fgetc(in);
	}

	for (i = 0; i < len-1 && !isspace(ch); i++) {
		word[i] = ch;
		ch = fgetc(in);
		if (ch == EOF)
			return FALSE;
		if (ch == '\n')
			(*lineno)++;
	}
	word[i] = 0;

	return TRUE;
}

static int load_config(const char *config_file)
{
#define NEED_INTERFACE() if (iface == NULL) { rc = 2; break; }

	static const char *errors[] = {
		"syntax error",
		"missing keyword",
		"interface context not defined",
	};
	struct nhrp_interface *iface = NULL;
	char word[32], nbma[32], addr[32];
	FILE *in;
	int lineno = 1, rc = -1;

	in = fopen(config_file, "r");
	if (in == NULL) {
		nhrp_error("Unable to open configuration file '%s'.", config_file);
		return FALSE;
	}

	while (read_word(in, &lineno, sizeof(word), word)) {
		if (strcmp(word, "interface") == 0) {
			if (!read_word(in, &lineno, sizeof(word), word)) {
				rc = 1;
				break;
			}
			iface = nhrp_interface_get_by_name(word, TRUE);
		} else if (strcmp(word, "map") == 0) {
			struct nhrp_peer *peer;

			NEED_INTERFACE();
			read_word(in, &lineno, sizeof(addr), addr);
			read_word(in, &lineno, sizeof(nbma), nbma);
			read_word(in, &lineno, sizeof(word), word);

			if (strcmp(word, "register") == 0) {

			} else {
				rc = 0;
				break;
			}

			peer = calloc(1, sizeof(struct nhrp_peer));
			peer->type = NHRP_PEER_TYPE_STATIC;
			nhrp_parse_protocol_address(addr, &peer->protocol_type,
						    &peer->protocol_address,
						    &peer->prefix_length);
			nhrp_parse_nbma_address(nbma, &peer->afnum, &peer->nbma_address);
			peer->dst_protocol_address = peer->protocol_address;
			nhrp_peer_insert(peer);
		} else if (strcmp(word, "cisco-authentication") == 0) {
			struct nhrp_buffer *buf;
			struct nhrp_cisco_authentication_extension *auth;

			NEED_INTERFACE();
			read_word(in, &lineno, sizeof(word), word);

			buf = nhrp_buffer_alloc(strlen(word) + sizeof(uint32_t));
			auth = (struct nhrp_cisco_authentication_extension *) buf->data;
			auth->type = NHRP_AUTHENTICATION_PLAINTEXT;
			memcpy(auth->secret, word, strlen(word));

			iface->auth_token = buf;
		} else if (strcmp(word, "shortcut") == 0) {
			NEED_INTERFACE();
			iface->flags |= NHRP_INTERFACE_FLAG_SHORTCUT;
		} else if (strcmp(word, "redirect") == 0) {
			NEED_INTERFACE();
			iface->flags |= NHRP_INTERFACE_FLAG_REDIRECT;
		} else if (strcmp(word, "non-caching") == 0) {
			NEED_INTERFACE();
			iface->flags |= NHRP_INTERFACE_FLAG_NON_CACHING;
		} else if (strcmp(word, "shortcut-destination") == 0) {
			NEED_INTERFACE();
			iface->flags |= NHRP_INTERFACE_FLAG_SHORTCUT_DEST;
		} else {
			rc = 0;
			break;
		}
	}
	fclose(in);

	if (rc >= 0) {
		nhrp_error("Configuration file %s in %s:%d, near word '%s'",
			   errors[rc], config_file, lineno, word);
		return FALSE;
	}
	return TRUE;
}

int main(int argc, char **argv)
{
	if (!log_init())
		return 1;
	if (!load_config("../nhrp.conf"))
		return 2;
	if (!kernel_init())
		return 3;

	nhrp_task_run();

	return 0;
}
