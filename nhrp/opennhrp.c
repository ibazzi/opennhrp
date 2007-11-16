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

			peer = nhrp_peer_alloc();
			peer->type = NHRP_PEER_TYPE_STATIC;
			peer->interface = iface;
			nhrp_address_parse(addr, &peer->protocol_address,
					   &peer->prefix_length);
			peer->protocol_type = nhrp_protocol_from_pf(peer->protocol_address.type);
			nhrp_address_parse(nbma, &peer->next_hop_address, NULL);
			peer->afnum = nhrp_afnum_from_pf(peer->next_hop_address.type);
			nhrp_peer_insert(peer);
			nhrp_peer_free(peer);
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
	if (!signal_init())
		return 2;
	if (!load_config("/etc/opennhrp/opennhrp.conf"))
		return 3;
	if (!kernel_init())
		return 4;

	nhrp_task_run();

	return 0;
}
