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

const char *nhrp_config_file = "/etc/opennhrp/opennhrp.conf";
const char *nhrp_script_file = "/etc/opennhrp/opennhrp-script";

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
#define NEED_INTERFACE() if (iface == NULL) { rc = 2; break; } peer = NULL;
#define NEED_PEER() if (peer == NULL) { rc = 3; break; }

	static const char *errors[] = {
		"syntax error",
		"missing keyword",
		"interface context not defined",
		"register is used with map",
	};
	struct nhrp_interface *iface = NULL;
	struct nhrp_peer *peer = NULL;
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
			peer = NULL;
		} else if (strcmp(word, "map") == 0) {
			NEED_INTERFACE();
			read_word(in, &lineno, sizeof(addr), addr);
			read_word(in, &lineno, sizeof(nbma), nbma);

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
		} else if (strcmp(word, "register") == 0) {
			NEED_PEER();
			peer->flags |= NHRP_PEER_FLAG_REGISTER;
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

int usage(const char *prog)
{
	fprintf(stderr, "usage: %s [-c config-file] [-s script-file]\n", prog);
	return 1;
}

int main(int argc, char **argv)
{
	int i;

	for (i = 1; i < argc; i++) {
		if (strlen(argv[i]) != 2 || argv[i][0] != '-')
			return usage(argv[0]);

		switch (argv[i][1]) {
		case 'c':
			if (++i >= argc)
				return usage(argv[0]);
			nhrp_config_file = argv[i];
			break;
		case 's':
			if (++i >= argc)
				return usage(argv[0]);
			nhrp_script_file = argv[i];
			break;
		default:
			return usage(argv[0]);
		}
	}

	if (!log_init())
		return 1;
	if (!signal_init())
		return 2;
	if (!load_config(nhrp_config_file))
		return 3;
	if (!forward_init())
		return 4;
	if (!kernel_init())
		return 5;

	nhrp_task_run();

	return 0;
}
