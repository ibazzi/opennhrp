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
#include <errno.h>
#include <malloc.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>

#include "nhrp_common.h"
#include "nhrp_peer.h"
#include "nhrp_interface.h"

const char *nhrp_admin_socket = OPENNHRP_ADMIN_SOCKET;
const char *nhrp_pid_file     = "/var/run/opennhrp.pid";
const char *nhrp_config_file  = "/etc/opennhrp/opennhrp.conf";
const char *nhrp_script_file  = "/etc/opennhrp/opennhrp-script";

static int pid_file_fd;

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
	int ch, i, comment = 0;

	ch = fgetc(in);
	while (1) {
		if (ch == '#')
			comment = 1;
		if (!comment && !isspace(ch))
			break;
		if (ch == EOF)
			return FALSE;
		if (ch == '\n') {
			(*lineno)++;
			comment = 0;
		}
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
		"invalid address",
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

			peer = nhrp_peer_alloc(iface);
			peer->type = NHRP_PEER_TYPE_STATIC;
			if (!nhrp_address_parse(addr, &peer->protocol_address,
						&peer->prefix_length)) {
				rc = 4;
				break;
			}
			peer->protocol_type = nhrp_protocol_from_pf(peer->protocol_address.type);
			if (!nhrp_address_parse(nbma, &peer->next_hop_address,
						NULL)) {
				if (!nhrp_address_resolve(nbma,
						&peer->next_hop_address)) {
					rc = 4;
					break;
				}
				peer->nbma_hostname = strdup(nbma);
			}
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

static void remove_pid_file(void)
{
	if (pid_file_fd != 0) {
		close(pid_file_fd);
		pid_file_fd = 0;
		remove(nhrp_pid_file);
	}
}

static int daemonize(void)
{
	char tmp[16];
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return FALSE;
	if (pid > 0)
		exit(0);

	if (setsid() < 0)
		return FALSE;

	pid = fork();
	if (pid < 0)
		return FALSE;
	if (pid > 0)
		exit(0);

	if (chdir("/") < 0)
		return FALSE;

	pid_file_fd = open(nhrp_pid_file, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (pid_file_fd < 0) {
		nhrp_error("Unable to open pid file: %s.", strerror(errno));
		return FALSE;
	}

	if (flock(pid_file_fd, LOCK_EX | LOCK_NB) < 0) {
		nhrp_error("Unable to lock pid file (already running?).");
		close(pid_file_fd);
		pid_file_fd = 0;
		return FALSE;
	}

	ftruncate(pid_file_fd, 0);
	write(pid_file_fd, tmp, sprintf(tmp, "%d\n", getpid()));
	atexit(remove_pid_file);

	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "w", stdout);
	freopen("/dev/null", "w", stderr);

	umask(0);

	return TRUE;
}

int usage(const char *prog)
{
	fprintf(stderr,
		"usage: opennhrp [-a admin-socket] [-c config-file] [-s script-file]\n"
		"                [-p pid-file] [-d]\n"
		"       opennhrp -V\n"
		"\n"
		"\t-a admin-socket\tspecify management interface socket\n"
		"\t-c config-file\tread configuration from config-file\n"
		"\t-s script-file\tuse specified script-file for event handling\n"
		"\t-p pid-file\tspecify pid-file\n"
		"\t-d\t\tfork to background after startup\n"
		"\t-V\t\tshow version number and exit\n"
		"\n");
	return 1;
}

int main(int argc, char **argv)
{
	int i, daemonmode = 0;

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
		case 'a':
			if (++i >= argc)
				return usage(argv[0]);
			nhrp_admin_socket = argv[i];
			break;
		case 'p':
			if (++i >= argc)
				return usage(argv[0]);
			nhrp_pid_file = argv[i];
			break;
		case 'd':
			daemonmode = 1;
			break;
		case 'V':
			puts("OpenNHRP " OPENNHRP_VERSION);
			return 0;
		default:
			return usage(argv[0]);
		}
	}

	if (!log_init())
		return 1;

	nhrp_info("OpenNHRP " OPENNHRP_VERSION " starting");
	if (!signal_init())
		return 2;
	if (!load_config(nhrp_config_file))
		return 3;
	if (!forward_init())
		return 4;
	if (!kernel_init())
		return 5;
	if (!admin_init(nhrp_admin_socket))
		return 6;

	if (daemonmode && !daemonize()) {
		nhrp_error("Failed to daemonize. Exit.");
		return 7;
	}

	nhrp_task_run();

	return 0;
}

