/* opennhrp.c - OpenNHRP main routines
 *
 * Copyright (c) 2007-2012 Timo Teräs <timo.teras@iki.fi>
 *
 * This software is licensed under the MIT License.
 * See MIT-LICENSE.txt for additional details.
 */

#include <ctype.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <malloc.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <linux/rtnetlink.h>

#include "nhrp_common.h"
#include "nhrp_peer.h"
#include "nhrp_interface.h"

const char *nhrp_version_string =
	"OpenNHRP " OPENNHRP_VERSION
#ifdef NHRP_NO_NBMA_GRE
	" (no NBMA GRE support)"
#endif
	;

const char *nhrp_admin_socket = OPENNHRP_ADMIN_SOCKET;
const char *nhrp_pid_file     = "/var/run/opennhrp.pid";
const char *nhrp_config_file  = "/etc/opennhrp/opennhrp.conf";
const char *nhrp_script_file  = "/etc/opennhrp/opennhrp-script";
int nhrp_verbose = 0;
int nhrp_running = FALSE;

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

static void handle_signal_cb(struct ev_signal *w, int revents)
{
	switch (w->signum) {
	case SIGUSR1:
		nhrp_peer_dump_cache();
		break;
	case SIGINT:
	case SIGTERM:
		ev_unloop(EVUNLOOP_ALL);
		break;
	case SIGHUP:
		nhrp_reload_config();
		break;
	}
}

static int hook_signal[] = { SIGUSR1, SIGHUP, SIGINT, SIGTERM };
static ev_signal signal_event[ARRAY_SIZE(hook_signal)];

static void signal_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(hook_signal); i++) {
		ev_signal_init(&signal_event[i], handle_signal_cb,
			       hook_signal[i]);
		ev_signal_start(&signal_event[i]);
	}
}

static int read_word(FILE *in, int *lineno, size_t len, char *word)
{
	int ch, i, comment = 0;

	ch = fgetc(in);
	while (1) {
		if (ch == EOF)
			return FALSE;
		if (ch == '#')
			comment = 1;
		if (!comment && !isspace(ch))
			break;
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
			break;
		if (ch == '\n')
			(*lineno)++;
	}
	word[i] = 0;

	return TRUE;
}

static int load_config(const char *config_file)
{
#define NEED_INTERFACE() if (iface == NULL) { rc = 2; break; } peer = NULL;
#define NEED_PEER() if (peer == NULL || peer->type == NHRP_PEER_TYPE_LOCAL_ADDR) { rc = 3; break; }

	static const char *errors[] = {
		"syntax error",
		"missing keyword",
		"keyword valid only for 'interface' definition",
		"keyword valid only for 'map' definition",
		"invalid address",
		"dynamic-map requires a network address",
		"bad multicast destination",
		"keyword valid only for 'interace' and 'shortcut-target' definition",
	};
	struct nhrp_interface *iface = NULL;
	struct nhrp_peer *peer = NULL, *exist = NULL;
	struct nhrp_address paddr, nbma_addr;
	uint8_t prefix_length;
	char word[32], nbma[32], addr[32];
	FILE *in;
	int lineno = 1, rc = -1;

	in = fopen(config_file, "r");
	if (in == NULL) {
		nhrp_error("Unable to open configuration file '%s'.",
			   config_file);
		return FALSE;
	}

	while (read_word(in, &lineno, sizeof(word), word)) {
		if (strcmp(word, "interface") == 0) {
			if (!read_word(in, &lineno, sizeof(word), word)) {
				rc = 1;
				break;
			}
			iface = nhrp_interface_get_by_name(word, TRUE);
			if (iface != NULL)
				iface->flags |= NHRP_INTERFACE_FLAG_CONFIGURED;
			peer = NULL;
		} else if (strcmp(word, "shortcut-target") == 0) {
			NEED_INTERFACE();
			if (!read_word(in, &lineno, sizeof(addr), addr)) {
				rc = 1;
				break;
			}
			if (!nhrp_address_parse(addr, &paddr, &prefix_length)) {
				rc = 4;
				break;
			}
			exist = nhrp_peer_find_marked_static(iface, NHRP_PEER_TYPE_LOCAL_ADDR, &paddr, NULL, NULL);
			if (exist != NULL) {
				exist->flags &= ~NHRP_PEER_FLAG_MARK;
				exist->flags |= NHRP_PEER_FLAG_CONFIGURED;
				peer = exist;
			} else {
				peer = nhrp_peer_alloc(iface);
				peer->type = NHRP_PEER_TYPE_LOCAL_ADDR;
				peer->afnum = AFNUM_RESERVED;
				peer->protocol_address = paddr;
				peer->prefix_length = prefix_length;
				peer->protocol_type = nhrp_protocol_from_pf(paddr.type);
				peer->flags |= NHRP_PEER_FLAG_CONFIGURED;
				nhrp_peer_insert(peer);
				nhrp_peer_put(peer);
			}
		} else if (strcmp(word, "dynamic-map") == 0) {
			NEED_INTERFACE();
			read_word(in, &lineno, sizeof(addr), addr);
			read_word(in, &lineno, sizeof(nbma), nbma);

			if (!nhrp_address_parse(addr, &paddr, &prefix_length)) {
				rc = 4;
				break;
			}
			if (!nhrp_address_is_network(&paddr, prefix_length)) {
				rc = 5;
				break;
			}
			exist = nhrp_peer_find_marked_static(iface, NHRP_PEER_TYPE_STATIC_DNS, &paddr, NULL, nbma);
			if (exist != NULL) {
				exist->flags &= ~NHRP_PEER_FLAG_MARK;
				exist->flags |= NHRP_PEER_FLAG_CONFIGURED;
				peer = exist;
			} else {
				peer = nhrp_peer_alloc(iface);
				peer->type = NHRP_PEER_TYPE_STATIC_DNS;
				peer->protocol_address = paddr;
				peer->prefix_length = prefix_length;
				peer->protocol_type = nhrp_protocol_from_pf(paddr.type);
				peer->nbma_hostname = strdup(nbma);
				peer->afnum = nhrp_afnum_from_pf(peer->next_hop_address.type);
				peer->flags |= NHRP_PEER_FLAG_CONFIGURED;
				nhrp_peer_insert(peer);
				nhrp_peer_put(peer);
			}
		} else if (strcmp(word, "map") == 0) {
			NEED_INTERFACE();
			read_word(in, &lineno, sizeof(addr), addr);
			read_word(in, &lineno, sizeof(nbma), nbma);

			if (!nhrp_address_parse(addr, &paddr, &prefix_length)) {
				rc = 4;
				break;
			}
			nhrp_address_set_type(&nbma_addr, PF_UNSPEC);
			char *nbma_host = NULL;
			if (!nhrp_address_parse(nbma, &nbma_addr, NULL))
				nbma_host = nbma;

			exist = nhrp_peer_find_marked_static(iface, NHRP_PEER_TYPE_STATIC, &paddr, &nbma_addr, nbma_host);
			if (exist != NULL) {
				exist->flags &= ~NHRP_PEER_FLAG_MARK;
				exist->flags |= NHRP_PEER_FLAG_CONFIGURED;
				peer = exist;
			} else {
				peer = nhrp_peer_alloc(iface);
				peer->type = NHRP_PEER_TYPE_STATIC;
				peer->protocol_address = paddr;
				peer->prefix_length = prefix_length;
				peer->protocol_type = nhrp_protocol_from_pf(paddr.type);
				peer->next_hop_address = nbma_addr;
				if (nbma_host != NULL)
					peer->nbma_hostname = strdup(nbma_host);
				peer->afnum = nhrp_afnum_from_pf(peer->next_hop_address.type);
				peer->flags |= NHRP_PEER_FLAG_CONFIGURED;
				nhrp_peer_insert(peer);
				nhrp_peer_put(peer);
			}
		} else if (strcmp(word, "register") == 0) {
			NEED_PEER();
			peer->flags |= NHRP_PEER_FLAG_REGISTER;
		} else if (strcmp(word, "cisco") == 0) {
			NEED_PEER();
			peer->flags |= NHRP_PEER_FLAG_CISCO;
		} else if (strcmp(word, "no-unique") == 0) {
			NEED_PEER();
			peer->flags |= NHRP_PEER_FLAG_REG_NON_UNIQUE;
		} else if (strcmp(word, "holding-time") == 0) {
			read_word(in, &lineno, sizeof(word), word);
			if (peer != NULL &&
			    peer->type == NHRP_PEER_TYPE_LOCAL_ADDR) {
				peer->holding_time = atoi(word);
			} else if (iface != NULL) {
				iface->holding_time = atoi(word);
				peer = NULL;
			} else {
				rc = 7;
			}
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
		} else if (strcmp(word, "route-table") == 0) {
			NEED_INTERFACE();
			read_word(in, &lineno, sizeof(word), word);
			iface->route_table = atoi(word);
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
		} else if (strcmp(word, "multicast") == 0) {
			NEED_INTERFACE();
			read_word(in, &lineno, sizeof(word), word);
			if (strcmp(word, "dynamic") == 0) {
				iface->mcast_mask = \
					BIT(NHRP_PEER_TYPE_STATIC) |
					BIT(NHRP_PEER_TYPE_DYNAMIC_NHS) |
					BIT(NHRP_PEER_TYPE_DYNAMIC);
			} else if (strcmp(word, "nhs") == 0) {
				iface->mcast_mask = \
					BIT(NHRP_PEER_TYPE_STATIC) |
					BIT(NHRP_PEER_TYPE_DYNAMIC_NHS);
			} else if (nhrp_address_parse(word, &paddr, NULL)) {
				iface->mcast_numaddr++;
				iface->mcast_addr = realloc(iface->mcast_addr,
					iface->mcast_numaddr *
					sizeof(struct nhrp_address));
				iface->mcast_addr[iface->mcast_numaddr-1] =
					paddr;
			} else {
				rc = 6;
				break;
			}
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

static int open_pid_file(void)
{
	if (strlen(nhrp_pid_file) == 0)
		return TRUE;

	pid_file_fd = open(nhrp_pid_file, O_CREAT | O_WRONLY,
			   S_IRUSR | S_IWUSR);
	if (pid_file_fd < 0)
		goto err;

	fcntl(pid_file_fd, F_SETFD, FD_CLOEXEC);
	if (flock(pid_file_fd, LOCK_EX | LOCK_NB) < 0)
		goto err_close;

	return TRUE;

err_close:
	close(pid_file_fd);
err:
	nhrp_error("Unable to open/lock pid file: %s.", strerror(errno));
	return FALSE;
}

static int write_pid(void)
{
	char tmp[16];
	int n;

	if (pid_file_fd >= 0) {
		if (ftruncate(pid_file_fd, 0) < 0)
			return FALSE;

		n = sprintf(tmp, "%d\n", getpid());
		if (write(pid_file_fd, tmp, n) != n)
			return FALSE;

		atexit(remove_pid_file);
	}

	return TRUE;
}

static int daemonize(void)
{
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

	umask(0);

	if (freopen("/dev/null", "r", stdin) == NULL ||
	    freopen("/dev/null", "w", stdout) == NULL ||
	    freopen("/dev/null", "w", stderr) == NULL) {
		nhrp_error("Unable reopen standard file descriptors");
		goto err;
	}

	ev_default_fork();

	return TRUE;

err:
	close(pid_file_fd);
	pid_file_fd = 0;
	return FALSE;
}

int usage(const char *prog)
{
	fprintf(stderr,
		"usage: opennhrp [-a admin-socket] [-c config-file] [-s script-file]\n"
		"                [-p pid-file] [-d] [-v]\n"
		"       opennhrp -V\n"
		"\n"
		"\t-a admin-socket\tspecify management interface socket\n"
		"\t-c config-file\tread configuration from config-file\n"
		"\t-s script-file\tuse specified script-file for event handling\n"
		"\t-p pid-file\tspecify pid-file\n"
		"\t-d\t\tfork to background after startup\n"
		"\t-v\t\tverbose logging\n"
		"\t-V\t\tshow version number and exit\n"
		"\n");
	return 1;
}

int main(int argc, char **argv)
{
	struct nhrp_address any;
	int i, daemonmode = 0;

	nhrp_address_set_type(&any, AF_UNSPEC);

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
		case 'v':
			nhrp_verbose = 1;
			break;
		case 'V':
			puts(nhrp_version_string);
			return 0;
		default:
			return usage(argv[0]);
		}
	}

	srandom(time(NULL));
	if (!log_init())
		return 1;
	if (!open_pid_file())
		return 1;

	nhrp_info("%s starting", nhrp_version_string);

	ev_default_loop(0);
	signal_init();
	server_init();
	if (!nhrp_address_init())
		return 3;
	if (!load_config(nhrp_config_file))
		return 4;
	if (!kernel_init())
		return 5;
	if (!admin_init(nhrp_admin_socket))
		return 6;
	if (!forward_init())
		return 7;

	if (daemonmode && !daemonize()) {
		nhrp_error("Failed to daemonize. Exit.");
		return 8;
	}

	write_pid();

	nhrp_running = TRUE;
	ev_loop(0);
	nhrp_running = FALSE;

	forward_cleanup();
	kernel_stop_listening();
	nhrp_peer_cleanup();
	kernel_cleanup();
	nhrp_interface_cleanup();
	nhrp_rate_limit_clear(&any, 0);
	nhrp_address_cleanup();

	ev_default_destroy();

	return 0;
}

int nhrp_reload_config(void)
{
	nhrp_info("Reloading configuration file %s", nhrp_config_file);
	nhrp_peer_mark_static();
	if (!load_config(nhrp_config_file)) {
		nhrp_error("Failed to reload configuration file %s", nhrp_config_file);
		return FALSE;
	}
	nhrp_peer_sweep_marked_static();
	nhrp_info("Configuration reloaded successfully");
	return TRUE;
}

struct save_ctx {
	FILE *fp;
	struct nhrp_interface *iface;
};

static int save_peer_config(void *ctx, struct nhrp_peer *peer)
{
	FILE *fp = ((struct save_ctx *) ctx)->fp;
	char pbuf[64], nbuf[64];

	if (!(peer->flags & NHRP_PEER_FLAG_CONFIGURED))
		return 0;

	nhrp_address_format(&peer->protocol_address, sizeof(pbuf), pbuf);

	switch (peer->type) {
	case NHRP_PEER_TYPE_LOCAL_ADDR:
		fprintf(fp, "  shortcut-target %s/%d\n", pbuf, peer->prefix_length);
		break;
	case NHRP_PEER_TYPE_STATIC_DNS:
		fprintf(fp, "  dynamic-map %s/%d %s\n", pbuf, peer->prefix_length,
			peer->nbma_hostname ? peer->nbma_hostname : "");
		break;
	case NHRP_PEER_TYPE_STATIC:
		if (peer->nbma_hostname != NULL)
			fprintf(fp, "  map %s/%d %s", pbuf, peer->prefix_length, peer->nbma_hostname);
		else {
			nhrp_address_format(&peer->next_hop_address, sizeof(nbuf), nbuf);
			fprintf(fp, "  map %s/%d %s", pbuf, peer->prefix_length, nbuf);
		}
		if (peer->flags & NHRP_PEER_FLAG_REGISTER)
			fprintf(fp, " register");
		if (peer->flags & NHRP_PEER_FLAG_CISCO)
			fprintf(fp, " cisco");
		if (peer->flags & NHRP_PEER_FLAG_REG_NON_UNIQUE)
			fprintf(fp, " no-unique");
		fprintf(fp, "\n");
		break;
	}
	return 0;
}

static int save_iface_config(void *ctx, struct nhrp_interface *iface)
{
	FILE *fp = (FILE *) ctx;
	struct nhrp_peer_selector sel;
	struct save_ctx sctx = { fp, iface };

	if (!(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED))
		return 0;

	fprintf(fp, "interface %s\n", iface->name);

	memset(&sel, 0, sizeof(sel));
	sel.interface = iface;
	sel.type_mask = BIT(NHRP_PEER_TYPE_LOCAL_ADDR) |
			BIT(NHRP_PEER_TYPE_STATIC_DNS) |
			BIT(NHRP_PEER_TYPE_STATIC);
	nhrp_peer_foreach(save_peer_config, &sctx, &sel);

	if (iface->holding_time != 0)
		fprintf(fp, "  holding-time %u\n", iface->holding_time);
	if (iface->route_table != 0 && iface->route_table != RT_TABLE_MAIN)
		fprintf(fp, "  route-table %u\n", iface->route_table);
	if (iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT)
		fprintf(fp, "  shortcut\n");
	if (iface->flags & NHRP_INTERFACE_FLAG_REDIRECT)
		fprintf(fp, "  redirect\n");
	if (iface->flags & NHRP_INTERFACE_FLAG_NON_CACHING)
		fprintf(fp, "  non-caching\n");
	if (iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST)
		fprintf(fp, "  shortcut-destination\n");

	fprintf(fp, "\n");
	return 0;
}

int nhrp_save_config(void)
{
	char tmp_file[1024];
	FILE *fp;

	snprintf(tmp_file, sizeof(tmp_file), "%s.tmp", nhrp_config_file);
	fp = fopen(tmp_file, "w");
	if (fp == NULL) {
		nhrp_error("Unable to open temporary config file %s: %s",
			   tmp_file, strerror(errno));
		return FALSE;
	}

	fprintf(fp, "# OpenNHRP Configuration File (saved automatically)\n\n");
	nhrp_interface_foreach(save_iface_config, fp);

	fflush(fp);
	fclose(fp);

	if (rename(tmp_file, nhrp_config_file) != 0) {
		nhrp_error("Failed to rename %s to %s: %s",
			   tmp_file, nhrp_config_file, strerror(errno));
		unlink(tmp_file);
		return FALSE;
	}

	nhrp_info("Configuration saved successfully to %s", nhrp_config_file);
	return TRUE;
}

