/* admin.c - OpenNHRP administrative interface implementation
 *
 * Copyright (c) 2007-2012 Timo Teräs <timo.teras@iki.fi>
 *
 * This software is licensed under the MIT License.
 * See MIT-LICENSE.txt for additional details.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "nhrp_common.h"
#include "nhrp_ha.h"
#include "nhrp_ha_hub.h"
#include "nhrp_peer.h"
#include "nhrp_address.h"
#include "nhrp_interface.h"

static struct ev_io accept_io;

struct admin_remote {
	struct list_head monitor_list_entry;
	struct ev_timer timeout;
	struct ev_io io;
	int num_read;
	int monitor;
	int deferred;
	int in_handler;
	char monitor_interface[16];
	char cmd[512];
};

static struct list_head ha_monitors = LIST_INITIALIZER(ha_monitors);

static int parse_word(const char **bufptr, size_t len, char *word)
{
	const char *buf = *bufptr;
	int i, pos = 0;

	while (isspace(buf[pos]) && buf[pos] != '\n' && buf[pos])
		pos++;

	if (buf[pos] == '\n' || buf[pos] == 0)
		return FALSE;

	for (i = 0; i < len-1 && !isspace(buf[pos+i]); i++)
		word[i] = buf[pos+i];
	word[i] = 0;

	*bufptr += i + pos;
	return TRUE;
}

static void admin_raw_write(void *ctx, const void *buf, size_t len)
{
	struct admin_remote *rmt = (struct admin_remote *) ctx;

	if (write(rmt->io.fd, buf, len) != len) {
	}
}

static void admin_write(void *ctx, const char *format, ...)
{
	char msg[1024];
	va_list ap;
	size_t len;

	va_start(ap, format);
	len = vsnprintf(msg, sizeof(msg), format, ap);
	va_end(ap);
	if (len >= sizeof(msg))
		len = sizeof(msg) - 1;

	admin_raw_write(ctx, msg, len);
}

static void admin_free_remote(struct admin_remote *rm)
{
	int fd = rm->io.fd;

	if (list_hashed(&rm->monitor_list_entry))
		list_del(&rm->monitor_list_entry);
	ev_io_stop(&rm->io);
	ev_timer_stop(&rm->timeout);
	shutdown(fd, SHUT_RDWR);
	close(fd);
	free(rm);
}

void admin_ha_notify(struct nhrp_interface *iface)
{
	struct admin_remote *remote, *next;
	char buffer[16384];
	size_t length;

	list_for_each_entry_safe(remote, next, &ha_monitors,
				 monitor_list_entry) {
		if (remote->monitor_interface[0] != 0 &&
		    strcmp(remote->monitor_interface, iface->name) != 0)
			continue;
		length = nhrp_ha_render(buffer, sizeof(buffer),
					remote->monitor_interface, TRUE);
		if (write(remote->io.fd, buffer, length) != length)
			admin_free_remote(remote);
	}
}

static int admin_show_peer(void *ctx, struct nhrp_peer *peer)
{
	char buf[512], tmp[32];
	char *str;
	size_t len = sizeof(buf);
	int i = 0, rel;

	if (peer->interface != NULL)
		i += snprintf(&buf[i], len - i,
			"Interface: %s\n",
			peer->interface->name);

	i += snprintf(&buf[i], len - i,
		"Type: %s\n"
		"Protocol-Address: %s/%d\n",
		nhrp_peer_type[peer->type],
		nhrp_address_format(&peer->protocol_address, sizeof(tmp), tmp),
		peer->prefix_length);

	if (peer->next_hop_address.type != PF_UNSPEC) {
		switch (peer->type) {
		case NHRP_PEER_TYPE_SHORTCUT_ROUTE:
		case NHRP_PEER_TYPE_LOCAL_ROUTE:
			str = "Next-hop-Address";
			break;
		case NHRP_PEER_TYPE_LOCAL_ADDR:
			str = "Alias-Address";
			break;
		default:
			str = "NBMA-Address";
			break;
		}
		i += snprintf(&buf[i], len - i, "%s: %s\n",
			str,
			nhrp_address_format(&peer->next_hop_address,
					    sizeof(tmp), tmp));
	}
	if (peer->nbma_hostname) {
		i += snprintf(&buf[i], len - i, "Hostname: %s\n",
			      peer->nbma_hostname);
	}
	if (peer->local_connect_address.type != PF_UNSPEC) {
		i += snprintf(&buf[i], len - i, "Local-NBMA-Address: %s\n",
			nhrp_address_format(&peer->local_connect_address,
					    sizeof(tmp), tmp));
	}
	if (peer->next_hop_nat_oa.type != PF_UNSPEC) {
		i += snprintf(&buf[i], len - i, "NBMA-NAT-OA-Address: %s\n",
			nhrp_address_format(&peer->next_hop_nat_oa,
					    sizeof(tmp), tmp));
	}
	if (peer->flags & (NHRP_PEER_FLAG_USED | NHRP_PEER_FLAG_UNIQUE |
			   NHRP_PEER_FLAG_UP | NHRP_PEER_FLAG_LOWER_UP)) {
		i += snprintf(&buf[i], len - i, "Flags:");
		if (peer->flags & NHRP_PEER_FLAG_UNIQUE)
			i += snprintf(&buf[i], len - i, " unique");

		if (peer->flags & NHRP_PEER_FLAG_USED)
			i += snprintf(&buf[i], len - i, " used");
		if (peer->flags & NHRP_PEER_FLAG_UP)
			i += snprintf(&buf[i], len - i, " up");
		else if (peer->flags & NHRP_PEER_FLAG_LOWER_UP)
			i += snprintf(&buf[i], len - i, " lower-up");
		i += snprintf(&buf[i], len - i, "\n");
	}
	if (peer->expire_time) {
		rel = (int) (peer->expire_time - ev_now());
		if (rel >= 0) {
			i += snprintf(&buf[i], len - i, "Expires-In: %d:%02d\n",
				      rel / 60, rel % 60);
		}
	}
	i += snprintf(&buf[i], len - i, "\n");
	admin_raw_write(ctx, buf, i);
	return 0;
}

static void admin_free_selector(struct nhrp_peer_selector *sel)
{
	if (sel->hostname != NULL) {
		free((void *) sel->hostname);
		sel->hostname = NULL;
	}
}

static int admin_parse_selector(void *ctx, const char *cmd,
				struct nhrp_peer_selector *sel)
{
	char keyword[64], tmp[64];
	struct nhrp_address address;
	uint8_t prefix_length;

	while (parse_word(&cmd, sizeof(keyword), keyword)) {
		if (!parse_word(&cmd, sizeof(tmp), tmp)) {
			admin_write(ctx,
				    "Status: failed\n"
				    "Reason: missing-argument\n"
				    "Near-Keyword: '%s'\n",
				    keyword);
			return FALSE;
		}

		if (strcmp(keyword, "interface") == 0 ||
		    strcmp(keyword, "iface") == 0 ||
		    strcmp(keyword, "dev") == 0) {
			if (sel->interface != NULL)
				goto err_conflict;
			sel->interface = nhrp_interface_get_by_name(tmp, FALSE);
			if (sel->interface == NULL)
				goto err_noiface;
			continue;
		} else if (strcmp(keyword, "host") == 0 ||
			   strcmp(keyword, "hostname") == 0) {
			if (sel->hostname != NULL)
				goto err_conflict;
			sel->hostname = strdup(tmp);
			continue;
		}

		if (!nhrp_address_parse(tmp, &address, &prefix_length)) {
			admin_write(ctx,
				    "Status: failed\n"
				    "Reason: invalid-address\n"
				    "Near-Keyword: '%s'\n",
				   keyword);
			return FALSE;
		}

		if (strcmp(keyword, "protocol") == 0) {
			if (sel->protocol_address.type != AF_UNSPEC)
				goto err_conflict;
			sel->protocol_address = address;
			sel->prefix_length = prefix_length;
		} else if (strcmp(keyword, "nbma") == 0) {
			if (sel->next_hop_address.type != AF_UNSPEC)
				goto err_conflict;
			sel->type_mask &= ~BIT(NHRP_PEER_TYPE_SHORTCUT_ROUTE);
			sel->next_hop_address = address;
		} else if (strcmp(keyword, "local-protocol") == 0) {
			if (sel->interface != NULL)
				goto err_conflict;
			sel->interface = nhrp_interface_get_by_protocol(&address);
			if (sel->interface == NULL)
				goto err_noiface;
		} else if (strcmp(keyword, "local-nbma") == 0) {
			if (sel->interface != NULL)
				goto err_conflict;
			sel->local_nbma_address = address;
			if (sel->interface == NULL)
				sel->interface = nhrp_interface_get_by_nbma(&address);
		} else {
			admin_write(ctx,
				    "Status: failed\n"
				    "Reason: syntax-error\n"
				    "Near-Keyword: '%s'\n",
				    keyword);
			return FALSE;
		}
	}
	return TRUE;

err_conflict:
	admin_write(ctx,
		    "Status: failed\n"
		    "Reason: conflicting-keyword\n"
		    "Near-Keyword: '%s'\n",
		    keyword);
	goto err;
err_noiface:
	admin_write(ctx,
		    "Status: failed\n"
		    "Reason: interface-not-found\n"
		    "Near-Keyword: '%s'\n"
		    "Argument: '%s'\n",
		    keyword, tmp);
err:
	admin_free_selector(sel);
	return FALSE;
}

static void admin_route_show(void *ctx, const char *cmd)
{
	struct nhrp_peer_selector sel;

	memset(&sel, 0, sizeof(sel));
	sel.type_mask = BIT(NHRP_PEER_TYPE_LOCAL_ROUTE);
	if (!admin_parse_selector(ctx, cmd, &sel))
		return;

	admin_write(ctx, "Status: ok\n\n");
	nhrp_peer_foreach(admin_show_peer, ctx, &sel);
	admin_free_selector(&sel);
}

static void admin_cache_show(void *ctx, const char *cmd)
{
	struct nhrp_peer_selector sel;

	memset(&sel, 0, sizeof(sel));
	sel.type_mask = NHRP_PEER_TYPEMASK_ALL &
		~BIT(NHRP_PEER_TYPE_LOCAL_ROUTE);
	if (!admin_parse_selector(ctx, cmd, &sel))
		return;

	admin_write(ctx, "Status: ok\n\n");
	nhrp_peer_foreach(admin_show_peer, ctx, &sel);
	admin_free_selector(&sel);
}

static void admin_cache_purge(void *ctx, const char *cmd)
{
	struct nhrp_peer_selector sel;
	int count = 0;

	memset(&sel, 0, sizeof(sel));
	sel.type_mask = NHRP_PEER_TYPEMASK_PURGEABLE;
	if (!admin_parse_selector(ctx, cmd, &sel))
		return;

	nhrp_peer_foreach(nhrp_peer_purge_matching, &count, &sel);
	admin_free_selector(&sel);

	admin_write(ctx,
		    "Status: ok\n"
		    "Entries-Affected: %d\n",
		    count);
}

static void admin_cache_lower_down(void *ctx, const char *cmd)
{
	struct nhrp_peer_selector sel;
	int count = 0;

	memset(&sel, 0, sizeof(sel));
	sel.type_mask = NHRP_PEER_TYPEMASK_PURGEABLE;
	if (!admin_parse_selector(ctx, cmd, &sel))
		return;

	nhrp_peer_foreach(nhrp_peer_lowerdown_matching, &count, &sel);
	admin_free_selector(&sel);

	admin_write(ctx,
		    "Status: ok\n"
		    "Entries-Affected: %d\n",
		    count);
}

static void admin_cache_renew(void *ctx, const char *cmd)
{
	struct nhrp_peer_selector sel;
	int count = 0;

	memset(&sel, 0, sizeof(sel));
	sel.type_mask = BIT(NHRP_PEER_TYPE_STATIC);
	if (!admin_parse_selector(ctx, cmd, &sel))
		return;

	nhrp_peer_foreach(nhrp_peer_reregister_matching, &count, &sel);
	admin_free_selector(&sel);

	admin_write(ctx,
		    "Status: ok\n"
		    "Entries-Affected: %d\n",
		    count);
}

static void admin_cache_flush(void *ctx, const char *cmd)
{
	struct nhrp_peer_selector sel;
	int count = 0;

	memset(&sel, 0, sizeof(sel));
	sel.type_mask = NHRP_PEER_TYPEMASK_REMOVABLE;
	if (!admin_parse_selector(ctx, cmd, &sel))
		return;

	nhrp_peer_foreach(nhrp_peer_remove_matching, &count, &sel);
	admin_free_selector(&sel);

	admin_write(ctx,
		    "Status: ok\n"
		    "Entries-Affected: %d\n",
		    count);
}

static int admin_show_interface(void *ctx, struct nhrp_interface *iface)
{
	char buf[512], tmp[32];
	size_t len = sizeof(buf);
	int i = 0;

	i += snprintf(&buf[i], len - i,
		"Interface: %s\n"
		"Index: %d\n",
		iface->name,
		iface->index);

	if (iface->protocol_address.addr_len != 0) {
		i += snprintf(&buf[i], len - i,
			"Protocol-Address: %s/%d\n",
			nhrp_address_format(&iface->protocol_address, sizeof(tmp), tmp),
			iface->protocol_address_prefix);
	}

	if (iface->flags) {
		i += snprintf(&buf[i], len - i,
			"Flags:%s%s%s%s%s\n",
			(iface->flags & NHRP_INTERFACE_FLAG_NON_CACHING) ? " non-caching" : "",
			(iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT) ? " shortcut" : "",
			(iface->flags & NHRP_INTERFACE_FLAG_REDIRECT) ? " redirect" : "",
			(iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT_DEST) ? " shortcut-dest" : "",
			(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED) ? " configured" : "");
	}

	if (!(iface->flags & NHRP_INTERFACE_FLAG_CONFIGURED))
		goto done;

	i += snprintf(&buf[i], len - i,
		"Holding-Time: %u\n"
		"Route-Table: %u\n"
		"GRE-Key: %u\n"
		"MTU: %u\n",
		iface->holding_time,
		iface->route_table,
		iface->gre_key,
		iface->mtu);

	if (iface->link_index) {
		struct nhrp_interface *link;

		i += snprintf(&buf[i], len - i, "Link-Index: %d\n", iface->link_index);
		link = nhrp_interface_get_by_index(iface->link_index, FALSE);
		if (link != NULL)
			i += snprintf(&buf[i], len - i, "Link-Name: %s\n", link->name);
	}

	if (iface->nbma_address.addr_len != 0) {
		i += snprintf(&buf[i], len - i,
			"NBMA-MTU: %u\n"
			"NBMA-Address: %s\n",
			iface->nbma_mtu,
			nhrp_address_format(&iface->nbma_address, sizeof(tmp), tmp));
	}
	if (iface->nat_cie.nbma_address.addr_len != 0) {
		i += snprintf(&buf[i], len - i,
			"NBMA-NAT-OA: %s\n",
			nhrp_address_format(&iface->nat_cie.nbma_address, sizeof(tmp), tmp));
	}
done:
	i += snprintf(&buf[i], len - i, "\n");
	admin_raw_write(ctx, buf, i);
	return 0;
}

static void admin_interface_show(void *ctx, const char *cmd)
{
	admin_write(ctx, "Status: ok\n\n");
	nhrp_interface_foreach(admin_show_interface, ctx);
}

static void admin_redirect_purge(void *ctx, const char *cmd)
{
	char keyword[64];
	struct nhrp_address addr;
	uint8_t prefix = 0;
	int count;

	nhrp_address_set_type(&addr, PF_UNSPEC);

	if (parse_word(&cmd, sizeof(keyword), keyword)) {
		if (!nhrp_address_parse(keyword, &addr, &prefix)) {
			admin_write(ctx,
				    "Status: failed\n"
				    "Reason: invalid-address\n"
				    "Near-Keyword: '%s'\n",
				    keyword);
			return;
		}
	}

	count = nhrp_rate_limit_clear(&addr, prefix);
	admin_write(ctx,
		    "Status: ok\n"
		    "Entries-Affected: %d\n",
		    count);
}

struct update_nbma {
	struct nhrp_address addr;
	int count;
};

static int update_nbma(void *ctx, struct nhrp_peer *p)
{
	struct update_nbma *un = (struct update_nbma *) ctx;

	nhrp_peer_discover_nhs(p, &un->addr);
	un->count++;

	return 0;
}

static void admin_update_nbma(void *ctx, const char *cmd)
{
	char keyword[64];
	struct nhrp_peer_selector sel;
	struct update_nbma un;

	memset(&sel, 0, sizeof(sel));
	sel.type_mask = BIT(NHRP_PEER_TYPE_DYNAMIC_NHS);

	if (!parse_word(&cmd, sizeof(keyword), keyword))
		goto err;
	if (!nhrp_address_parse(keyword, &sel.next_hop_address, NULL))
		goto err;
	if (!parse_word(&cmd, sizeof(keyword), keyword))
		goto err;
	if (!nhrp_address_parse(keyword, &un.addr, NULL))
		goto err;

	un.count = 0;
	nhrp_peer_foreach(update_nbma, &un, &sel);

	admin_write(ctx,
		    "Status: ok\n"
		    "Entries-Affected: %d\n",
		    un.count);
	return;
err:
	admin_write(ctx,
		    "Status: failed\n"
		    "Reason: syntax-error\n"
		    "Near-Keyword: '%s'\n",
		    keyword);
	return;
}

static void admin_config_reload(void *ctx, const char *cmd)
{
	if (nhrp_reload_config()) {
		admin_write(ctx, "Status: ok\n");
	} else {
		admin_write(ctx,
			    "Status: failed\n"
			    "Reason: config-reload-error\n");
	}
}

static void admin_managed_reload(void *ctx, const char *cmd) {
  if (nhrp_reload_managed()) {
    admin_write(ctx, "Status: ok\n");
  } else {
    admin_write(ctx, "Status: failed\n"
                     "Reason: managed-state-reload-error\n");
  }
}

static void admin_managed_stop(void *ctx, const char *cmd) {
  (void)cmd;
  admin_write(ctx, nhrp_stop_managed_hub() ? "Status: ok\n"
                                           : "Status: failed\n");
}

static void admin_map_add(void *ctx, const char *cmd)
{
	char word[64], ifname[64] = "", pstr[64] = "", nbstr[64] = "";
	struct nhrp_interface *iface = NULL;
	struct nhrp_address paddr, nbma_addr, local_nbma_addr;
	struct nhrp_address *nbma_ptr = NULL, *local_nbma_ptr = NULL;
	const char *nbma_host = NULL;
	uint8_t prefix_length = 0;
	unsigned int flags = 0;

	nhrp_address_set_type(&paddr, PF_UNSPEC);
	nhrp_address_set_type(&nbma_addr, PF_UNSPEC);
	nhrp_address_set_type(&local_nbma_addr, PF_UNSPEC);

	while (parse_word(&cmd, sizeof(word), word)) {
		if (strcmp(word, "interface") == 0 || strcmp(word, "iface") == 0 || strcmp(word, "dev") == 0) {
			if (parse_word(&cmd, sizeof(ifname), ifname))
				iface = nhrp_interface_get_by_name(ifname, FALSE);
		} else if (strcmp(word, "protocol") == 0) {
			parse_word(&cmd, sizeof(pstr), pstr);
		} else if (strcmp(word, "nbma") == 0) {
			parse_word(&cmd, sizeof(nbstr), nbstr);
		} else if (strcmp(word, "local-nbma") == 0) {
			char lnbstr[64];
			if (parse_word(&cmd, sizeof(lnbstr), lnbstr) &&
			    nhrp_address_parse(lnbstr, &local_nbma_addr, NULL))
				local_nbma_ptr = &local_nbma_addr;
		} else if (strcmp(word, "register") == 0) {
			flags |= NHRP_PEER_FLAG_REGISTER;
		} else if (strcmp(word, "cisco") == 0) {
			flags |= NHRP_PEER_FLAG_CISCO;
		} else if (strcmp(word, "no-unique") == 0) {
			flags |= NHRP_PEER_FLAG_REG_NON_UNIQUE;
		} else {
			if (ifname[0] == 0) {
				snprintf(ifname, sizeof(ifname), "%s", word);
				iface = nhrp_interface_get_by_name(ifname, FALSE);
			} else if (pstr[0] == 0) {
				snprintf(pstr, sizeof(pstr), "%s", word);
			} else if (nbstr[0] == 0) {
				snprintf(nbstr, sizeof(nbstr), "%s", word);
			}
		}
	}

	if (iface == NULL) {
		admin_write(ctx, "Status: failed\nReason: interface-not-found\n");
		return;
	}
	if (!nhrp_address_parse(pstr, &paddr, &prefix_length)) {
		admin_write(ctx, "Status: failed\nReason: invalid-protocol-address\n");
		return;
	}
	if (nbstr[0] == 0) {
		admin_write(ctx, "Status: failed\nReason: missing-nbma-address\n");
		return;
	}

	if (nhrp_address_parse(nbstr, &nbma_addr, NULL))
		nbma_ptr = &nbma_addr;
	else
		nbma_host = nbstr;

	if (nhrp_peer_add_static(iface, &paddr, prefix_length, nbma_ptr, nbma_host, local_nbma_ptr, flags) != NULL) {
		admin_write(ctx, "Status: ok\n");
	} else {
		admin_write(ctx, "Status: failed\nReason: add-static-failed\n");
	}
}

static void admin_map_del(void *ctx, const char *cmd)
{
	char word[64], ifname[32] = "", pstr[64] = "";
	struct nhrp_interface *iface = NULL;
	struct nhrp_address paddr;

	nhrp_address_set_type(&paddr, PF_UNSPEC);

	while (parse_word(&cmd, sizeof(word), word)) {
		if (strcmp(word, "interface") == 0 || strcmp(word, "iface") == 0 || strcmp(word, "dev") == 0) {
			if (parse_word(&cmd, sizeof(ifname), ifname))
				iface = nhrp_interface_get_by_name(ifname, FALSE);
		} else if (strcmp(word, "protocol") == 0) {
			parse_word(&cmd, sizeof(pstr), pstr);
		} else {
			if (iface == NULL && (iface = nhrp_interface_get_by_name(word, FALSE)) != NULL)
				continue;
			if (pstr[0] == 0)
				snprintf(pstr, sizeof(pstr), "%s", word);
		}
	}

	if (!nhrp_address_parse(pstr, &paddr, NULL)) {
		admin_write(ctx, "Status: failed\nReason: invalid-protocol-address\n");
		return;
	}

	if (nhrp_peer_del_static(iface, &paddr)) {
		admin_write(ctx, "Status: ok\n");
	} else {
		admin_write(ctx, "Status: failed\nReason: entry-not-found\n");
	}
}

static void admin_config_save(void *ctx, const char *cmd)
{
	if (nhrp_save_config()) {
		admin_write(ctx, "Status: ok\n");
	} else {
		admin_write(ctx, "Status: failed\nReason: config-save-error\n");
	}
}

static int admin_ha_parse_common(void *ctx, const char *cmd,
				 char *interface_name, size_t interface_size,
				 int *json)
{
	char keyword[64], value[64];

	while (parse_word(&cmd, sizeof(keyword), keyword)) {
		if (!parse_word(&cmd, sizeof(value), value)) {
			admin_write(ctx, "Status: failed\nReason: missing-argument\n");
			return FALSE;
		}
		if (strcmp(keyword, "interface") == 0) {
			if (strlen(value) >= interface_size)
				goto invalid;
			strcpy(interface_name, value);
		} else if (strcmp(keyword, "format") == 0 &&
			   strcmp(value, "json") == 0 && json != NULL) {
			*json = TRUE;
		} else {
		invalid:
			admin_write(ctx, "Status: failed\nReason: invalid-argument\n");
			return FALSE;
		}
	}
	return TRUE;
}

static void admin_ha_show(void *ctx, const char *cmd)
{
	char interface_name[16] = "";
	char buffer[16384];
	int json = FALSE;
	size_t length;

	if (!admin_ha_parse_common(ctx, cmd, interface_name,
				   sizeof(interface_name), &json))
		return;
	admin_write(ctx, "Status: ok\n\n");
	length = nhrp_ha_render(buffer, sizeof(buffer), interface_name, json);
	admin_raw_write(ctx, buffer, length);
}

static void admin_ha_monitor(void *ctx, const char *cmd)
{
	struct admin_remote *remote = ctx;
	char buffer[16384];
	int json = TRUE;
	size_t length;

	if (!admin_ha_parse_common(ctx, cmd, remote->monitor_interface,
				   sizeof(remote->monitor_interface), &json))
		return;
	length = nhrp_ha_render(buffer, sizeof(buffer),
				remote->monitor_interface, TRUE);
	admin_raw_write(ctx, buffer, length);
	remote->monitor = TRUE;
	ev_timer_stop(&remote->timeout);
	list_add_tail(&remote->monitor_list_entry, &ha_monitors);
}

static void admin_ha_activate_done(void *ctx, int status,
				   const char *reason, uint32_t generation)
{
	struct admin_remote *remote = ctx;

	if (status == 0)
		admin_write(remote, "Status: ok\nGeneration: %u\nReason: %s\n",
			    generation, reason);
	else
		admin_write(remote,
			    "Status: failed\nReason: %s\nError: %d\nGeneration: %u\n",
			    reason, -status, generation);
	remote->deferred = FALSE;
	if (!remote->in_handler)
		admin_free_remote(remote);
}

static void admin_ha_activate(void *ctx, const char *cmd)
{
	struct admin_remote *remote = ctx;
	struct nhrp_address protocol;
	char keyword[64], value[64];
	char interface_name[16] = "";
	char member_id[64] = "";
	uint32_t generation = 0;
	int have_protocol = FALSE, have_generation = FALSE;
	const char *reason = "invalid-argument";

	while (parse_word(&cmd, sizeof(keyword), keyword)) {
		if (!parse_word(&cmd, sizeof(value), value))
			goto invalid;
		if (strcmp(keyword, "interface") == 0) {
			if (strlen(value) >= sizeof(interface_name))
				goto invalid;
			strcpy(interface_name, value);
		} else if (strcmp(keyword, "protocol") == 0) {
			if (!nhrp_address_parse(value, &protocol, NULL))
				goto invalid;
			have_protocol = TRUE;
		} else if (strcmp(keyword, "member") == 0) {
			if (strlen(value) >= sizeof(member_id))
				goto invalid;
			strcpy(member_id, value);
		} else if (strcmp(keyword, "expect-generation") == 0) {
			char *end = NULL;
			unsigned long parsed = strtoul(value, &end, 10);

			if (end == value || *end != 0 || parsed > UINT32_MAX)
				goto invalid;
			generation = parsed;
			have_generation = TRUE;
		} else {
			goto invalid;
		}
	}
	if (interface_name[0] == 0 || member_id[0] == 0 || !have_protocol ||
	    !have_generation)
		goto invalid;

	remote->deferred = TRUE;
	if (nhrp_ha_activate(interface_name, &protocol, member_id, generation,
			     admin_ha_activate_done, remote, &reason))
		return;
	remote->deferred = FALSE;
	admin_write(ctx, "Status: failed\nReason: %s\n", reason);
	return;

invalid:
	admin_write(ctx, "Status: failed\nReason: invalid-argument\n");
}

static int parse_u64(const char *text, uint64_t *value)
{
	char *end = NULL;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(text, &end, 10);
	if (errno != 0 || end == text || *end != 0)
		return FALSE;
	*value = parsed;
	return TRUE;
}

static void admin_ha_hub_role(void *ctx, const char *cmd)
{
	struct nhrp_interface *iface = NULL;
	enum nhrp_ha_hub_role role = NHRP_HA_HUB_UNMANAGED;
	char keyword[64], value[64];
	uint64_t term = 0, index = 0;

	while (parse_word(&cmd, sizeof(keyword), keyword)) {
		if (!parse_word(&cmd, sizeof(value), value))
			goto invalid;
		if (strcmp(keyword, "interface") == 0) {
			iface = nhrp_interface_get_by_name(value, FALSE);
		} else if (strcmp(keyword, "role") == 0) {
			if (strcmp(value, "leader") == 0)
				role = NHRP_HA_HUB_LEADER;
			else if (strcmp(value, "standby") == 0)
				role = NHRP_HA_HUB_STANDBY;
			else
				goto invalid;
		} else if (strcmp(keyword, "term") == 0) {
			if (!parse_u64(value, &term))
				goto invalid;
		} else if (strcmp(keyword, "index") == 0) {
			if (!parse_u64(value, &index))
				goto invalid;
		} else {
			goto invalid;
		}
	}
	if (iface == NULL || role == NHRP_HA_HUB_UNMANAGED || term == 0 ||
	    !nhrp_ha_hub_set_role(iface, role, term, index))
		goto invalid;
	admin_write(ctx, "Status: ok\n");
	return;

invalid:
	admin_write(ctx, "Status: failed\nReason: invalid-argument\n");
}

static void admin_ha_hub_show(void *ctx, const char *cmd)
{
	struct nhrp_interface *iface = NULL;
	char keyword[64], value[64];
	char buffer[2048];
	int json = FALSE;
	size_t length;

	while (parse_word(&cmd, sizeof(keyword), keyword)) {
		if (!parse_word(&cmd, sizeof(value), value))
			goto invalid;
		if (strcmp(keyword, "interface") == 0)
			iface = nhrp_interface_get_by_name(value, FALSE);
		else if (strcmp(keyword, "format") == 0 &&
			 strcmp(value, "json") == 0)
			json = TRUE;
		else
			goto invalid;
	}
	if (iface == NULL)
		goto invalid;
	admin_write(ctx, "Status: ok\n\n");
	length = nhrp_ha_hub_status_render(iface, buffer, sizeof(buffer), json);
	admin_raw_write(ctx, buffer, length);
	return;

invalid:
	admin_write(ctx, "Status: failed\nReason: invalid-argument\n");
}

static void admin_ha_cluster_set(void *ctx, const char *cmd)
{
	struct nhrp_interface *iface = NULL;
	char keyword[64], value[64], leader[64] = "";
	uint64_t term = 0, commit_index = 0;

	while (parse_word(&cmd, sizeof(keyword), keyword)) {
		if (!parse_word(&cmd, sizeof(value), value))
			goto invalid;
		if (strcmp(keyword, "interface") == 0)
			iface = nhrp_interface_get_by_name(value, FALSE);
		else if (strcmp(keyword, "term") == 0) {
			if (!parse_u64(value, &term))
				goto invalid;
		} else if (strcmp(keyword, "commit-index") == 0) {
			if (!parse_u64(value, &commit_index))
				goto invalid;
		} else if (strcmp(keyword, "leader") == 0) {
			if (strlen(value) >= sizeof(leader))
				goto invalid;
			strcpy(leader, value);
		} else
			goto invalid;
	}
	if (iface == NULL || leader[0] == 0 ||
	    !nhrp_ha_set_cluster_state(iface, term, commit_index, leader))
		goto invalid;
	admin_write(ctx, "Status: ok\n");
	return;

invalid:
	admin_write(ctx, "Status: failed\nReason: invalid-argument\n");
}

static void admin_ha_registration_snapshot(void *ctx, const char *cmd)
{
	struct nhrp_interface *iface = NULL;
	char keyword[64], value[64];
	char digest[65];
	char *buffer;
	uint64_t parsed;
	size_t offset = 0, limit = 128, total, length;

	while (parse_word(&cmd, sizeof(keyword), keyword)) {
		if (!parse_word(&cmd, sizeof(value), value))
			goto invalid;
		if (strcmp(keyword, "interface") == 0) {
			iface = nhrp_interface_get_by_name(value, FALSE);
		} else if (strcmp(keyword, "offset") == 0) {
			if (!parse_u64(value, &parsed) || parsed > 4096)
				goto invalid;
			offset = parsed;
		} else if (strcmp(keyword, "limit") == 0) {
			if (!parse_u64(value, &parsed) || parsed == 0 || parsed > 128)
				goto invalid;
			limit = parsed;
		} else {
			goto invalid;
		}
	}
	if (iface == NULL)
		goto invalid;
	buffer = malloc(65536);
	if (buffer == NULL) {
		admin_write(ctx, "Status: failed\nReason: out-of-memory\n");
		return;
	}
	length = nhrp_ha_hub_snapshot_render(iface, buffer, 65536, offset,
					      limit, &total, digest);
	admin_write(ctx,
		    "Status: ok\nTotal: %zu\nOffset: %zu\nCount: %zu\n"
		    "More: %s\nDigest: %s\n\n",
		    total, offset, total > offset ? (total - offset > limit ? limit : total - offset) : 0,
		    offset + limit < total ? "yes" : "no", digest);
	admin_raw_write(ctx, buffer, length);
	free(buffer);
	return;

invalid:
	admin_write(ctx, "Status: failed\nReason: invalid-argument\n");
}

static void admin_ha_registration_sync_begin(void *ctx, const char *cmd)
{
	struct nhrp_interface *iface = NULL;
	char keyword[64], value[64];
	uint64_t term = 0, index = 0;

	while (parse_word(&cmd, sizeof(keyword), keyword)) {
		if (!parse_word(&cmd, sizeof(value), value))
			goto invalid;
		if (strcmp(keyword, "interface") == 0)
			iface = nhrp_interface_get_by_name(value, FALSE);
		else if (strcmp(keyword, "term") == 0) {
			if (!parse_u64(value, &term))
				goto invalid;
		} else if (strcmp(keyword, "index") == 0) {
			if (!parse_u64(value, &index))
				goto invalid;
		} else
			goto invalid;
	}
	if (iface == NULL || !nhrp_ha_hub_sync_begin(iface, term, index))
		goto invalid;
	admin_write(ctx, "Status: ok\n");
	return;

invalid:
	admin_write(ctx, "Status: failed\nReason: invalid-argument\n");
}

static void admin_ha_registration_sync_apply(void *ctx, const char *cmd)
{
	struct nhrp_interface *iface = NULL;
	struct nhrp_address protocol, address;
	struct nhrp_ha_hub_binding binding;
	char keyword[64], value[64];
	uint8_t prefix = 0;
	uint64_t parsed;
	int have_protocol = FALSE, have_nbma = FALSE;

	memset(&binding, 0, sizeof(binding));
	nhrp_address_set_type(&binding.nat_oa, PF_UNSPEC);
	while (parse_word(&cmd, sizeof(keyword), keyword)) {
		if (!parse_word(&cmd, sizeof(value), value))
			goto invalid;
		if (strcmp(keyword, "interface") == 0) {
			iface = nhrp_interface_get_by_name(value, FALSE);
		} else if (strcmp(keyword, "protocol") == 0) {
			if (!nhrp_address_parse(value, &protocol, &prefix))
				goto invalid;
			have_protocol = TRUE;
		} else if (strcmp(keyword, "nbma") == 0) {
			if (!nhrp_address_parse(value, &binding.nbma, NULL))
				goto invalid;
			have_nbma = TRUE;
		} else if (strcmp(keyword, "nat-oa") == 0) {
			if (strcmp(value, "-") != 0) {
				if (!nhrp_address_parse(value, &address, NULL))
					goto invalid;
				binding.nat_oa = address;
			}
		} else if (strcmp(keyword, "mtu") == 0) {
			if (!parse_u64(value, &parsed) || parsed > UINT16_MAX)
				goto invalid;
			binding.mtu = parsed;
		} else if (strcmp(keyword, "holding") == 0) {
			if (!parse_u64(value, &parsed) || parsed == 0 ||
			    parsed > UINT16_MAX)
				goto invalid;
			binding.holding_time = parsed;
		} else if (strcmp(keyword, "flags") == 0) {
			if (!parse_u64(value, &parsed) || parsed > UINT32_MAX)
				goto invalid;
			binding.flags = parsed;
		} else if (strcmp(keyword, "term") == 0) {
			if (!parse_u64(value, &binding.term))
				goto invalid;
		} else if (strcmp(keyword, "index") == 0) {
			if (!parse_u64(value, &binding.index))
				goto invalid;
		} else {
			goto invalid;
		}
	}
	if (iface == NULL || !have_protocol || !have_nbma ||
	    !nhrp_ha_hub_sync_apply(iface, &protocol, prefix, &binding))
		goto invalid;
	admin_write(ctx, "Status: ok\n");
	return;

invalid:
	admin_write(ctx, "Status: failed\nReason: invalid-argument\n");
}

static void admin_ha_registration_sync_end(void *ctx, const char *cmd)
{
	struct nhrp_interface *iface = NULL;
	char keyword[64], value[64];

	while (parse_word(&cmd, sizeof(keyword), keyword)) {
		if (!parse_word(&cmd, sizeof(value), value) ||
		    strcmp(keyword, "interface") != 0)
			goto invalid;
		iface = nhrp_interface_get_by_name(value, FALSE);
	}
	if (iface == NULL || !nhrp_ha_hub_sync_end(iface))
		goto invalid;
	admin_write(ctx, "Status: ok\n");
	return;

invalid:
	admin_write(ctx, "Status: failed\nReason: invalid-argument\n");
}

static struct {
	const char *command;
	void (*handler)(void *ctx, const char *cmd);
} admin_handler[] = {
	{ "ha registration sync apply", admin_ha_registration_sync_apply },
	{ "ha registration sync begin", admin_ha_registration_sync_begin },
	{ "ha registration sync end", admin_ha_registration_sync_end },
	{ "ha registration snapshot", admin_ha_registration_snapshot },
	{ "ha cluster set", admin_ha_cluster_set },
	{ "ha hub role", admin_ha_hub_role },
	{ "ha hub show", admin_ha_hub_show },
	{ "ha activate", admin_ha_activate },
	{ "ha monitor", admin_ha_monitor },
	{ "ha show", admin_ha_show },
	{ "route show",		admin_route_show },
	{ "show",		admin_cache_show },
	{ "cache show",		admin_cache_show },
	{ "flush",		admin_cache_flush },
	{ "cache flush",	admin_cache_flush },
	{ "purge",		admin_cache_purge },
	{ "cache purge",	admin_cache_purge },
	{ "cache lowerdown",	admin_cache_lower_down },
	{ "renew",		admin_cache_renew },
	{ "cache renew",	admin_cache_renew },
	{ "interface show",	admin_interface_show },
	{ "redirect purge",	admin_redirect_purge },
	{ "update nbma",	admin_update_nbma },
	{ "ha managed stop", admin_managed_stop },
	{ "ha managed reload", admin_managed_reload },
	{ "reload",		admin_config_reload },
	{ "config reload",	admin_config_reload },
	{ "map add",		admin_map_add },
	{ "map del",		admin_map_del },
	{ "map save",		admin_config_save },
	{ "config save",	admin_config_save },
};

static void admin_receive_cb(struct ev_io *w, int revents)
{
	struct admin_remote *rm = container_of(w, struct admin_remote, io);
	int fd = rm->io.fd;
	ssize_t len;
	int i, cmdlen;

	len = recv(fd, rm->cmd, sizeof(rm->cmd) - rm->num_read, MSG_DONTWAIT);
	if (len < 0 && errno == EAGAIN)
		return;
	if (len <= 0)
		goto err;

	rm->num_read += len;
	if (rm->num_read >= sizeof(rm->cmd))
		goto err;

	if (rm->cmd[rm->num_read-1] != '\n')
		return;
	rm->cmd[--rm->num_read] = 0;

	for (i = 0; i < ARRAY_SIZE(admin_handler); i++) {
		cmdlen = strlen(admin_handler[i].command);
		if (rm->num_read >= cmdlen &&
		    strncasecmp(rm->cmd, admin_handler[i].command, cmdlen) == 0) {
			nhrp_debug("Admin: %s", rm->cmd);
			rm->in_handler = TRUE;
			admin_handler[i].handler(rm, &rm->cmd[cmdlen]);
			rm->in_handler = FALSE;
			break;
		}
	}
	if (i >= ARRAY_SIZE(admin_handler)) {
		admin_write(rm,
			    "Status: error\n"
			    "Reason: unrecognized command\n");
	}
	if (rm->monitor || rm->deferred)
		return;

err:
	admin_free_remote(rm);
}

static void admin_timeout_cb(struct ev_timer *t, int revents)
{
	admin_free_remote(container_of(t, struct admin_remote, timeout));
}

static void admin_accept_cb(ev_io *w, int revents)
{
	struct admin_remote *rm;
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);
	int cnx;

	cnx = accept(w->fd, (struct sockaddr *) &from, &fromlen);
	if (cnx < 0)
		return;
	fcntl(cnx, F_SETFD, FD_CLOEXEC);
	fcntl(cnx, F_SETFL, O_NONBLOCK);

	rm = calloc(1, sizeof(struct admin_remote));
	list_init(&rm->monitor_list_entry);

	ev_io_init(&rm->io, admin_receive_cb, cnx, EV_READ);
	ev_io_start(&rm->io);
	ev_timer_init(&rm->timeout, admin_timeout_cb, 10.0, 0.);
	ev_timer_start(&rm->timeout);
}

int admin_init(const char *opennhrp_socket)
{
	struct sockaddr_un sun;
	int fd;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlen(opennhrp_socket) >= sizeof(sun.sun_path)) {
		errno = ENAMETOOLONG;
		nhrp_error("Failed initialize admin socket [%s]: %s",
			   opennhrp_socket, strerror(errno));
		return 0;
	}
	strcpy(sun.sun_path, opennhrp_socket);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return 0;

	fcntl(fd, F_SETFD, FD_CLOEXEC);
	unlink(opennhrp_socket);
	if (bind(fd, (struct sockaddr *) &sun, sizeof(sun)) != 0)
		goto err_close;

	if (listen(fd, 5) != 0)
		goto err_close;

	ev_io_init(&accept_io, admin_accept_cb, fd, EV_READ);
	ev_io_start(&accept_io);

	return 1;

err_close:
	nhrp_error("Failed initialize admin socket [%s]: %s",
		   opennhrp_socket, strerror(errno));
	close(fd);
	return 0;
}
