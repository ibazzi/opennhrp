/* nhrp_server.c - NHRP request handling
 *
 * Copyright (C) 2007-2009 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 or later as
 * published by the Free Software Foundation.
 *
 * See http://www.gnu.org/ for details.
 */

#include <string.h>
#include <netinet/in.h>

#include "nhrp_common.h"
#include "nhrp_packet.h"
#include "nhrp_interface.h"
#include "nhrp_peer.h"

static int nhrp_handle_resolution_request(struct nhrp_packet *packet)
{
	char tmp[64], tmp2[64];
	struct nhrp_payload *payload;
	struct nhrp_peer *peer = packet->dst_peer;
	struct nhrp_cie *cie;

	nhrp_info("Received Resolution Request from proto src %s to %s",
		  nhrp_address_format(&packet->src_protocol_address,
				      sizeof(tmp), tmp),
		  nhrp_address_format(&packet->dst_protocol_address,
				      sizeof(tmp2), tmp2));

	packet->hdr.type = NHRP_PACKET_RESOLUTION_REPLY;
	packet->hdr.flags &= NHRP_FLAG_RESOLUTION_SOURCE_IS_ROUTER |
			     NHRP_FLAG_RESOLUTION_SOURCE_STABLE |
			     NHRP_FLAG_RESOLUTION_UNIQUE |
			     NHRP_FLAG_RESOLUTION_NAT;
	packet->hdr.flags |= NHRP_FLAG_RESOLUTION_DESTINATION_STABLE |
			     NHRP_FLAG_RESOLUTION_AUTHORATIVE;
	packet->hdr.hop_count = 0;

	cie = nhrp_cie_alloc();
	if (cie == NULL)
		return FALSE;

	cie->hdr = (struct nhrp_cie_header) {
		.code = NHRP_CODE_SUCCESS,
		.prefix_length = peer->prefix_length,
		.holding_time = htons(peer->interface->holding_time),
	};

	payload = nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_ANY);
	nhrp_payload_free(payload);
	nhrp_payload_set_type(payload, NHRP_PAYLOAD_TYPE_CIE_LIST);
	nhrp_payload_add_cie(payload, cie);

	if (!nhrp_packet_reroute(packet, NULL))
		return FALSE;

	peer = packet->dst_peer;
	cie->hdr.mtu = htons(peer->my_nbma_mtu);
	cie->nbma_address = peer->my_nbma_address;
	cie->protocol_address = packet->dst_iface->protocol_address;

	nhrp_info("Sending Resolution Reply %s is-at %s",
		  nhrp_address_format(&cie->protocol_address,
				      sizeof(tmp), tmp),
		  nhrp_address_format(&cie->nbma_address,
				      sizeof(tmp2), tmp2));

	/* Reset NAT header to regenerate it for reply */
	payload = nhrp_packet_extension(packet,
					NHRP_EXTENSION_NAT_ADDRESS |
					NHRP_EXTENSION_FLAG_NOCREATE,
					NHRP_PAYLOAD_TYPE_ANY);
	if (payload != NULL) {
		nhrp_payload_free(payload);
		nhrp_payload_set_type(payload, NHRP_PAYLOAD_TYPE_CIE_LIST);
	}

	return nhrp_packet_send(packet);
}

static int find_one(void *ctx, struct nhrp_peer *p)
{
	return 1;
}

static int remove_old_registrations(void *ctx, struct nhrp_peer *p)
{
	struct nhrp_peer *peer = (struct nhrp_peer *) ctx;

	/* If re-registration, mark the new connection up */
	if (nhrp_address_cmp(&peer->protocol_address, &p->protocol_address) == 0 &&
	    nhrp_address_cmp(&peer->next_hop_address, &p->next_hop_address) == 0 &&
	    peer->prefix_length == p->prefix_length)
		peer->flags |= p->flags & (NHRP_PEER_FLAG_UP |
					   NHRP_PEER_FLAG_LOWER_UP);

	p->flags |= NHRP_PEER_FLAG_REPLACED;
	nhrp_peer_remove(p);
	return 0;
}

static int nhrp_handle_registration_request(struct nhrp_packet *packet)
{
	char tmp[64], tmp2[64];
	struct nhrp_payload *payload;
	struct nhrp_cie *cie;
	struct nhrp_peer *peer, *rpeer = NULL;
	struct nhrp_peer_selector sel;
	int natted = 0;

	nhrp_info("Received Registration Request from proto src %s to %s",
		  nhrp_address_format(&packet->src_protocol_address,
				      sizeof(tmp), tmp),
		  nhrp_address_format(&packet->dst_protocol_address,
				      sizeof(tmp2), tmp2));

	/* Cisco NAT extension, CIE added IF all of the following is true:
	 * 1. We are the first hop registration server
	 *    (=no entries in forward transit CIE list)
	 * 2. NAT is detected (link layer address != announced address)
	 * 3. NAT extension is requested */
	payload = nhrp_packet_extension(packet,
					NHRP_EXTENSION_FORWARD_TRANSIT_NHS |
					NHRP_EXTENSION_FLAG_NOCREATE,
					NHRP_PAYLOAD_TYPE_CIE_LIST);
	if (payload != NULL && TAILQ_EMPTY(&payload->u.cie_list_head) &&
	    packet->src_linklayer_address.type != PF_UNSPEC &&
	    nhrp_address_cmp(&packet->src_nbma_address,
			     &packet->src_linklayer_address) != 0) {
		natted = 1;
		payload = nhrp_packet_extension(packet,
						NHRP_EXTENSION_NAT_ADDRESS |
						NHRP_EXTENSION_FLAG_NOCREATE,
						NHRP_PAYLOAD_TYPE_CIE_LIST);
		if (payload != NULL) {
			cie = nhrp_cie_alloc();
			if (cie != NULL) {
				cie->nbma_address = packet->src_linklayer_address;
				cie->protocol_address = packet->src_protocol_address;
				nhrp_payload_add_cie(payload, cie);
			}
		}
	}

	packet->hdr.type = NHRP_PACKET_REGISTRATION_REPLY;
	packet->hdr.flags &= NHRP_FLAG_REGISTRATION_UNIQUE |
			     NHRP_FLAG_REGISTRATION_NAT;
	packet->hdr.hop_count = 0;

	payload = nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_CIE_LIST);
	TAILQ_FOREACH(cie, &payload->u.cie_list_head, cie_list_entry) {
		peer = nhrp_peer_alloc(packet->src_iface);
		if (peer == NULL) {
			cie->hdr.code = NHRP_CODE_INSUFFICIENT_RESOURCES;
			continue;
		}

		peer->type = NHRP_PEER_TYPE_DYNAMIC;
		peer->afnum = packet->hdr.afnum;
		peer->protocol_type = packet->hdr.protocol_type;
		peer->expire_time = ev_now() + ntohs(cie->hdr.holding_time);
		peer->mtu = ntohs(cie->hdr.mtu);

		if (cie->nbma_address.addr_len != 0)
			peer->next_hop_address = cie->nbma_address;
		else
			peer->next_hop_address = packet->src_nbma_address;

		if (natted) {
			peer->next_hop_nat_oa  = peer->next_hop_address;
			peer->next_hop_address = packet->src_linklayer_address;
		}

		if (cie->protocol_address.addr_len != 0)
			peer->protocol_address = cie->protocol_address;
		else
			peer->protocol_address = packet->src_protocol_address;

		peer->prefix_length = cie->hdr.prefix_length;
		if (peer->prefix_length == 0xff)
			peer->prefix_length = peer->protocol_address.addr_len * 8;

		memset(&sel, 0, sizeof(sel));
		sel.flags = NHRP_PEER_FIND_EXACT;
		sel.type_mask = ~NHRP_PEER_TYPEMASK_REMOVABLE;
		sel.interface = packet->src_iface;
		sel.protocol_address = peer->protocol_address;
		sel.prefix_length = peer->prefix_length;

		/* Check that there is no conflicting peers and
		 * that the script allows this registration. */
		if (nhrp_peer_foreach(find_one, peer, &sel) == 0 &&
		    nhrp_peer_authorize_registration(peer)) {
			/* Remove all old stuff and accept registration */
			memset(&sel, 0, sizeof(sel));
			sel.flags = NHRP_PEER_FIND_EXACT;
			sel.type_mask = NHRP_PEER_TYPEMASK_REMOVABLE;
			sel.interface = packet->src_iface;
			sel.protocol_address = peer->protocol_address;
			sel.prefix_length = peer->prefix_length;
			nhrp_peer_foreach(remove_old_registrations, peer, &sel);

			cie->hdr.code = NHRP_CODE_SUCCESS;
			nhrp_peer_insert(peer);

			if (rpeer == NULL)
				rpeer = nhrp_peer_get(peer);
		} else {
			/* Non-removable binding already exists */
			cie->hdr.code = NHRP_CODE_ADMINISTRATIVELY_PROHIBITED;
			peer->flags |= NHRP_PEER_FLAG_REPLACED;
		}
		nhrp_peer_put(peer);
	}

	if (!nhrp_packet_reroute(packet, rpeer)) {
		if (rpeer != NULL)
			nhrp_peer_put(rpeer);

		nhrp_packet_send_error(
			packet, NHRP_ERROR_PROTOCOL_ADDRESS_UNREACHABLE, 0);
		return FALSE;
	}
	if (rpeer != NULL)
		nhrp_peer_put(rpeer);

	return nhrp_packet_send(packet);
}

static int nhrp_handle_purge_request(struct nhrp_packet *packet)
{
	char tmp[64], tmp2[64];
	struct nhrp_peer_selector sel;
	struct nhrp_payload *payload;
	struct nhrp_cie *cie;
	int flags, ret = TRUE;

	nhrp_info("Received Purge Request from proto src %s to %s",
		  nhrp_address_format(&packet->src_protocol_address,
				      sizeof(tmp), tmp),
		  nhrp_address_format(&packet->dst_protocol_address,
				      sizeof(tmp2), tmp2));

	flags = packet->hdr.flags;
	packet->hdr.type = NHRP_PACKET_PURGE_REPLY;
	packet->hdr.flags = 0;
	packet->hdr.hop_count = 0;

	if (!(flags & NHRP_FLAG_PURGE_NO_REPLY)) {
		if (nhrp_packet_reroute(packet, NULL))
			ret = nhrp_packet_send(packet);
		else
			ret = FALSE;
	}

	payload = nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_CIE_LIST);
	TAILQ_FOREACH(cie, &payload->u.cie_list_head, cie_list_entry) {
		nhrp_info("Purge proto %s/%d nbma %s",
			nhrp_address_format(&cie->protocol_address,
					    sizeof(tmp), tmp),
			cie->hdr.prefix_length,
			nhrp_address_format(&cie->nbma_address,
					    sizeof(tmp2), tmp2));

		memset(&sel, 0, sizeof(sel));
		sel.flags = NHRP_PEER_FIND_EXACT;
		sel.type_mask = NHRP_PEER_TYPEMASK_REMOVABLE;
		sel.interface = packet->src_iface;
		sel.protocol_address = cie->protocol_address;
		sel.prefix_length = cie->hdr.prefix_length;
		nhrp_peer_foreach(nhrp_peer_remove_matching, NULL, &sel);
		nhrp_rate_limit_clear(&cie->protocol_address,
				      cie->hdr.prefix_length);
	}

	return ret;
}

static int nhrp_handle_traffic_indication(struct nhrp_packet *packet)
{
	char tmp[64], tmp2[64];
	struct nhrp_address dst;
	struct nhrp_payload *pl;

	pl = nhrp_packet_payload(packet, NHRP_PAYLOAD_TYPE_RAW);
	if (pl == NULL)
		return FALSE;

	if (!nhrp_address_parse_packet(packet->hdr.protocol_type,
				       pl->u.raw->length, pl->u.raw->data,
				       NULL, &dst))
		return FALSE;

	/* Shortcuts enabled? */
	if (packet->src_iface->flags & NHRP_INTERFACE_FLAG_SHORTCUT) {
		nhrp_info("Traffic Indication from proto src %s; "
			  "about packet to %s",
			  nhrp_address_format(&packet->src_protocol_address,
					      sizeof(tmp), tmp),
			  nhrp_address_format(&dst, sizeof(tmp2), tmp2));

		nhrp_peer_traffic_indication(packet->src_iface,
					     packet->hdr.afnum,
					     &dst);
	} else {
		nhrp_info("Traffic Indication ignored from proto src %s; "
			  "about packet to %s",
			  nhrp_address_format(&packet->src_protocol_address,
					      sizeof(tmp), tmp),
			  nhrp_address_format(&dst, sizeof(tmp2), tmp2));
	}

	return TRUE;
}

void server_init(void)
{
	nhrp_packet_hook_request(NHRP_PACKET_RESOLUTION_REQUEST,
				 nhrp_handle_resolution_request);
	nhrp_packet_hook_request(NHRP_PACKET_REGISTRATION_REQUEST,
				 nhrp_handle_registration_request);
	nhrp_packet_hook_request(NHRP_PACKET_PURGE_REQUEST,
				 nhrp_handle_purge_request);
	nhrp_packet_hook_request(NHRP_PACKET_TRAFFIC_INDICATION,
				 nhrp_handle_traffic_indication);
}
