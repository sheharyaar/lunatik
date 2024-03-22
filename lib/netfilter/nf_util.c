/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2003 USAGI/WIDE Project, Yasuyuki Kozakai <yasuyuki.kozakai@toshiba.co.jp>
 * (C) 2002-2004 Netfilter Core Team <coreteam@netfilter.org>
 * (C) 2005-2007 Patrick McHardy <kaber@trash.net>
 * (C) 2017-2019 This file was modified by CUJO LLC
 *
 * Based on net/ipv4/ip_forward.c, net/ipv6/ip6_output.c, net/ipv6.h,
 * linux/net.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/version.h>
#include <linux/ratelimit.h>
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include "nf_util.h"
#include "kpi_compat.h"

#if IS_ENABLED(CONFIG_IPV6)
#include <net/ip6_route.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

static struct sk_buff *tcp_ipv6_payload(struct sk_buff *skb,
		const unsigned char *payload, size_t len)
{
	struct tcphdr tcph, *ntcphp;
	struct ipv6hdr *nip6h, *ip6h = ipv6_hdr(skb);
	struct sk_buff *nskb;
	unsigned char *data;
	unsigned int otcplen;
	size_t tcplen;
	int tcphoff;
	u8 proto;
	__be16 frag_off;

	if (!(ipv6_addr_type(&ip6h->saddr) & IPV6_ADDR_UNICAST) ||
	    !(ipv6_addr_type(&ip6h->daddr) & IPV6_ADDR_UNICAST)) {
		pr_warn("addr is not unicast.\n");
		return NULL;
	}

	proto = ip6h->nexthdr;
	tcphoff = ipv6_skip_exthdr(skb, (u8*)(ip6h + 1) - skb->data,
		&proto, &frag_off);

	if (tcphoff < 0 || tcphoff > skb->len) {
		pr_warn("Cannot get TCP header.\n");
		return NULL;
	}

	otcplen = skb->len - tcphoff;

	/* IP header checks: fragment, too short. */
	if (proto != IPPROTO_TCP || otcplen < sizeof(struct tcphdr)) {
		pr_warn("proto(%d) != IPPROTO_TCP, or too short. tcplen = %d\n",
			 proto, otcplen);
		return NULL;
	}

	if (skb_copy_bits(skb, tcphoff, &tcph, sizeof(struct tcphdr))) {
		pr_warn("Could not copy TCP header.\n");
		return NULL;
	}

	nskb = alloc_skb(sizeof(struct ipv6hdr) + sizeof(struct tcphdr) +
	                 LL_MAX_HEADER + len, GFP_ATOMIC);
	if (nskb == NULL) {
		pr_warn("Could not allocate new skb\n");
		return NULL;
	}

	nskb->protocol = htons(ETH_P_IPV6);
	skb_reserve(nskb, LL_MAX_HEADER);

	skb_reset_network_header(nskb);
	nip6h = (struct ipv6hdr *)skb_put(nskb, sizeof(struct ipv6hdr));
	memcpy(nip6h, ip6h, sizeof(struct ipv6hdr));
	nip6h->nexthdr = IPPROTO_TCP;

	skb_set_transport_header(nskb, sizeof(struct ipv6hdr));
	ntcphp = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
	memcpy(ntcphp, &tcph, sizeof(struct tcphdr));
	ntcphp->doff = sizeof(struct tcphdr) / 4;

	data = skb_put(nskb, len);
	memcpy(data, payload, len);

	tcplen = nskb->len - sizeof(struct ipv6hdr);

	/* Adjust TCP checksum */
	ntcphp->check = 0;
	ntcphp->check = csum_ipv6_magic(&nip6h->saddr, &nip6h->daddr,
				      tcplen, IPPROTO_TCP,
				      csum_partial(ntcphp, tcplen, 0));

	nip6h->payload_len = htons(tcplen);
	nskb->ip_summed = CHECKSUM_UNNECESSARY;

	/* ip6_route_me_harder expects skb->dst to be set */
	skb_dst_set_noref(nskb, skb_dst(skb));

	return nskb;
}

static int tcp_ipv6_payload_length(const struct sk_buff *skb)
{
	struct ipv6hdr *iph = ipv6_hdr(skb);
	struct tcphdr _tcph, *tcph;
	int tcphoff;
	__be16 frag_off;
	u8 proto;

	proto = iph->nexthdr;
	tcphoff = ipv6_skip_exthdr(skb, (u8*)(iph + 1) - skb->data,
		&proto, &frag_off);

	if (proto != IPPROTO_TCP) {
		pr_warn_ratelimited("TCP length called on non tcp packet.\n");
		return -1;
	}

	if (unlikely(tcphoff < 0 || tcphoff >= skb->len)) {
		pr_warn("Invalid TCP header offset.\n");
		return -1;
	}

	tcph = skb_header_pointer(skb, tcphoff, sizeof(_tcph), &_tcph);
	if (unlikely(tcph == NULL)) {
		pr_warn("Could not get TCP header.\n");
		return -1;
	}

	return skb->len - tcphoff - tcph->doff * 4;
}

#endif /* IS_ENABLED(CONFIG_IPV6) */

static struct sk_buff *tcp_ipv4_payload(struct sk_buff *skb,
		const unsigned char *payload, size_t len)
{
	struct tcphdr tcph, *ntcphp;
	struct iphdr *niph;
	struct sk_buff *nskb;
	unsigned char *data;
	size_t tcplen;
	int tcphoff;

	/* IP header checks: fragment. */
	if (ip_hdr(skb)->frag_off & htons(IP_OFFSET))
		return NULL;

	tcphoff = skb_transport_offset(skb);
	if (tcphoff < 0 || tcphoff >= skb->len) {
		pr_warn("Cannot get TCP header.\n");
		return NULL;
	}

	if (skb_copy_bits(skb, tcphoff, &tcph, sizeof(struct tcphdr))) {
		pr_warn("Could not copy TCP header.\n");
		return NULL;
	}

	nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) +
	                  LL_MAX_HEADER + len, GFP_ATOMIC);
	if (nskb == NULL) {
		pr_warn("Could not allocate new skb\n");
		return NULL;
	}

	nskb->protocol = htons(ETH_P_IP);
	skb_reserve(nskb, LL_MAX_HEADER);

	skb_reset_network_header(nskb);
	niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
	memcpy(niph, ip_hdr(skb), sizeof(struct iphdr));
	niph->ihl = sizeof(struct iphdr) / 4;
	niph->frag_off = htons(IP_DF);

	skb_set_transport_header(nskb, sizeof(struct iphdr));
	ntcphp = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
	memcpy(ntcphp, &tcph, sizeof(struct tcphdr));
	ntcphp->doff = sizeof(struct tcphdr) / 4;

	data = skb_put(nskb, len);
	memcpy(data, payload, len);

	tcplen = nskb->len - ip_hdrlen(nskb);
	ntcphp->check = 0;
	ntcphp->check = csum_tcpudp_magic(niph->saddr, niph->daddr,
	                                 tcplen, IPPROTO_TCP,
	                                 csum_partial(ntcphp, tcplen, 0));

	niph->tot_len = htons(nskb->len);
	ip_send_check(niph);

	/* ip_route_me_harder expects skb->dst to be set */
	skb_dst_set_noref(nskb, skb_dst(skb));

	return nskb;
}

static int tcp_ipv4_payload_length(const struct sk_buff *skb)
{
	struct tcphdr _tcph, *tcph;
	int tcphoff;

	if (ip_hdr(skb)->protocol != IPPROTO_TCP) {
		pr_warn_ratelimited("TCP length called on non tcp packet.\n");
		return -1;
	}

	tcphoff = ip_hdrlen(skb);
	if (unlikely(tcphoff < 0 || tcphoff >= skb->len)) {
		pr_warn("Invalid TCP header offset.\n");
		return -1;
	}

	tcph = skb_header_pointer(skb, tcphoff, sizeof(_tcph), &_tcph);
	if (unlikely(tcph == NULL)) {
		pr_warn("Could not get TCP header.\n");
		return -1;
	}

	return skb->len - tcphoff - tcph->doff * 4;
}

struct sk_buff *tcp_payload(struct sk_buff *skb,
                            const unsigned char *payload, size_t len)
{
	if (IS_ENABLED(CONFIG_IPV6) && skb->protocol == htons(ETH_P_IPV6))
		return tcp_ipv6_payload(skb, payload, len);
	return tcp_ipv4_payload(skb, payload, len);
}

int tcp_payload_length(const struct sk_buff *skb)
{
	if (IS_ENABLED(CONFIG_IPV6) && skb->protocol == htons(ETH_P_IPV6))
		return tcp_ipv6_payload_length(skb);
	return tcp_ipv4_payload_length(skb);
}
