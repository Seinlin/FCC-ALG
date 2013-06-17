/****************************************************************************/
/*                                                                          */
/* File: nf_nat_fcc.c                                                       */
/*                                                                          */
/* Description:                                                             */
/*    FCC extension for NAT alteration.                                     */
/*                                                                          */
/* Author : Seinlin (Kaizhen Li)                                            */
/*                                                                          */
/*                                                                          */
/* This program is free software; you can redistribute it and/or modify     */
/* it under the terms of the GNU General Public License version 2 as        */
/* published by the Free Software Foundation.                               */
/*                                                                          */
/* This program is distributed in the hope that it will be useful,          */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of           */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             */
/* GNU General Public License for more details.                             */
/*                                                                          */
/* You should have received a copy of the GNU General Public License        */
/* along with this program; if not, write to the Free Software              */
/* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,USA */
/*                                                                          */
/****************************************************************************/

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_helper.h>
#include <net/netfilter/nf_nat_rule.h>
#include <linux/netfilter/nf_conntrack_fcc.h>

/****************************************************************************/
static int fcc_nat_addr (struct sk_buff *skb, struct nf_conn *ct, enum ip_conntrack_info ctinfo,
	unsigned int matchoff, unsigned int matchlen, __be32 fci_saddr)
{
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	unsigned int addrLen;
	__be32 newAddr;


	if (ct->tuplehash[dir].tuple.src.u3.ip == fci_saddr && 
		ct->tuplehash[!dir].tuple.dst.u3.ip != fci_saddr) {

		newAddr = htonl(ct->tuplehash[!dir].tuple.dst.u3.ip);
		addrLen = sizeof(__be32);
	}
	else {

		return NF_ACCEPT;
	}

	if (ip_hdr(skb)->protocol == IPPROTO_TCP) {

		if (!nf_nat_mangle_tcp_packet(skb, ct, ctinfo, matchoff, matchlen,
					(char *)&newAddr, addrLen)) {
 
			if (net_ratelimit())
				pr_notice("nf_nat_fcc: nf_nat_mangle_tcp_packet error\n");
			return NF_DROP;
		}
	}
	else  {
 
		if (!nf_nat_mangle_udp_packet(skb, ct, ctinfo, matchoff, matchlen,
					(char *)&newAddr, addrLen)) {
 
			if (net_ratelimit())
				pr_notice("nf_nat_fcc: nf_nat_mangle_udp_packet error\n");

			return NF_DROP;
		}
	}
 
	return NF_ACCEPT;
}

/****************************************************************************/
static void fcc_nat_redirect(struct nf_conn *ct,
			    struct nf_conntrack_expect *exp)
{
	struct nf_nat_range range;

	/* This must be a fresh one. */
	BUG_ON(ct->status & IPS_NAT_DONE_MASK);


	/* Change src to where new ct comes from */
	range.flags = IP_NAT_RANGE_MAP_IPS;
	range.min_ip = range.max_ip =
		ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
	nf_nat_setup_info(ct, &range, IP_NAT_MANIP_SRC);

	/* For DST manip, map port here to where it's expected. */
	range.flags = (IP_NAT_RANGE_MAP_IPS | IP_NAT_RANGE_PROTO_SPECIFIED);
	range.min = range.max = exp->saved_proto;
	range.min_ip = range.max_ip 
		= ct->master->tuplehash[!exp->dir].tuple.src.u3.ip;

	pr_debug("fcc_nat_redirect: setup PREROUTING map %pI4:%hu\n",
	       	 &range.min_ip, ntohs(range.min.udp.port));
	
	nf_nat_setup_info(ct, &range, IP_NAT_MANIP_DST);
}

/****************************************************************************/
static int fcc_nat_expect (struct sk_buff *skb, struct nf_conn *ct, enum ip_conntrack_info ctinfo, 
	struct nf_conntrack_expect *rtp_exp)
{	
	struct nf_conntrack_expect *exp;
	struct net *net = nf_ct_net(ct);
	int dir = CTINFO2DIR(ctinfo);
	int exp_exist = 0;	
	u_int16_t nated_port = 0;

	pr_debug("%s: rtp dst %pI4:%hu, src %pI4:%hu\n", __FUNCTION__,
		&rtp_exp->tuple.dst.u3.ip, ntohs(rtp_exp->tuple.dst.u.all),
		&rtp_exp->tuple.src.u3.ip, ntohs(rtp_exp->tuple.src.u.all) );
	
	/* Set expectations for NAT */
	rtp_exp->saved_proto.udp.port = rtp_exp->tuple.dst.u.udp.port;
	rtp_exp->saved_ip = rtp_exp->tuple.dst.u3.ip;
	rtp_exp->expectfn = fcc_nat_redirect;
	rtp_exp->dir = !dir;

	exp = nf_ct_expect_find_get(net, &rtp_exp->tuple);
	if (exp) {
		/* Expectation already exists */ 
		rtp_exp->tuple.dst.u.udp.port = exp->tuple.dst.u.udp.port;
		nated_port = ntohs(exp->tuple.dst.u.udp.port);
		exp_exist = 1;
	}

	if (exp_exist) {

		pr_debug("nf_nat_fcc: exp exist go to expect_end!\n");
		nf_ct_expect_related(rtp_exp);
		goto expect_end;
	}

	/* Try to get a port. */
	for (nated_port = ntohs(rtp_exp->tuple.dst.u.udp.port);
	     nated_port != 0; nated_port++) {

		rtp_exp->tuple.dst.u.udp.port = htons(nated_port);
		if (nf_ct_expect_related(rtp_exp) == 0) 
				break;
	}

	if (nated_port == 0) {	/* No port available */
		if (net_ratelimit())
			pr_notice("nf_nat_fcc: out of RTP ports\n");

		return 0;
	}

expect_end:
	/* Success */
	pr_debug("nf_nat_fcc: expect RTP ");
	nf_ct_dump_tuple(&rtp_exp->tuple);

	return 0;
}


/****************************************************************************/
static int __init init(void)
{
	BUG_ON(rcu_dereference(fcc_nat_expect_hook) != NULL);
	rcu_assign_pointer(fcc_nat_expect_hook, fcc_nat_expect);
	BUG_ON(rcu_dereference(fcc_nat_addr_hook) != NULL);
	rcu_assign_pointer(fcc_nat_addr_hook, fcc_nat_addr);

	pr_notice("nf_nat_fcc: init success\n");
	return 0;
}

/****************************************************************************/
static void __exit fini(void)
{
	rcu_assign_pointer(fcc_nat_expect_hook, NULL);
	rcu_assign_pointer(fcc_nat_addr_hook, NULL);

	synchronize_rcu();
}

/****************************************************************************/
module_init(init);
module_exit(fini);

/****************************************************************************/
MODULE_AUTHOR("Seinlin");
MODULE_DESCRIPTION("FCC NAT helper");
MODULE_LICENSE("GPL");
MODULE_ALIAS("nf_nat_fcc");
