#ifndef _NF_CONNTRACK_FCC_H
#define _NF_CONNTRACK_FCC_H

#ifdef __KERNEL__

struct rsrhdr {
	__be16	ver:2,
			pad:1,
			fmt:5,
			feedback:8;
	__be16	len;
	__be32	ssrc1;
	__be32	ssrc2;
	__be32	fci_info;
	__be32	fci_maddr;
	__be32	fci_saddr;
	__be32	fci_faddr;
};

extern int (*fcc_nat_expect_hook) (struct sk_buff *skb,
					struct nf_conn *ct,
					enum ip_conntrack_info ctinfo,
 					struct nf_conntrack_expect *rtp_exp);

extern int (*fcc_nat_addr_hook) (struct sk_buff *skb, struct nf_conn *ct, 
				enum ip_conntrack_info ctinfo, unsigned int matchoff, 
				unsigned int matchlen, __be32 addr);

#endif /* __KERNEL__ */

#endif /* _NF_CONNTRACK_FCC_H */
