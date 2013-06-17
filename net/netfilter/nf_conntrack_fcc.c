/****************************************************************************/
/*                                                                          */
/* File: nf_conntrack_fcc.c                                                 */
/*                                                                          */
/* Description:                                                             */
/*    FCC helper for connection tracking.                                   */
/*                                                                          */
/* Author : Seinlin (Kaizhen Li)                                            */
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
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/ctype.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <net/checksum.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <linux/netfilter/nf_conntrack_fcc.h>
#include <linux/iqos.h>

#define FCC_PORT 5000

/* This is slow, but it's simple. --RR */
static char *fcc_buffer;

static DEFINE_SPINLOCK(nf_fcc_lock);

#define MAX_PORTS 8
static u_int16_t ports[MAX_PORTS];
static unsigned int ports_c;
module_param_array(ports, ushort, &ports_c, 0400);
MODULE_PARM_DESC(ports, "port numbers of FCC servers");

#define FCC_CHANNEL_MAX 16
static int max_outstanding = FCC_CHANNEL_MAX;
module_param(max_outstanding, int, 0600);
MODULE_PARM_DESC(max_outstanding, "max number of outstanding SETUP requests per FCC session");

static unsigned char protonum = IPPROTO_UDP;
module_param(protonum, byte, 0600);
MODULE_PARM_DESC(protonum, "protocol of FCC session");

static u_int16_t fcc_shift = 0;
static u_int8_t fcc_match = 0x5;

static struct nf_conntrack_helper fcc[MAX_PORTS];
static char fcc_names[MAX_PORTS][sizeof("fcc-65535")];
static struct nf_conntrack_expect_policy fcc_exp_policy;

/****************************************************************************/
int (*fcc_nat_expect_hook) (struct sk_buff *skb, struct nf_conn *ct,
			      enum ip_conntrack_info ctinfo, struct nf_conntrack_expect *exp);
EXPORT_SYMBOL_GPL(fcc_nat_expect_hook);

int (*fcc_nat_addr_hook)(struct sk_buff *skb, struct nf_conn *ct, 
				enum ip_conntrack_info ctinfo, unsigned int matchoff, 
				unsigned int matchlen, __be32 addr);
EXPORT_SYMBOL_GPL(fcc_nat_addr_hook);


/****************************************************************************/
static int expect_fcc_channel(struct sk_buff *skb, struct nf_conn *ct,
			       enum ip_conntrack_info ctinfo, __be16 rtpport)
{
	int ret = 0;
	int dir = CTINFO2DIR(ctinfo);
	struct nf_conntrack_expect *rtp_exp;
	typeof(fcc_nat_expect_hook) fcc_nat_expect;

	if (rtpport == 0)
		return -1;

	/* Create expect for RTP */
	if ((rtp_exp = nf_ct_expect_alloc(ct)) == NULL)
		return -1;

	/* Mostly FCC server and media server is different. In this case Source Addr need to be NULL */
	nf_ct_expect_init(rtp_exp, NF_CT_EXPECT_CLASS_DEFAULT, nf_ct_l3num(ct),
			  NULL, /* &ct->tuplehash[!dir].tuple.src.u3 */
			  &ct->tuplehash[!dir].tuple.dst.u3,
			  protonum, NULL, &rtpport);

	if ((fcc_nat_expect = rcu_dereference(fcc_nat_expect_hook)) &&
	    ct->status & IPS_NAT_MASK) {
		/* NAT needed */
		ret = fcc_nat_expect(skb, ct, ctinfo, rtp_exp);
	}
	else {
		/* Conntrack only */
		if (nf_ct_expect_related(rtp_exp) == 0) {
			pr_debug("nf_ct_fcc: expect RTP ");
			nf_ct_dump_tuple(&rtp_exp->tuple);
		}
		else {
			ret = -1;
		}
	}

	nf_ct_expect_put(rtp_exp);

	return ret;
}

/****************************************************************************/
static int nf_fcc_help(struct sk_buff *skb, unsigned int protoff,
		struct nf_conn *ct, enum ip_conntrack_info ctinfo)
{
	int dir = CTINFO2DIR(ctinfo);
	struct tcphdr _tcph, *th;
	struct udphdr _udph, *uh;
	struct rsrhdr *rsr;
	unsigned int dataoff, datalen;
	int matchlen = 0;
	int matchoff = 0;
	__be16 rtpport = 0;
	__be16 rtcpport = 0; 

	typeof(fcc_nat_addr_hook) fcc_nat_addr;
	
	pr_debug("%s: check protonum=%d, dir=%d, ctinfo=%d, skblen=%d\n", 
		__FUNCTION__, protonum, dir, ctinfo, skb->len);

	if (protonum == IPPROTO_UDP) {
		/* Get UDP header */
		uh = skb_header_pointer(skb, protoff, sizeof(_udph), &_udph);
		if (uh == NULL) {
			pr_debug("No UDP header!\n");
			return NF_ACCEPT;
		}

		/* Get UDP payload offset */
		dataoff = protoff + 8;
	}
	else {
		/* Get TCP header */
		th = skb_header_pointer(skb, protoff, sizeof(_tcph), &_tcph);
		if (th == NULL) {
			pr_debug("No TCP header!\n");
			return NF_ACCEPT;
		}

		/* Get TCP payload offset */
		dataoff = protoff + th->doff * 4;
	}
	
	if (dataoff >= skb->len) { /* No data? */
		pr_debug("data off is greater than length!\n");
		return NF_ACCEPT;
	}

	/* Get UDP/TCP payload length */
	datalen = skb->len - dataoff;

	if(datalen < sizeof(struct rsrhdr)) {
		pr_debug("data len is less than RSR header!\n");
		return NF_ACCEPT;
	}

	spin_lock_bh(&nf_fcc_lock);

	/* Get UDP/TCP payload pointer */
	rsr = (struct rsrhdr *)skb_header_pointer(skb, dataoff, datalen, fcc_buffer);
	BUG_ON(rsr == NULL);

	/* check RSR type */
	if ( rsr->ver != 2 || rsr->fmt != fcc_match ) {
		pr_debug("fmt of RSR is not match!\n");
		goto end;
	}
 
	if (memcmp(&ct->tuplehash[dir].tuple.src.u3,
	   	   &ct->tuplehash[!dir].tuple.dst.u3,
	   	   sizeof(ct->tuplehash[dir].tuple.src.u3)) != 0) {
	   	/* LAN to WAN */

		rtcpport = ct->tuplehash[dir].tuple.src.u.all;
		rtpport = rtcpport - 1; 

		/*
		pr_debug("%s: LAN to WAN RTP Port = %d, RTCP Port = %d\n", __FUNCTION__, rtpport, rtcpport);
		ct->tuplehash[dir].tuple.src.u.all += fcc_shift;

		rtpport += fcc_shift;
		rtcpport += fcc_shift;
		*/
		
		pr_debug("%s: check rsr addr=%pI4, src=%pI4, dst=%pI4\n", 
			__FUNCTION__, &rsr->fci_saddr, &ct->tuplehash[dir].tuple.src.u3.ip, &ct->tuplehash[dir].tuple.dst.u3.ip);

		if ((fcc_nat_addr = rcu_dereference(fcc_nat_addr_hook))) {

			matchoff=20;
			matchlen=sizeof(__be32);
			fcc_nat_addr(skb, ct, ctinfo, matchoff, matchlen, rsr->fci_saddr);
		}

		pr_debug("%s: LAN to WAN RTP Port = %d, RTCP Port = %d\n", __FUNCTION__, rtpport, rtcpport);
		
		/* expect RTCP from any IP */
		expect_fcc_channel(skb, ct, ctinfo, rtcpport);

		/* expect RTP from any IP */
		expect_fcc_channel(skb, ct, ctinfo, rtpport);	
		
		/* register the RTP ports with ingress QoS classifier */
		iqos_add_L4port(protonum, rtpport, IQOS_ENT_DYN, IQOS_PRIO_HIGH);
		iqos_add_L4port(protonum, rtcpport, IQOS_ENT_DYN, IQOS_PRIO_HIGH);		
	} 
	else {
		/* WAN to LAN, can do something here in case of necessary */
	}

end:
	spin_unlock_bh(&nf_fcc_lock);

	return NF_ACCEPT;
}


static int my_atoi(const char *s)
{
	int val = 0;
	int base = 10;

	/* skip space */
	while (*s == ' ')
		s++;

	if( strlen(s) > 2 && *s == '0' && *(s+1)=='x' ) {

		base = 16;
		s += 2;
	}

	for (;; s++) {

		switch (*s) {

			case '0'...'9':
				val = base * val + (*s-'0');
				break;

			case 'a'...'f':
				if (base == 10)
					return 0;
				else
					val = base * val + (*s-'a' + 10);
				break;

			case 'A'...'F':
				if (base == 10)
					return 0;
				else
					val = base * val + (*s-'A' + 10);
				break;

			default:
				return val;
		}
	}
}

static int fcc_read_proc(char* page, char ** start, off_t off, int count,
                            int* eof, void * data)
{ 
	char buffer[64]={0};
	int i;
	
	sprintf(buffer, "ports=");
	for (i=0;i<MAX_PORTS;i++)
	{
		sprintf(buffer,"%s%d,", buffer, ports[i]);
	}
	return sprintf( page, "shift: %d\nmatch: 0x%0X\n%s\n", fcc_shift, fcc_match, buffer);
}

static int fcc_write_proc(struct file* file, const char* buffer,
                             unsigned long count, void *data)
{
	char *foo, *val;

	if (count > 3) {

		foo = kmalloc(count, GFP_ATOMIC);

		if (!foo) {
			pr_err("FCC: out of memory!\n");
			return count;
		}

		if(copy_from_user(foo, buffer, count)) {
			return -EFAULT;
		}

		val = foo;
		if (*val == 's')
			fcc_shift = my_atoi(++val);
		else if (*val == 'm')
			fcc_match = my_atoi(++val);

		kfree (foo);
	}

	return count;
}

/****************************************************************************/
/* register the proc file */
/****************************************************************************/
static void fcc_init_proc(void)
{
	struct proc_dir_entry* entry;
	entry = create_proc_entry("fcc", 0644, init_net.proc_net);
	entry->read_proc = fcc_read_proc;
	entry->write_proc = fcc_write_proc;
}

static void fcc_cleanup_proc(void)
{
	remove_proc_entry("fcc", init_net.proc_net);
}


/****************************************************************************/
static void nf_conntrack_fcc_fini(void)
{
	int i;

	for (i = 0; i < ports_c; i++) {
		if (fcc[i].me == NULL)
			continue;

	fcc_cleanup_proc();

        /* unregister the FCC ports with ingress QoS classifier */
        iqos_rem_L4port( fcc[i].tuple.dst.protonum, 
                         fcc[i].tuple.src.u.tcp.port, IQOS_ENT_STAT );
		pr_debug("nf_ct_fcc: unregistering helper for port %d\n",
		       	 ports[i]);
		nf_conntrack_helper_unregister(&fcc[i]);
	}

	kfree(fcc_buffer);
}

static int __init nf_conntrack_fcc_init(void)
{
	int i, ret = 0;
	char *tmpname;

	fcc_buffer = kmalloc(4000, GFP_KERNEL);
	if (!fcc_buffer)
		return -ENOMEM;

	if ( protonum != IPPROTO_UDP && protonum != IPPROTO_TCP )
		protonum = IPPROTO_UDP;

	/* when ALG is inserted with port==0x0, check packet when protocol is matched. */
	if (ports_c == 0)
		ports[ports_c++] = 0x0;

	fcc_exp_policy.max_expected = max_outstanding;
	fcc_exp_policy.timeout	= 20;

	for (i = 0; i < ports_c; i++) {

		fcc[i].tuple.src.l3num = PF_INET;
		fcc[i].tuple.src.u.all = htons(ports[i]);
		fcc[i].tuple.dst.protonum = protonum;
		fcc[i].expect_policy = &fcc_exp_policy;
		fcc[i].expect_class_max = 1;
		fcc[i].me = THIS_MODULE;
		fcc[i].help = nf_fcc_help;
		tmpname = &fcc_names[i][0];
		if (ports[i] == FCC_PORT)
			sprintf(tmpname, "fcc");
		else
			sprintf(tmpname, "fcc-%d", ports[i]);
		fcc[i].name = tmpname;

		pr_notice("nf_ct_fcc: registering helper for port %d\n", ports[i]);
		ret = nf_conntrack_helper_register(&fcc[i]);
		if (ret) {

			pr_notice("nf_ct_fcc: failed to register helper for port %d\n", ports[i]);
			nf_conntrack_fcc_fini();
			return ret;
		}

	        /* register the FCC ports with ingress QoS classifier */
	        iqos_add_L4port( protonum, ports[i], IQOS_ENT_STAT, IQOS_PRIO_HIGH );
	}
	fcc_init_proc();

	return 0;
}

/****************************************************************************/
module_init(nf_conntrack_fcc_init);
module_exit(nf_conntrack_fcc_fini);

/****************************************************************************/
MODULE_AUTHOR("Seinlin");
MODULE_DESCRIPTION("FCC conntrack helper");
MODULE_LICENSE("GPL");
MODULE_ALIAS("nf_conntrack_fcc");
