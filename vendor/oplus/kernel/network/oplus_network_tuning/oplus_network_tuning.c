#include <linux/types.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <net/dst.h>
#include <linux/file.h>
#include <net/tcp_states.h>
#include <linux/netlink.h>
#include <net/genetlink.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <net/inet_connection_sock.h>
#include <linux/spinlock.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include "oplus_kernel_common/oplus_kernel_common.h"
#include "oplus_tcp_syn/oplus_tcp_syn.h"
#include "oplus_tcp_congest_control/oplus_tcp_congest_control.h"
#include "oplus_dev_check/oplus_dev_check.h"

#define OPLUS_NETWORK_TUNING_FAMILY_NAME "kernel_tuning"
#define OPLUS_NETWORK_TUNING_FAMILY_VERSION	1
#define OPLUS_NETWORK_TUNING_MSG_MAX (__OPLUS_TUNING_MSG_MAX - 1)

static u32 s_oplus_network_tuning_user_pid = 0;

enum network_tuning_cmd_type_et
{
	OPLUS_NETWORK_TUNING_CMD_UNSPEC,
	OPLUS_NETWORK_TUNING_CMD_CTRL,
	__OPLUS_NETWORK_TUNING_CMD_MAX,
};

static int oplus_network_tuning_netlink_rcv_msg(struct sk_buff *skb, struct genl_info *info);

static inline int skb_v4_check(struct sk_buff *skb)
{
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct net_device *dev;

	iph = ip_hdr(skb);
	tcph = tcp_hdr(skb);
	if (skb->protocol != htons(ETH_P_IP) || (!iph)) {
		return OPLUS_FALSE;
	}

	if (iph->protocol != IPPROTO_TCP || !tcph) {
		return OPLUS_FALSE;
	}

	dev = skb->dev;
	if (!dev) {
		return OPLUS_FALSE;
	}

	return OPLUS_TRUE;
}

static inline int skb_v6_check(struct sk_buff *skb)
{
	struct tcphdr *tcph = NULL;
	struct ipv6hdr *ipv6h = NULL;
	struct net_device *dev;

	ipv6h = ipv6_hdr(skb);
	tcph = tcp_hdr(skb);
	if (skb->protocol != htons(ETH_P_IPV6) || (!ipv6h)) {
		return OPLUS_FALSE;
	}

	if ((ipv6h->nexthdr != NEXTHDR_TCP) || (!tcph)) {
		return OPLUS_FALSE;
	}

	dev = skb->dev;
	if (!dev) {
		return OPLUS_FALSE;
	}

	return OPLUS_TRUE;
}

unsigned int oplus_network_tuning_post_routing_hook_v4(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	if (skb_v4_check(skb) == OPLUS_FALSE) {
		return NF_ACCEPT;
	}

	tcp_syn_hook(priv, skb, state);
	tcp_congest_control_post_routing_hook(priv, skb, state);

    return NF_ACCEPT;
}

unsigned int oplus_network_tuning_report_hook_v4(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	if (!skb_v4_check(skb)) {
		return NF_ACCEPT;
	}
	tcp_syn_report(priv, skb, state);
	return NF_ACCEPT;
}

struct nf_hook_ops network_tuning_netfilter_ops[] __read_mostly = {
	{
		.hook = oplus_network_tuning_post_routing_hook_v4,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_FILTER + 1,
	},
	{
		.hook = oplus_network_tuning_report_hook_v4,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FILTER + 1,
	},
};

static const struct genl_ops oplus_network_tuning_genl_ops[] =
{
	{
		.cmd = OPLUS_NETWORK_TUNING_CMD_CTRL,
		.flags = 0,
		.doit = oplus_network_tuning_netlink_rcv_msg,
		.dumpit = NULL,
	},
};

static struct genl_family oplus_network_tuning_genl_family =
{
	.id = 0,
	.hdrsize = 0,
	.name = OPLUS_NETWORK_TUNING_FAMILY_NAME,
	.version = OPLUS_NETWORK_TUNING_FAMILY_VERSION,
	.maxattr = OPLUS_NETWORK_TUNING_MSG_MAX,
	.ops = oplus_network_tuning_genl_ops,
	.n_ops = ARRAY_SIZE(oplus_network_tuning_genl_ops),
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	.resv_start_op = OPLUS_NETWORK_TUNING_CMD_CTRL + 1,
#endif
};



static inline int genl_msg_prepare_usr_msg(u8 cmd, size_t size, pid_t pid, struct sk_buff **skbp)
{
	struct sk_buff *skb;
	/* create a new netlink msg */
	skb = genlmsg_new(size, GFP_ATOMIC);
	if (skb == NULL) {
		return -ENOMEM;
	}

	/* Add a new netlink message to an skb */
	genlmsg_put(skb, pid, 0, &oplus_network_tuning_genl_family, 0, cmd);
	*skbp = skb;
	return 0;
}

static inline int genl_msg_mk_usr_msg(struct sk_buff *skb, int type, void *data, int len)
{
	/* add a netlink attribute to a socket buffer */
	return nla_put(skb, type, len, data);
}

static int oplus_network_tuning_netlink_rcv_msg(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	struct nlmsghdr *nlhdr;
	struct genlmsghdr *genlhdr;
	struct nlattr *nla;

	nlhdr = nlmsg_hdr(skb);
	genlhdr = nlmsg_data(nlhdr);
	nla = genlmsg_data(genlhdr);

	s_oplus_network_tuning_user_pid = nlhdr->nlmsg_pid;
	if (ENABLE_DEBUG) {
		logt("set s_oplus_network_tuning_user_pid=%u.\n", s_oplus_network_tuning_user_pid);
	}

	/* to do: may need to some head check here*/
	if (ENABLE_DEBUG) {
		logt("oplus_network_tuning_netlink_rcv_msg type=%u.\n", nla->nla_type);
	}
	switch (nla->nla_type) {
	case OPLUS_TUNING_MSG_TCPSYN_ENABLE:
		oplus_tuning_tcpsyn_enable(nla);
		break;
	case OPLUS_TUNING_MSG_FOREGROUND_ANDROID_UID:
		oplus_tuning_tcpsyn_set_foreground_uid(nla);
		break;
	case OPLUS_TUNING_MSG_REQUEST_TCPSYN_REPORT:
		oplus_tuning_tcpsyn_request_report(nla);
		break;
	case OPLUS_TUNING_MSG_TCP_CONTROL_ENABLE:
		oplus_tcp_congest_control_enable(nla);
		break;
	case OPLUS_TUNING_MSG_SET_TCP_BBR_UID:
		oplus_tcp_congest_control_set_bbr_uid(nla);
		break;
	case OPLUS_TUNING_MSG_REQUEST_TCP_BBR_INFO:
		oplus_tcp_congest_control_request_report(nla);
		break;
	case OPLUS_TUNING_MSG_SET_TCP_BBR_STAT_UID:
		oplus_tcp_congest_control_set_bbr_stat_uid(nla);
		break;
	default:
		return -EINVAL;
	}

	return ret;
}

/* send to user space */
int oplus_network_tuning_send_netlink_msg(int msg_type, char *payload, int payload_len)
{
	int ret = 0;
	void * head;
	struct sk_buff *skbuff;
	size_t size;

	if (!s_oplus_network_tuning_user_pid) {
		logt("oplus_network_tuning_send_netlink_msg, s_oplus_network_tuning_user_pid=0\n");
		return -1;
	}

	/* allocate new buffer cache */
	size = nla_total_size(payload_len);
	ret = genl_msg_prepare_usr_msg(OPLUS_NETWORK_TUNING_CMD_CTRL, size, s_oplus_network_tuning_user_pid, &skbuff);
	if (ret) {
		return ret;
	}

	ret = genl_msg_mk_usr_msg(skbuff, msg_type, payload, payload_len);
	if (ret) {
		kfree_skb(skbuff);
		return ret;
	}

	head = genlmsg_data(nlmsg_data(nlmsg_hdr(skbuff)));
	genlmsg_end(skbuff, head);

	/* send data */
	ret = genlmsg_unicast(&init_net, skbuff, s_oplus_network_tuning_user_pid);
	if(ret < 0) {
		logt("oplus_tcpsyn_send_netlink_msg error, ret = %d\n", ret);
		return -1;
	}

	return 0;
}

static int oplus_network_tuning_netlink_init(void)
{
	int ret;
	ret = genl_register_family(&oplus_network_tuning_genl_family);
	if (ret) {
		logt("genl_register_family:%s failed,ret = %d\n", OPLUS_NETWORK_TUNING_FAMILY_NAME, ret);
		return ret;
	} else {
		logt("genl_register_family complete, id = %d!\n", oplus_network_tuning_genl_family.id);
	}

    return 0;
}

static void oplus_network_tuning_netlink_exit(void)
{
	genl_unregister_family(&oplus_network_tuning_genl_family);
}


static int __init oplus_kernel_tuning_init(void)
{
	int ret;
	ret = oplus_tuning_tcpsyn_init();
	if(ret < 0) {
		logt("oplus_tuning_tcpsyn_init failed, ret =% d\n",  ret);
		return -1;
	}
	ret = oplus_network_tuning_netlink_init();
	if (ret < 0) {
		logt("init module failed to init netlink, ret =% d\n",  ret);
		oplus_tuning_tcpsyn_fini();
		return ret;
	}

	logt("init module init netlink successfully.\n");

	ret = nf_register_net_hooks(&init_net, network_tuning_netfilter_ops, ARRAY_SIZE(network_tuning_netfilter_ops));
	if (ret)
	{
		nf_unregister_net_hooks(&init_net, network_tuning_netfilter_ops, ARRAY_SIZE(network_tuning_netfilter_ops));
		logt("nf_register_net_hooks failed! return %d", ret);
		return ret;
	}

	oplus_tcp_congest_control_init();
	oplus_dev_check_init();

	return ret;
}

static void __exit oplus_kernel_tuning_fini(void)
{
	oplus_tuning_tcpsyn_fini();
	nf_unregister_net_hooks(&init_net, network_tuning_netfilter_ops, ARRAY_SIZE(network_tuning_netfilter_ops));
	oplus_network_tuning_netlink_exit();
	oplus_tcp_congest_control_fini();
	oplus_dev_check_fini();
}

module_init(oplus_kernel_tuning_init);
module_exit(oplus_kernel_tuning_fini);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("oplus_network_tuning");
