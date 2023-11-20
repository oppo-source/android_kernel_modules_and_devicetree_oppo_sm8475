#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <net/dst.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include "oplus_dev_check.h"

unsigned int oplus_network_skb_dev_check(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct net_device *dev = skb_dst(skb)->dev;

	if ((dev) && (skb->dev != dev)) {
		if (skb->dev) {
			printk("skb->dev update, old_dev=%s, new_dev=%s\n", skb->dev->name, dev->name);
		} else {
			printk("skb->dev update, old_dev=null, new_dev=%s\n", dev->name);
		}
		skb->dev = dev;
	}

	return NF_ACCEPT;
}

struct nf_hook_ops oplus_dev_check_netfilter_ops[] __read_mostly =
{
	{
		.hook = oplus_network_skb_dev_check,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
	{
		.hook = oplus_network_skb_dev_check,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
};

int oplus_dev_check_init(void)
{
	int ret;
	ret = nf_register_net_hooks(&init_net, oplus_dev_check_netfilter_ops, ARRAY_SIZE(oplus_dev_check_netfilter_ops));
	printk("register oplus_dev_check_netfilter_ops: ret = %d\n", ret);
	return ret;
}

void oplus_dev_check_fini(void)
{
	nf_unregister_net_hooks(&init_net, oplus_dev_check_netfilter_ops, ARRAY_SIZE(oplus_dev_check_netfilter_ops));
}
