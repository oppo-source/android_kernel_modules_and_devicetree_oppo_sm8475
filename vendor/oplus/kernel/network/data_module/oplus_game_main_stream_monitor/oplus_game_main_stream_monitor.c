/************************************************************************************
** File: - oplus_game_main_stream_monitor.c
** Copyright (C), 2008-2020, OPLUS Mobile Comm Corp., Ltd
**
** Description:
**     1. Add for Linkboost game ip address
**
** Version: 1.0
** Date :   2023-04-25
** Author:  YangZhaoJi@NETWROK.DATA
** TAG:     OPLUS_FEATURE_GAME_STREAM_MONITOR
**
** ---------------------Revision History: ---------------------
** <author>                           <data>      <version>    <desc>
** ---------------------------------------------------------------
************************************************************************************/
#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netlink.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/version.h>
#include <net/dst.h>
#include <net/genetlink.h>
#include <net/inet_connection_sock.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/tcp_states.h>
#include <net/udp.h>
#include <linux/netfilter_ipv6.h>

#include "../include/netlink_api.h"
#include "../include/comm_def.h"

#define DNS_DST_PORT 53
#define DETECT_PKT_THRED (32)
#define MAX_UID_CONTAIN_IP_COUNT (20)
static spinlock_t game_info_list_lock;
static struct hlist_head s_game_uid_info_node_head;

static void data_free(void *data)
{
	if (data) {
		kfree(data);
	}
}

typedef struct {
	struct hlist_node game_ip_node;
	u32 pkg_count;
	u32 ipv4_daddr;
} game_ip_count_node;

typedef struct {
	struct hlist_node game_uid_node;
	struct hlist_head child_list;
	u32 uid;
	u32 ip_count;
} game_uid_info_node;

static void notify_game_main_stream_ip_message(u32 gameuid, u32 gameip)
{
	char *buffer = NULL;
	int size = 0;
	Netlink__Proto__NotifyMessage msg = NETLINK__PROTO__NOTIFY_MESSAGE__INIT;
	Netlink__Proto__MessageHeader header = NETLINK__PROTO__MESSAGE_HEADER__INIT;
	Netlink__Proto__NotifyGameMainServerIp data = NETLINK__PROTO__NOTIFY_GAME_MAIN_SERVER_IP__INIT;
	header.requestid = 0;
	header.eventid = NETLINK__PROTO__NETLINK_MSG_ID__COMM_NETLINK_EVENT_NOTIFY_GAME_MAIN_IP;
	header.retcode = 0;
	data.battleip = gameip;
	data.gameuid = gameuid;
	msg.header = &header;
	msg.notify_data_case = NETLINK__PROTO__NOTIFY_MESSAGE__NOTIFY_DATA_NOTIFY_GAME_MAIN_SERVER_IP;
	msg.notifygamemainserverip = &data;
	size = netlink__proto__notify_message__get_packed_size(&msg);
	buffer = kmalloc(size, GFP_ATOMIC);
	if (!buffer) {
		printk("[GAME_MONITOR]malloc game buffer failed!");
		return;
	}
	size = netlink__proto__notify_message__pack(&msg, buffer);
	notify_netlink_event(buffer, size);
	if (buffer) {
		kfree(buffer);
	}
}

static void add_game_ipaddress(u32 ipaddress, struct hlist_head *gameiphead)
{
	game_ip_count_node *info_node = NULL;
	info_node = kmalloc(sizeof(game_ip_count_node), GFP_ATOMIC);
	if (!info_node) {
		printk("[GAME_MONITOR]add_game_monitor_uid kmallocfailed");
		return;
	}
	INIT_HLIST_NODE(&info_node->game_ip_node);
	info_node->pkg_count = 1;
	info_node->ipv4_daddr = ipaddress;
	hlist_add_head(&info_node->game_ip_node, gameiphead);
}

static void init_game_uid_list(u32 *list, size_t size)
{
	int i;
	for (i = 0;i < size;i++) {
		game_uid_info_node *uid_node = NULL;
		uid_node = kmalloc(sizeof(game_uid_info_node), GFP_ATOMIC);
		if (!uid_node) {
			printk("[GAME_MONITOR]add_game_monitor_uid kmallocfailed");
			return;
		}
		INIT_HLIST_NODE(&uid_node->game_uid_node);
		INIT_HLIST_HEAD(&uid_node->child_list);
		uid_node->uid = list[i];
		uid_node->ip_count = 0;
		hlist_add_head(&uid_node->game_uid_node, &s_game_uid_info_node_head);
	}
}

static int delete_game_uid(u32 uid)
{
	game_uid_info_node *uid_node = NULL;
	game_ip_count_node *ip_node = NULL;
	struct hlist_node *n = NULL;
	struct hlist_node *i = NULL;
	hlist_for_each_entry_safe(uid_node, n, &s_game_uid_info_node_head, game_uid_node) {
		if (uid_node->uid == uid) {
			hlist_for_each_entry_safe(ip_node, i, &uid_node->child_list, game_ip_node) {
				hlist_del_init(&ip_node->game_ip_node);
				if (ip_node) {
					kfree(ip_node);
				}
			}
			hlist_del_init(&uid_node->game_uid_node);
			if (uid_node) {
				kfree(uid_node);
			}
		}
	}
	return 0;
}

static int clear_game_all_uid(void)
{
	game_uid_info_node *uid_node = NULL;
	game_ip_count_node *ip_node = NULL;
	struct hlist_node *n = NULL;
	struct hlist_node *i = NULL;
	hlist_for_each_entry_safe(uid_node, n, &s_game_uid_info_node_head, game_uid_node) {
		hlist_for_each_entry_safe(ip_node, i, &uid_node->child_list, game_ip_node) {
			hlist_del_init(&ip_node->game_ip_node);
			if (ip_node) {
				kfree(ip_node);
			}
		}
		hlist_del_init(&uid_node->game_uid_node);
		if (uid_node) {
			kfree(uid_node);
		}
	}
	return 0;
}

static bool check_game_monitor_info(u32 uid, u32 ipaddress)
{
	game_uid_info_node *uid_node = NULL;
	game_ip_count_node *info_node = NULL;
	bool update_ipaddress = false;
	spin_lock_bh(&game_info_list_lock);
	hlist_for_each_entry(uid_node, &s_game_uid_info_node_head, game_uid_node) {
		if (uid_node->uid == uid) {
			hlist_for_each_entry(info_node, &uid_node->child_list, game_ip_node) {
				if ((info_node->ipv4_daddr == ipaddress) && (info_node->pkg_count >= DETECT_PKT_THRED)) {
					notify_game_main_stream_ip_message(uid, ipaddress);
					printk("[GAME_MONITOR]notify_game_main_stream_ip_message");
					spin_unlock_bh(&game_info_list_lock);
					return true;
				} else if ((info_node->ipv4_daddr == ipaddress) && (info_node->pkg_count < DETECT_PKT_THRED)) {
					info_node->pkg_count++;
					spin_unlock_bh(&game_info_list_lock);
					return false;
				}
			}
			if (uid_node->ip_count < MAX_UID_CONTAIN_IP_COUNT) {
				uid_node->ip_count++;
				update_ipaddress = true;
				break;
			}
		}
	}
	if (update_ipaddress) {
		add_game_ipaddress(ipaddress, &uid_node->child_list);
	}
	spin_unlock_bh(&game_info_list_lock);
	return false;
}

/*to check if tcp uid is the qr sk*/
static int oplus_get_skb_uid(struct sock *sk)
{
	kuid_t kuid;
	if (!sk || !sk_fullsock(sk))
		return overflowuid;
	kuid = sock_net_uid(sock_net(sk), sk);
	return from_kuid_munged(sock_net(sk)->user_ns, kuid);
}

static void detect_game_stream_info(struct sk_buff *skb)
{
	u32 uid = 0;
	u32 dstip;
	struct sock *sk = NULL;
	struct iphdr *iph = NULL;
	struct udphdr *udph = NULL;
	if (NULL == skb) {
		return;
	}
	sk = skb_to_full_sk(skb);
	if (NULL == sk || NULL == sk->sk_socket) {
		return;
	}
	uid = oplus_get_skb_uid(sk);
	if (uid == 0) {
		return;
	}
	iph = ip_hdr(skb);
	if (NULL == iph) {
		return;
	}
	if (iph->protocol != IPPROTO_UDP) {
		return;
	}
	udph = udp_hdr(skb);
	if ((!udph) || (udph->dest == htons(DNS_DST_PORT))) {
		return;
	}
	dstip = (u32)ntohl(iph->daddr);
	if (check_game_monitor_info(uid, dstip)) {
		printk("[GAME_MONITOR]delete_game_uid");
		delete_game_uid(uid);
	}
}

static unsigned int game_main_stream_nf_output_hook_func(void *priv,
		struct sk_buff *skb, const struct nf_hook_state *state)
{
	int ret = NF_ACCEPT;
	detect_game_stream_info(skb);
	return ret;
}

static struct nf_hook_ops game_main_stream_nf_hook_ops[] __read_mostly = {
	{
		.hook		= game_main_stream_nf_output_hook_func,
		.pf		    = NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP_PRI_CONNTRACK + 2,
	}
};

static int game_uid_record(u32 eventid, Netlink__Proto__RequestMessage *requestMsg, char **rsp_data, u32 *rsp_len)
{
	if ((requestMsg->request_data_case != NETLINK__PROTO__REQUEST_MESSAGE__REQUEST_DATA_REQUEST_SET_GAME_MAIN_STREAM_UID)
		|| (!requestMsg->requestsetgamemainstreamuid)) {
		return COMM_NETLINK_ERR_PARAM;
	}
	spin_lock_bh(&game_info_list_lock);
	clear_game_all_uid();
	init_game_uid_list(requestMsg->requestsetgamemainstreamuid->gameuid, requestMsg->requestsetgamemainstreamuid->n_gameuid);
	spin_unlock_bh(&game_info_list_lock);
	do {
		size_t len = 0, pack_len = 0;
		char *buf = NULL;
		NETLINK_RSP_DATA_DECLARE(rsp_name, requestMsg->header->requestid, requestMsg->header->eventid, COMM_NETLINK_SUCC);
		len = netlink__proto__response_message__get_packed_size(&rsp_name);
		buf = kmalloc(len, GFP_ATOMIC);
		if (!buf) {
			printk("[GAME_MONITOR]game_uid_record malloc size %lu failed", len);
			return COMM_NETLINK_ERR_MEMORY;
		}
		pack_len = netlink__proto__response_message__pack(&rsp_name, buf);
		printk("[GAME_MONITOR]game_uid_recordpack len %lu  buf len %lu", pack_len, len);
		*rsp_data = buf;
		*rsp_len = len;
	} while (0);
	return COMM_NETLINK_SUCC;
}

int game_main_stream_monitor_init(void)
{
	int ret = 0;
	INIT_HLIST_HEAD(&s_game_uid_info_node_head);
	spin_lock_init(&game_info_list_lock);
	ret = nf_register_net_hooks(&init_net, game_main_stream_nf_hook_ops, ARRAY_SIZE(game_main_stream_nf_hook_ops));
	if (ret) {
		printk("[GAME_MONITOR]nf_register_net_hooks failed ");
	}
	ret = register_netlink_request(COMM_NETLINK_EVENT_SET_GAME_UID, game_uid_record, data_free);
	if (ret) {
		nf_unregister_net_hooks(&init_net, game_main_stream_nf_hook_ops, ARRAY_SIZE(game_main_stream_nf_hook_ops));
		printk("[GAME_MONITOR]register cmd COMM_NETLINK_EVENT_SET_GAME_UID failed ");
	}
	return ret;
}

void game_main_stream_monitor_fint(void)
{
	nf_unregister_net_hooks(&init_net, game_main_stream_nf_hook_ops, ARRAY_SIZE(game_main_stream_nf_hook_ops));
	unregister_netlink_request(COMM_NETLINK_EVENT_SET_GAME_UID);
	printk("[GAME_MONITOR]game_main_stream_monitor_exit ");
	return;
}
