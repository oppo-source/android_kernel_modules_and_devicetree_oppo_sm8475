/***********************************************************
** Copyright (C), 2008-2022, oplus Mobile Comm Corp., Ltd.
** File: dpi_core.c
** Description: Add dpi core
**
** Version: 1.0
** Date : 2022/6/24
** Author: ShiQianhua
**
** ------------------ Revision History:------------------------
** <author> <data> <version > <desc>
** shiqianhua 2022/6/24 1.0 build this module
****************************************************************/
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
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <net/dst.h>
#include <net/genetlink.h>
#include <net/inet_connection_sock.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/tcp_states.h>
#include <net/udp.h>
#include <net/addrconf.h>
#include <linux/netfilter_ipv6.h>
#include <linux/timekeeping.h>
#include <linux/crc64.h>
#include <linux/crc32.h>
#include <linux/sock_diag.h>


#include "../include/dpi_api.h"
#include "../include/comm_def.h"
#include "../include/netlink_api.h"
#include "../proto-src/netlink_msg.pb-c.h"
#include "dpi_core.h"

#define LOG_TAG "oplus_dpi"

static int s_debug = 0;

#define logt(fmt, args...) LOG(LOG_TAG, fmt, ##args)
#define logi(fmt, args...) do { \
	if (s_debug) { \
		LOG(LOG_TAG, fmt, ##args); \
	} \
} while (0)

static spinlock_t s_dpi_lock;
static spinlock_t s_match_lock;
static spinlock_t s_record_lock;

static struct hlist_head s_notify_head;
static struct hlist_head s_match_app_head;
static struct hlist_head s_match_app_result_head;
static struct hlist_head s_match_uid_result_head;
static struct hlist_head s_dpi_record_result_head;

DEFINE_HASHTABLE(s_match_socket_map, (DPI_HASH_BIT + 1));

static u32 s_match_app_count = 0;
static u32 s_notify_count = 0;

static u32 s_dpi_result_count[DPI_LEVEL_TYPE_MAX] = {0, 0, 0, 0, 0};
static u32 s_match_socket_count = 0;
static u32 s_dpi_record_count = 0;


static u64 s_speed_calc_interval = DEFAULT_SPEED_CALC_INTVL;
static u64 s_speed_expire = DEFAULT_SPEED_EXPIRE;
static u64 s_dpi_timeout = DEFAULT_DPI_TIMEOUT;

static char *s_type_str[DPI_LEVEL_TYPE_MAX] = {
	"unspec",
	"uid",
	"app",
	"func",
	"stream"
};

static struct timer_list s_check_timeout_timer;
static int s_match_all_uid = 0;

extern u32 s_tmgp_sgame_uid;

typedef struct {
	struct hlist_node node;
	u64 dpi_id;
	dpi_notify_fun fun;
} dpi_notify_node;

typedef struct {
	struct hlist_node node;
	u32 uid;
	dpi_match_fun fun;
} dpi_app_config;

static u64 get_tuple_key(dpi_tuple_t *tuple)
{
	return (u64)crc32_be(0, (unsigned char *)tuple, sizeof(dpi_tuple_t));
}

int dpi_register_result_notify(u64 dpi_id, dpi_notify_fun fun)
{
	dpi_notify_node *pos = NULL;

	spin_lock_bh(&s_dpi_lock);
	hlist_for_each_entry(pos, &s_notify_head, node) {
		if ((pos->dpi_id == dpi_id) && (pos->fun == fun)) {
			spin_unlock_bh(&s_dpi_lock);
			logt("already set!");
			return 0;
		}
	}
	pos = kmalloc(sizeof(dpi_notify_node), GFP_ATOMIC);
	if (!pos) {
		spin_unlock_bh(&s_dpi_lock);
		logt("malloc dpi_notify_node failed!");
		return -1;
	}
	INIT_HLIST_NODE(&pos->node);
	pos->dpi_id = dpi_id;
	pos->fun = fun;
	hlist_add_head(&pos->node, &s_notify_head);
	s_notify_count++;
	spin_unlock_bh(&s_dpi_lock);

	return 0;
}

int dpi_unregister_result_notify(u64 dpi_id, dpi_notify_fun fun)
{
	dpi_notify_node *pos = NULL;
	struct hlist_node *n = NULL;

	spin_lock_bh(&s_dpi_lock);
	hlist_for_each_entry_safe(pos, n, &s_notify_head, node) {
		if ((pos->dpi_id == dpi_id) && (pos->fun == fun)) {
			hlist_del_init(&pos->node);
			kfree(pos);
			s_notify_count--;
			break;
		}
	}
	spin_unlock_bh(&s_dpi_lock);
	return 0;
}

int dpi_register_app_match(u32 uid, dpi_match_fun fun)
{
	dpi_app_config *pos = NULL;

	spin_lock_bh(&s_match_lock);
	hlist_for_each_entry(pos, &s_match_app_head, node) {
		if (pos->uid == uid) {
			spin_unlock_bh(&s_match_lock);
			logt("already set!");
			return 0;
		}
	}
	pos = kmalloc(sizeof(dpi_app_config), GFP_ATOMIC);
	if(!pos) {
		logt("malloc dpi_app_config failed!");
		spin_unlock_bh(&s_match_lock);
		return -1;
	}
	INIT_HLIST_NODE(&pos->node);
	pos->uid = uid;
	pos->fun = fun;
	hlist_add_head(&pos->node, &s_match_app_head);
	s_match_app_count++;
	spin_unlock_bh(&s_match_lock);

	return 0;
}

int dpi_unregister_app_match(u32 uid)
{
	dpi_app_config *pos = NULL;
	struct hlist_node *n = NULL;

	spin_lock_bh(&s_match_lock);
	hlist_for_each_entry_safe(pos, n, &s_match_app_head, node) {
		if (pos->uid == uid) {
			hlist_del_init(&pos->node);
			kfree(pos);
			s_match_app_count--;
			break;
		}
	}
	spin_unlock_bh(&s_match_lock);
	return 0;
}

static dpi_match_fun get_match_fun_by_uid(u32 uid)
{
	dpi_app_config *pos = NULL;
	dpi_match_fun fun = NULL;

	spin_lock_bh(&s_match_lock);
	hlist_for_each_entry(pos, &s_match_app_head, node) {
		if (pos->uid == uid) {
			fun = pos->fun;
			break;
		}
	}
	spin_unlock_bh(&s_match_lock);
	return fun;
}

static void dpi_init_hash_stats(dpi_hash_stats_t *hash_stats)
{
	memset(hash_stats, 0, sizeof(dpi_hash_stats_t));
	INIT_HLIST_NODE(&hash_stats->total_stats.node);
	hash_init(hash_stats->stats_map);
}

static void dpi_destroy_hash_stats(dpi_hash_stats_t *hash_stats)
{
	int i = 0;
	dpi_stats_t *pos = NULL;
	struct hlist_node *next = NULL;

	hash_for_each_safe(hash_stats->stats_map, i, next, pos, node) {
		hash_stats->stats_count--;
		hash_del(&pos->node);
		kfree(pos);
	}
}

static void dpi_update_speed_dir(stats_dir_t *dir_stats, int len, u64 cur_time)
{
	dir_stats->bytes += len;
	dir_stats->packets += 1;
	dir_stats->byte_uptime = cur_time;

	if ((cur_time - dir_stats->speed_uptime) > (s_speed_calc_interval * 1000000)) {
		dir_stats->speed = (dir_stats->bytes - dir_stats->last_bytes) * 8 * NS_PER_SEC / (cur_time - dir_stats->speed_uptime);
		dir_stats->last_bytes = dir_stats->bytes;
		dir_stats->speed_uptime = cur_time;
	}
}

static void dpi_update_speed(struct sk_buff *skb, int dir, int if_idx, dpi_hash_stats_t *hash_stats, u64 cur_time)
{
	stats_dir_t *dir_stats = NULL;
	dpi_stats_t *pos = NULL, *if_stats;

	dir_stats = dir ? &hash_stats->total_stats.tx_stats : &hash_stats->total_stats.rx_stats;

	dpi_update_speed_dir(dir_stats, skb->len, cur_time);

	hash_for_each_possible(hash_stats->stats_map, pos, node, if_idx) {
		if (pos->if_idx == if_idx) {
			dir_stats = dir ? &pos->tx_stats : &pos->rx_stats;
			dpi_update_speed_dir(dir_stats, skb->len, cur_time);
			return;
		}
	}
	if_stats = kmalloc(sizeof(dpi_stats_t), GFP_ATOMIC);
	if (if_stats == NULL) {
		logt("malloc if_stats failed!");
		return;
	}
	memset(if_stats, 0, sizeof(dpi_stats_t));
	if_stats->if_idx = if_idx;
	INIT_HLIST_NODE(&if_stats->node);
	hash_add(hash_stats->stats_map, &if_stats->node, if_idx);
	hash_stats->stats_count++;

	dir_stats = dir ? &if_stats->tx_stats : &if_stats->rx_stats;
	dpi_update_speed_dir(dir_stats, skb->len, cur_time);
}

static dpi_socket_node *get_dpi_socket_node_by_tuple(dpi_tuple_t *tuple)
{
	dpi_socket_node *data = NULL;
	dpi_socket_node *pos = NULL;

	hash_for_each_possible(s_match_socket_map, pos, list_node, get_tuple_key(tuple)) {
		if (memcmp(&pos->data.tuple, tuple, sizeof(dpi_tuple_t)) == 0) {
			data = pos;
			break;
		}
	}

	return data;
}

static dpi_socket_node *dpi_create_match_data(dpi_tuple_t *tuple)
{
	dpi_socket_node *node = NULL;

	node = kmalloc(sizeof(dpi_socket_node), GFP_ATOMIC);
	if (!node) {
		logt("malloc dpi_socket_node failed!");
		return NULL;
	}
	memset(node, 0, sizeof(dpi_socket_node));
	INIT_HLIST_NODE(&node->uid_tree_node);
	INIT_HLIST_NODE(&node->stream_tree_node);
	INIT_HLIST_NODE(&node->list_node);

	hash_add(s_match_socket_map, &node->list_node, get_tuple_key(tuple));
	s_match_socket_count++;
	memcpy(&node->data.tuple, tuple, sizeof(dpi_tuple_t));

	return node;
}

static dpi_result_node *dpi_find_add_result_node(
	u32 uid, u64 dpi_id, enum dpi_level_type_e type, struct hlist_head *header, dpi_result_node *parent, u64 cur_time)
{
	dpi_result_node * node = NULL;
	dpi_result_node * pos = NULL;

	hlist_for_each_entry(pos, header, node) {
		if(pos->dpi_id == dpi_id) {
			node = pos;
			break;
		}
	}
	if (!node) {
		node = kmalloc(sizeof(dpi_result_node), GFP_ATOMIC);
		if (!node) {
			logt("malloc dpi_result_node failed!");
			return NULL;
		}
		memset(node, 0, sizeof(dpi_result_node));
		dpi_init_hash_stats(&node->hash_stats);
		node->uid = uid;
		node->level_type = type;
		node->dpi_id = dpi_id;
		node->update_time = cur_time;
		node->start_time = cur_time;
		INIT_HLIST_HEAD(&node->child_list);
		INIT_HLIST_NODE(&node->node);
		hlist_add_head(&node->node, header);
		node->parent = parent;
		if (parent) {
			parent->child_count++;
		}
		s_dpi_result_count[type]++;
		logi("add app type[%s] dpi[%llx]", s_type_str[type], dpi_id);
	}

	return node;
}

static int dpi_match_data_add_tree(dpi_socket_node *socket_node, u64 cur_time)
{
	u64 app_result = socket_node->data.dpi_result & DPI_ID_APP_MASK;
	u64 fun_result = socket_node->data.dpi_result & DPI_ID_FUNC_MASK;
	u64 stream_result = socket_node->data.dpi_result & DPI_ID_STREAM_MASK;
	dpi_result_node *app_node = NULL;
	dpi_result_node *fun_node = NULL;
	dpi_result_node *stream_node = NULL;

	app_node = dpi_find_add_result_node(socket_node->data.uid, app_result, DPI_LEVEL_TYPE_APP, &s_match_app_result_head, NULL, cur_time);
	if (!app_node) {
		return -1;
	}
	fun_node = dpi_find_add_result_node(socket_node->data.uid, fun_result, DPI_LEVEL_TYPE_FUNCTION, &app_node->child_list, app_node, cur_time);
	if (!fun_node) {
		return -1;
	}
	stream_node = dpi_find_add_result_node(socket_node->data.uid, stream_result, DPI_LEVEL_TYPE_STREAM, &fun_node->child_list, fun_node, cur_time);
	if (!stream_node) {
		return -1;
	}
	hlist_add_head(&socket_node->stream_tree_node, &stream_node->child_list);
	socket_node->stream_result_node = stream_node;
	stream_node->child_count++;
	logi("add dpi result [%llx] for uid [%u]", stream_result, socket_node->data.uid);
	return 0;
}

static uid_t get_skb_uid(struct sk_buff *skb)
{
	struct sock *sk = sk_to_full_sk(skb->sk);
	kuid_t kuid;

	if (!sk || !sk_fullsock(sk) || NULL == sk->sk_socket) {
		return -1;
	}
	kuid = sock_net_uid(sock_net(sk), sk);
	return from_kuid_munged(sock_net(sk)->user_ns, kuid);
}

/* dir == 1 up  == 0 down */
static int get_match_tuple_by_skb(struct sk_buff *skb, int dir, int in_dev, dpi_tuple_t *tuple)
{
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	struct udphdr *udph = NULL;
	struct tcphdr *tcph = NULL;
	u8 *end = skb_tail_pointer(skb);
	int iph_len = 0;

	if (skb->protocol == htons(ETH_P_IP)) {
		iph = ip_hdr(skb);
		if (iph == NULL) {
			return -1;
		}
		if ((iph->protocol != IPPROTO_UDP) && (iph->protocol != IPPROTO_TCP)) {
			return -1;
		}
		tuple->protocol = iph->protocol;
		if (dir) {
			tuple->local_ip = ntohl(iph->saddr);
			tuple->peer_ip = ntohl(iph->daddr);
		} else {
			tuple->local_ip = ntohl(iph->daddr);
			tuple->peer_ip = ntohl(iph->saddr);
		}
		iph_len = (iph->ihl & 0x0F) * 4;
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		ip6h = ipv6_hdr(skb);
		if (ip6h == NULL) {
			return -1;
		}
		if ((ip6h->nexthdr != IPPROTO_UDP) && (ip6h->nexthdr != IPPROTO_TCP)) {
			return -1;
		}
		tuple->protocol = ip6h->nexthdr;
		tuple->is_ipv6 = 1;
		if (dir) {
			memcpy(tuple->local_ipv6, ip6h->saddr.s6_addr, sizeof(tuple->local_ipv6));
			memcpy(tuple->peer_ipv6, ip6h->daddr.s6_addr, sizeof(tuple->peer_ipv6));
		} else {
			memcpy(tuple->peer_ipv6, ip6h->saddr.s6_addr, sizeof(tuple->local_ipv6));
			memcpy(tuple->local_ipv6, ip6h->daddr.s6_addr, sizeof(tuple->peer_ipv6));
		}
		iph_len = sizeof(struct ipv6hdr);
	} else {
		return -1;
	}

	if (tuple->protocol == IPPROTO_UDP) {
		if (in_dev) {
			if ((skb_network_header(skb) + iph_len + sizeof(struct udphdr)) > end) {
				return -1;
			}
			udph = (struct udphdr *)(skb_network_header(skb) + iph_len);
		} else {
			udph = udp_hdr(skb);
		}
		if (udph == NULL) {
			return -1;
		}
		if (dir) {
			tuple->local_port = ntohs(udph->source);
			tuple->peer_port = ntohs(udph->dest);
		} else {
			tuple->local_port = ntohs(udph->dest);
			tuple->peer_port = ntohs(udph->source);
		}
	} else if (tuple->protocol == IPPROTO_TCP) {
		if (in_dev) {
			if ((skb_network_header(skb) + iph_len + sizeof(struct tcphdr)) > end) {
				return -1;
			}
			tcph = (struct tcphdr *)(skb_network_header(skb) + iph_len);
		} else {
			tcph = tcp_hdr(skb);
		}
		if (tcph == NULL) {
			return -1;
		}
		if (dir) {
			tuple->local_port = ntohs(tcph->source);
			tuple->peer_port = ntohs(tcph->dest);
		} else {
			tuple->local_port = ntohs(tcph->dest);
			tuple->peer_port = ntohs(tcph->source);
		}
	}

	return 0;
}

static bool dpi_uid_valid(kuid_t kuid) {
	return uid_valid(kuid) && __kuid_val(kuid) >= 1000;
}

u64 get_skb_dpi_id(struct sk_buff *skb, int dir, int in_dev)
{
#ifdef CONFIG_ANDROID_VENDOR_OEM_DATA
	struct sock *sk = NULL;
#endif
	dpi_tuple_t tuple = {0};
	int ret = 0;
	dpi_socket_node *socket_node = NULL;
	uid_t uid = -1;
	kuid_t kuid;
	u64 result = 0;

	uid = get_skb_uid(skb);
	kuid.val = uid;
	if (dpi_uid_valid(kuid)) {
#ifdef CONFIG_ANDROID_VENDOR_OEM_DATA
		if (skb->sk) {
			sk = sk_to_full_sk(skb->sk);
			if (!sk || !sk_fullsock(sk)) {
				return 0;
			}
			if (sk->android_oem_data1 != 0) {
				return sk->android_oem_data1;
			}
		}
#endif
	}
	ret = get_match_tuple_by_skb(skb, dir, in_dev, &tuple);
	if (ret) {
		return 0;
	}

	spin_lock_bh(&s_dpi_lock);
	socket_node = get_dpi_socket_node_by_tuple(&tuple);
	if (socket_node != NULL) {
		result = socket_node->data.dpi_result;
	}
	spin_unlock_bh(&s_dpi_lock);
	return result;
}

static int dpi_update_stats(struct sk_buff *skb, int dir, dpi_socket_node *data, u64 cur_time)
{
	dpi_result_node *stream_node = NULL;
	dpi_result_node *uid_node = NULL;
	stats_dir_t *dir_stats = NULL;
	int if_idx = skb->dev->ifindex;

	data->data.update_time = cur_time;
	dir_stats = dir ? &data->stats.tx_stats : &data->stats.rx_stats;
	dpi_update_speed_dir(dir_stats, skb->len, cur_time);

	if(data->data.state == DPI_MATCH_STATE_COMPLETE) {
		stream_node = data->stream_result_node;
		while (stream_node) {
			stream_node->update_time = cur_time;
			dpi_update_speed(skb, dir, if_idx, &stream_node->hash_stats, cur_time);
			stream_node = stream_node->parent;
		}
	}
	uid_node = data->uid_result_node;
	while (uid_node) {
		uid_node->update_time = cur_time;
		dpi_update_speed(skb, dir, if_idx, &uid_node->hash_stats, cur_time);
		uid_node = uid_node->parent;
	}
	return 0;
}

static void dpi_notify_dpi_event(u64 dpi_id, int startStop)
{
	dpi_notify_node *pos = NULL;

	hlist_for_each_entry(pos, &s_notify_head, node) {
		if (pos->dpi_id == (dpi_id & DPI_ID_STREAM_MASK)) {
			pos->fun(dpi_id, startStop);
		}
	}
}

static void save_dpi_result(struct sk_buff *skb, dpi_socket_node *socket_node)
{
#ifdef CONFIG_ANDROID_VENDOR_OEM_DATA
	struct sock *sk = NULL;

	if (skb->sk) {
		sk = sk_to_full_sk(skb->sk);
		if (!sk || !sk_fullsock(sk)) {
			return;
		}
		if (sk->android_oem_data1 == 0) {
			sk->android_oem_data1 = socket_node->data.dpi_result & DPI_ID_STREAM_MASK;
		}
	}
#endif
}

static void calculate_ipv6_netmask(int prefix_len, struct in6_addr *netmask) {
	int i;
	for (i = 0; i < 16; i++) {
		if (prefix_len >= 8) {
			netmask->s6_addr[i] = 0xff;
			prefix_len -= 8;
		} else if (prefix_len > 0) {
			netmask->s6_addr[i] = ~(0xff >> prefix_len);
			prefix_len = 0;
		} else {
			netmask->s6_addr[i] = 0;
		}
	}
}

static int is_local_network_traffic(struct sk_buff *skb, int dir) {
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	struct in_device *in_dev = NULL;
	struct in_ifaddr *if_info = NULL;
	struct inet6_dev *inet6_dev = NULL;
	struct inet6_ifaddr *inet6_ifaddr = NULL;
	struct in6_addr local_ip6;
	struct in6_addr peer_ip6;
	struct in6_addr netmask_ipv6;
	u32 local_ipv4 = 0;
	u32 peer_ipv4 = 0;
	u32 netmask_ipv4 = 0;
	if (skb->protocol == htons(ETH_P_IP)) {
		rcu_read_lock();
		in_dev = __in_dev_get_rcu(skb ->dev);
		if (in_dev == NULL) {
			rcu_read_unlock();
			return 0;
		}
		iph = ip_hdr(skb);
		if (iph == NULL) {
				logt("IP header is null!");
				rcu_read_unlock();
				return 0;
		}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0))
		in_dev_for_each_ifa_rcu(if_info, in_dev) {
			netmask_ipv4 = ntohl(if_info->ifa_mask);
			if (dir) {
				local_ipv4 = ntohl(iph->saddr);
				peer_ipv4 = ntohl(iph->daddr);
			} else {
				local_ipv4 = ntohl(iph->daddr);
				peer_ipv4 = ntohl(iph->saddr);
			}
			if ((local_ipv4 & netmask_ipv4) == (peer_ipv4 & netmask_ipv4)) {
				logi("LAN traffic ipv4 package, do not count");
				rcu_read_unlock();
				return 1;
			}
		}
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0))
		if_info = in_dev->ifa_list;
		while (if_info) {
			netmask_ipv4 = ntohl(if_info->ifa_mask);
			if (dir) {
				local_ipv4 = ntohl(iph->saddr);
				peer_ipv4 = ntohl(iph->daddr);
			} else {
				local_ipv4 = ntohl(iph->daddr);
				peer_ipv4 = ntohl(iph->saddr);
			}
			if ((local_ipv4 & netmask_ipv4) == (peer_ipv4 & netmask_ipv4)) {
				logi("LAN traffic ipv4 package, do not count");
				rcu_read_unlock();
				return 1;
			}
			if_info = if_info->ifa_next;
		}
#endif
		rcu_read_unlock();
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		ip6h = ipv6_hdr(skb);
		if (ip6h == NULL) {
			logi("IPv6 header is null!");
			return 0;
		}
		rcu_read_lock();
		inet6_dev = __in6_dev_get_safely(skb ->dev);
		if (inet6_dev == NULL) {
			rcu_read_unlock();
			return 0;
		}
		read_lock_bh(&inet6_dev ->lock);
		list_for_each_entry(inet6_ifaddr, &inet6_dev->addr_list, if_list) {
			if (inet6_ifaddr->prefix_len == 0) {
				continue;
			}
			if (dir) {
				local_ip6 = ip6h->saddr;
				peer_ip6 = ip6h->daddr;
			} else {
				local_ip6 = ip6h->daddr;
				peer_ip6 = ip6h->saddr;
			}
			calculate_ipv6_netmask(inet6_ifaddr->prefix_len, &netmask_ipv6);

			if (((local_ip6.s6_addr32[0] & netmask_ipv6.s6_addr32[0]) == (peer_ip6.s6_addr32[0] & netmask_ipv6.s6_addr32[0])) &&
				((local_ip6.s6_addr32[1] & netmask_ipv6.s6_addr32[1]) == (peer_ip6.s6_addr32[1] & netmask_ipv6.s6_addr32[1])) &&
				((local_ip6.s6_addr32[2] & netmask_ipv6.s6_addr32[2]) == (peer_ip6.s6_addr32[2] & netmask_ipv6.s6_addr32[2])) &&
				((local_ip6.s6_addr32[3] & netmask_ipv6.s6_addr32[3]) == (peer_ip6.s6_addr32[3] & netmask_ipv6.s6_addr32[3]))) {
				logi("LAN traffic IPv6 package, do not count");
				read_unlock_bh(&inet6_dev ->lock);
				rcu_read_unlock();
				return 1;
			}
		}
		read_unlock_bh(&inet6_dev ->lock);
		rcu_read_unlock();
	}
	return 0;
}


static int dpi_handle_match_pre(struct sk_buff *skb, int dir, dpi_tuple_t *tuple, dpi_socket_node **node_out, uid_t *uid_out)
{
	int ret = 0;
	uid_t uid = -1;
	kuid_t kuid;
	dpi_socket_node *socket_node = NULL;

	ret = get_match_tuple_by_skb(skb, dir, 0, tuple);
	if (ret || tuple->peer_ip == LOCAL_HOST) {
		return ret;
	}
	if (skb->sk == NULL) {
		socket_node = get_dpi_socket_node_by_tuple(tuple);
		if(socket_node) {
			uid = socket_node->data.uid;
		}
	} else {
		uid = get_skb_uid(skb);
	}

	kuid.val = uid;
	if (!dpi_uid_valid(kuid)) {
		return -1;
	}

	*node_out = socket_node;
	*uid_out = uid;

	return 0;
}

static int dpi_handle_uid_match(struct sk_buff *skb, int dir, dpi_socket_node *socket_node, int uid, u64 cur_time)
{
	u64 uid_dpi = 0;
	dpi_result_node *uid_node = NULL;

	if (!s_match_all_uid || socket_node->data.uid == SYSTEM_UID) {
		return -1;
	}

	uid_dpi = socket_node->data.dpi_result & DPI_ID_UID_MASK;
	if (uid_dpi == 0) {
		uid_dpi = ((u64)uid << DPI_ID_UID_BIT_OFFSET);
		socket_node->data.dpi_result |= uid_dpi;
		if (socket_node->uid_result_node == NULL) {
			uid_node = dpi_find_add_result_node(socket_node->data.uid, uid_dpi, DPI_LEVEL_TYPE_UID, &s_match_uid_result_head, NULL, cur_time);
			if (!uid_node) {
				return -1;
			}
			hlist_add_head(&socket_node->uid_tree_node, &uid_node->child_list);
			socket_node->uid_result_node = uid_node;
			uid_node->child_count++;
			logi("add dpi result [%llx] for uid [%u]", uid_dpi, socket_node->data.uid);
		}
	}
	return 0;
}

static int dpi_handle_stream_match(struct sk_buff *skb, int dir, dpi_socket_node *socket_node, int uid, u64 cur_time)
{
#ifdef CONFIG_ANDROID_VENDOR_OEM_DATA
	struct sock *sk = NULL;
#endif
	dpi_match_fun match_fun = NULL;
	if (socket_node->data.state == DPI_MATCH_STATE_COMPLETE) {
		save_dpi_result(skb, socket_node);
		return 0;
	}
	match_fun = get_match_fun_by_uid(uid);
	if (!match_fun) {
		return -1;
	}
#ifdef CONFIG_ANDROID_VENDOR_OEM_DATA
	if (skb->sk) {
		sk = sk_to_full_sk(skb->sk);
		if (sk && sk_fullsock(sk) && (sk->android_oem_data1 != 0)) {
			socket_node->data.state = DPI_MATCH_STATE_COMPLETE;
			socket_node->data.dpi_result |= sk->android_oem_data1;
			dpi_match_data_add_tree(socket_node, cur_time);
			dpi_notify_dpi_event(socket_node->data.dpi_result, 1);
			return 0;
		}
	}
#endif

	match_fun(skb, dir, &socket_node->data);
	if (socket_node->data.state == DPI_MATCH_STATE_COMPLETE) {
		dpi_match_data_add_tree(socket_node, cur_time);
		dpi_notify_dpi_event(socket_node->data.dpi_result, 1);
		save_dpi_result(skb, socket_node);
	}
	return 0;
}

static int dpi_handle_match(struct sk_buff *skb, int dir, int v6)
{
	dpi_tuple_t tuple = {0};
	int ret = 0;
	uid_t uid = -1;
	u64 cur_time = 0;
	struct timespec64 time;
	dpi_socket_node *socket_node = NULL;

	if (skb->dev == NULL) {
		return -1;
	}
	/* filter LAN traffic */
	ret = is_local_network_traffic(skb, dir);
	if(ret) {
		return ret;
	}

	ktime_get_raw_ts64(&time);
	cur_time = time.tv_sec * NS_PER_SEC + time.tv_nsec;
	spin_lock_bh(&s_dpi_lock);
	ret = dpi_handle_match_pre(skb, dir, &tuple, &socket_node, &uid);
	if (ret) {
		spin_unlock_bh(&s_dpi_lock);
		return ret;
	}
	if (socket_node == NULL) {
		socket_node = get_dpi_socket_node_by_tuple(&tuple);
		if(socket_node == NULL) {
			socket_node = dpi_create_match_data(&tuple);
			if (socket_node == NULL) {
				spin_unlock_bh(&s_dpi_lock);
				return -1;
			}
			socket_node->data.if_idx = skb->dev->ifindex;
			socket_node->data.uid = uid;
			socket_node->data.state = DPI_MATCH_STATE_MATCHING;
		}
	}
	dpi_handle_stream_match(skb, dir, socket_node, uid, cur_time);
	dpi_handle_uid_match(skb, dir, socket_node, uid, cur_time);
	dpi_update_stats(skb, dir, socket_node, cur_time);
	spin_unlock_bh(&s_dpi_lock);

	return 0;
}

static void dpi_record_stream_data(dpi_result_node *result_node, u64 ending_time) {
	dpi_record_node *node = NULL;
	dpi_record_node *pose = NULL;

	if(result_node->level_type != DPI_LEVEL_TYPE_STREAM || (result_node->dpi_id & DPI_STREAM_MASK) == 0) {
		return;
	}
	spin_lock_bh(&s_record_lock);
	hlist_for_each_entry(pose, &s_dpi_record_result_head, list_node) {
		if (pose->dpi_result == result_node->dpi_id) {
			pose->duration += (ending_time - result_node->start_time)/NS_PER_SEC;
			pose->rx_traffic += (result_node->hash_stats.total_stats.rx_stats.bytes)/TRAFFIC_UNIT;
			pose->tx_traffic += (result_node->hash_stats.total_stats.tx_stats.bytes)/TRAFFIC_UNIT;
			pose->total_traffic += (result_node->hash_stats.total_stats.rx_stats.bytes + result_node->hash_stats.total_stats.tx_stats.bytes)/TRAFFIC_UNIT;
			node = pose;
			break;
		}
	}
	if(!node) {
		node = kmalloc(sizeof(dpi_record_node), GFP_ATOMIC);
		if(!node) {
			logt("malloc failed");
			spin_unlock_bh(&s_record_lock);
			return;
		}
		memset(node, 0, sizeof(dpi_record_node));
		INIT_HLIST_NODE(&node->list_node);
		node->dpi_result = result_node->dpi_id;
		node->duration = (ending_time - result_node->start_time)/NS_PER_SEC;
		node->rx_traffic = (result_node->hash_stats.total_stats.rx_stats.bytes)/TRAFFIC_UNIT;
		node->tx_traffic = (result_node->hash_stats.total_stats.tx_stats.bytes)/TRAFFIC_UNIT;
		node->total_traffic = (result_node->hash_stats.total_stats.rx_stats.bytes + result_node->hash_stats.total_stats.tx_stats.bytes)/TRAFFIC_UNIT;
		hlist_add_head(&node->list_node, &s_dpi_record_result_head);
		s_dpi_record_count++;
	}
	spin_unlock_bh(&s_record_lock);
	logi("record dpi data : dpi_result = %llx, duration = %llu, traffic = %llu", node->dpi_result, node->duration, node->total_traffic);
	return;
}

static void dpi_clear_result_node(dpi_result_node *result_node, u64 curr_time)
{
	if (result_node && hlist_empty(&result_node->child_list)) {
		hlist_del_init(&result_node->node);
		dpi_destroy_hash_stats(&result_node->hash_stats);
		if (result_node->parent) {
			logi("clear app type[%s] with dpi [%llx]", s_type_str[result_node->level_type], result_node->dpi_id);
			result_node->parent->child_count--;
			dpi_clear_result_node(result_node->parent, curr_time);
		}
		dpi_notify_dpi_event(result_node->dpi_id, 0);
		dpi_record_stream_data(result_node, curr_time);
		s_dpi_result_count[result_node->level_type]--;
		kfree(result_node);
	}
}

static void dpi_clear_sock_list(void)
{
	dpi_socket_node *pos = NULL;
	struct hlist_node *next = NULL;
	struct timespec64 time;
	u64 curr_time = 0;
	int i = 0;

	logi("dpi_clear_sock_list start dpi count[%u-%u][%u-%u-%u-%u-%u]", s_notify_count, s_match_app_count,
		s_dpi_result_count[DPI_LEVEL_TYPE_APP], s_dpi_result_count[DPI_LEVEL_TYPE_FUNCTION],
		s_dpi_result_count[DPI_LEVEL_TYPE_STREAM], s_dpi_result_count[DPI_LEVEL_TYPE_UID], s_match_socket_count);
	ktime_get_raw_ts64(&time);
	curr_time = time.tv_sec * NS_PER_SEC + time.tv_nsec;

	if (s_match_socket_count == 0) {
		return;
	}

	spin_lock_bh(&s_dpi_lock);

	hash_for_each_safe(s_match_socket_map, i, next, pos, list_node) {
		if ((curr_time - pos->data.update_time) > s_dpi_timeout * 1000000) {
			s_match_socket_count--;
			hlist_del_init(&pos->list_node);
			hlist_del_init(&pos->uid_tree_node);
			hlist_del_init(&pos->stream_tree_node);
			if (pos->stream_result_node) {
				pos->stream_result_node->child_count--;
				logi("clear dpi uid [%llx] for uid [%u]", pos->stream_result_node->dpi_id, pos->stream_result_node->uid);
				dpi_clear_result_node(pos->stream_result_node, curr_time);
			}
			if (pos->uid_result_node) {
				pos->uid_result_node->child_count--;
				logi("clear dpi uid [%llx] for uid [%u]", pos->uid_result_node->dpi_id, pos->uid_result_node->uid);
				dpi_clear_result_node(pos->uid_result_node, curr_time);
			}
			kfree(pos);
		}
	}

	spin_unlock_bh(&s_dpi_lock);
}


static void dpi_check_timeout_fun(struct timer_list *t)
{
	dpi_clear_sock_list();
	mod_timer(&s_check_timeout_timer, jiffies + s_dpi_timeout * HZ / 1000);
}


static unsigned int dpi_output_hook_v4(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	dpi_handle_match(skb, 1, 0);
	return NF_ACCEPT;
}

static unsigned int dpi_input_hook_v4(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	dpi_handle_match(skb, 0, 0);
	return NF_ACCEPT;
}

static unsigned int dpi_output_hook_v6(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	dpi_handle_match(skb, 1, 1);
	return NF_ACCEPT;
}


static unsigned int dpi_input_hook_v6(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	dpi_handle_match(skb, 0, 1);
	return NF_ACCEPT;
}


static struct nf_hook_ops dpi_netfilter_ops[] __read_mostly = {
	{
		.hook = dpi_output_hook_v4,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_FILTER - 1,
	},
	{
		.hook = dpi_input_hook_v4,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FILTER - 1,
	},
	{
		.hook = dpi_output_hook_v6,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_FILTER - 1,
	},
	{
		.hook = dpi_input_hook_v6,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FILTER - 1,
	},
};

static struct ctl_table_header *oplus_dpi_table_hdr = NULL;

static struct ctl_table oplus_dpi_sysctl_table[] = {
	{
		.procname = "debug",
		.data = &s_debug,
		.maxlen = sizeof(u32),
		.mode = 0644,
		.proc_handler = proc_dointvec,
	},
	{
		.procname = "speed_intvl",
		.data = &s_speed_calc_interval,
		.maxlen = sizeof(u32),
		.mode = 0644,
		.proc_handler = proc_dointvec,
	},
	{
		.procname = "speed_expire",
		.data = &s_speed_expire,
		.maxlen = sizeof(u32),
		.mode = 0644,
		.proc_handler = proc_dointvec,
	},
	{
		.procname = "dpi_timeout",
		.data = &s_dpi_timeout,
		.maxlen = sizeof(u32),
		.mode = 0644,
		.proc_handler = proc_dointvec,
	},
	{
		.procname = "uid_tmgp_sgame",
		.data = &s_tmgp_sgame_uid,
		.maxlen = sizeof(u32),
		.mode = 0644,
		.proc_handler = proc_dointvec,
	},
	{
		.procname = "s_notify_count",
		.data = &s_notify_count,
		.maxlen = sizeof(u32),
		.mode = 0644,
		.proc_handler = proc_dointvec,
	},
	{
		.procname = "s_match_app_count",
		.data = &s_match_app_count,
		.maxlen = sizeof(u32),
		.mode = 0644,
		.proc_handler = proc_dointvec,
	},
	{
		.procname = "dpi_app_result_count",
		.data = &s_dpi_result_count[DPI_LEVEL_TYPE_APP],
		.maxlen = sizeof(u32),
		.mode = 0644,
		.proc_handler = proc_dointvec,
	},
	{
		.procname = "dpi_func_result_count",
		.data = &s_dpi_result_count[DPI_LEVEL_TYPE_FUNCTION],
		.maxlen = sizeof(u32),
		.mode = 0644,
		.proc_handler = proc_dointvec,
	},
	{
		.procname = "dpi_stream_result_count",
		.data = &s_dpi_result_count[DPI_LEVEL_TYPE_STREAM],
		.maxlen = sizeof(u32),
		.mode = 0644,
		.proc_handler = proc_dointvec,
	},
	{
		.procname = "s_match_socket_count",
		.data = &s_match_socket_count,
		.maxlen = sizeof(u32),
		.mode = 0644,
		.proc_handler = proc_dointvec,
	},
	{
		.procname = "s_match_all_uid",
		.data = &s_match_all_uid,
		.maxlen = sizeof(u32),
		.mode = 0644,
		.proc_handler = proc_dointvec,
	},
	{}
};

static void data_free(void *data)
{
	if (data) {
		kfree(data);
	}
}


static int request_set_match_all_uid_eable(u32 eventid, Netlink__Proto__RequestMessage *requestMsg, char **rsp_data, u32 *rsp_len) {
	if ((requestMsg->request_data_case != NETLINK__PROTO__REQUEST_MESSAGE__REQUEST_DATA_REQUEST_SET_DPI_MATCH_ALL_UID_EABLE)
		|| (!requestMsg->requsetsetdpiuid)) {
		return COMM_NETLINK_ERR_PARAM;
	}
	s_match_all_uid = requestMsg->requestsetdpimatchalluideable->enable;
	do {
		size_t len = 0, pack_len = 0;
		char *buf = NULL;
		NETLINK_RSP_DATA_DECLARE(rsp_name, requestMsg->header->requestid, requestMsg->header->eventid, COMM_NETLINK_SUCC);
		len = netlink__proto__response_message__get_packed_size(&rsp_name);
		buf = kmalloc(len, GFP_ATOMIC);
		if (!buf) {
			logt("malloc size %lu failed", len);
			return COMM_NETLINK_ERR_MEMORY;
		}
		pack_len = netlink__proto__response_message__pack(&rsp_name, buf);
		logi("request_set_match_all_uid_eable pack len %lu  buf len %lu", pack_len, len);
		*rsp_data = buf;
		*rsp_len = len;
	} while (0);

	return COMM_NETLINK_SUCC;
}

static int dpi_stats_valid(u64 cur_time, u64 expire, dpi_stats_t *pstats, u64 speed_size)
{
	if (((cur_time - pstats->rx_stats.speed_uptime) > expire * 1000000) && ((cur_time - pstats->tx_stats.speed_uptime) > expire * 1000000)) {
		return 0;
	}
	if (speed_size) {
		if ((pstats->rx_stats.speed < speed_size) && (pstats->tx_stats.speed < speed_size)) {
			return 0;
		}
	}
	if ((pstats->rx_stats.speed / 1000 == 0) && (pstats->tx_stats.speed / 1000 == 0)) {
		return 0;
	}
	return 1;
}


static void copy_data_to_dpi_speed(Netlink__Proto__DpiSpeedItem *item, dpi_result_node *dpi_result,
										u64 cur_time, u64 expire, dpi_stats_t *pstats)
{
	switch (dpi_result->level_type) {
	case DPI_LEVEL_TYPE_UID:
		item->type = NETLINK__PROTO__DPI_LEVEL_TYPE__DPI_LEVEL_UID;
		break;
	case DPI_LEVEL_TYPE_APP:
		item->type = NETLINK__PROTO__DPI_LEVEL_TYPE__DPI_LEVEL_APP;
		break;
	case DPI_LEVEL_TYPE_FUNCTION:
		item->type = NETLINK__PROTO__DPI_LEVEL_TYPE__DPI_LEVEL_FUNC;
		break;
	case DPI_LEVEL_TYPE_STREAM:
		item->type = NETLINK__PROTO__DPI_LEVEL_TYPE__DPI_LEVEL_STREAM;
		break;
	default:
		logt("unknown type %d", dpi_result->level_type);
		break;
	}
	item->uid = dpi_result->uid;
	item->ifidx = pstats->if_idx;
	item->dpiid = dpi_result->dpi_id;
	if ((cur_time - pstats->rx_stats.speed_uptime) <= expire * 1000000) {
		item->rxspeed = pstats->rx_stats.speed / 1000;
	}
	if ((cur_time - pstats->tx_stats.speed_uptime) <= expire * 1000000) {
		item->txspeed = pstats->tx_stats.speed / 1000;
	}
}


static int check_u32_array_match(u32 *array, size_t size, u32 value)
{
	int i = 0;
	for (i = 0; i < size; i++) {
		if (array[i] == value) {
			return 1;
		}
	}
	return 0;
}

static int get_dpi_stream_speed_uid_request(u32 eventid, Netlink__Proto__RequestMessage *requestMsg, char **rsp_data, u32 *rsp_len)
{
	u32 uid_size = 0;
	u32 uid_count = 0;
	u32 stream_count = 0;
	u32 stream_added = 0;
	u32 buf_len = 0;
	int i = 0, j = 0, k = 0;
	int ifidx_count = 0;
	u64 cur_time = 0;
	u64 expire = s_speed_expire;
	u64 speed_size = 0;
	struct timespec64 time;
	dpi_result_node *pos_app = NULL;
	dpi_result_node *pos_func = NULL;
	dpi_result_node *pos_stream = NULL;
	Netlink__Proto__ResponseGetDpiStreamSpeed speedRsp = NETLINK__PROTO__RESPONSE_GET_DPI_STREAM_SPEED__INIT;

	if ((requestMsg->request_data_case != NETLINK__PROTO__REQUEST_MESSAGE__REQUEST_DATA_REQUEST_GET_DPI_STREAM_SPEED)
		|| (!requestMsg->requestgetdpistreamspeed)) {
		return COMM_NETLINK_ERR_PARAM;
	}

	uid_size = requestMsg->requestgetdpistreamspeed->n_uid;
	ifidx_count = requestMsg->requestgetdpistreamspeed->n_ifidx;
	speed_size = requestMsg->requestgetdpistreamspeed->speed_size;
	ktime_get_raw_ts64(&time);
	cur_time = time.tv_sec * NS_PER_SEC + time.tv_nsec;

	spin_lock_bh(&s_dpi_lock);
	uid_count = 0;
	hlist_for_each_entry(pos_app, &s_match_app_result_head, node) {
		if((uid_size == 0) || check_u32_array_match(requestMsg->requestgetdpistreamspeed->uid, uid_size, pos_app->uid)) {
			hlist_for_each_entry(pos_func, &pos_app->child_list, node) {
				hlist_for_each_entry(pos_stream, &pos_func->child_list, node) {
					if (ifidx_count == 0) {
						if (dpi_stats_valid(cur_time, expire, &pos_stream->hash_stats.total_stats, speed_size)) {
							stream_count++;
						}
					} else {
						dpi_stats_t *stats_pos = NULL;
						for(i = 0; i < ifidx_count; i++) {
							hash_for_each_possible(pos_stream->hash_stats.stats_map, stats_pos, node, requestMsg->requestgetdpistreamspeed->ifidx[i]) {
								if (stats_pos->if_idx == requestMsg->requestgetdpistreamspeed->ifidx[i]) {
									if (dpi_stats_valid(cur_time, expire, stats_pos, speed_size)) {
										stream_count++;
									}
									break;
								}
							}
						}
					}
				}
			}
			if (uid_size) {
				uid_count++;
				if (uid_count == uid_size) {
					break;
				}
			}
		}
	}

	if (stream_count != 0) {
		buf_len = (sizeof(void *) + sizeof(Netlink__Proto__DpiSpeedItem)) * stream_count;
		speedRsp.n_streamuidspeed = stream_count;
		speedRsp.streamuidspeed = kmalloc(buf_len, GFP_ATOMIC);
		if (speedRsp.streamuidspeed == NULL) {
			logt("malloc size %u failed!", buf_len);
			spin_unlock_bh(&s_dpi_lock);
			return COMM_NETLINK_ERR_MEMORY;
		}
		memset((char *)speedRsp.streamuidspeed, 0, buf_len);
		for (k = 0; k < stream_count; k++) {
			speedRsp.streamuidspeed[k] = (Netlink__Proto__DpiSpeedItem *)
						((char *)speedRsp.streamuidspeed + sizeof(void *) * stream_count + sizeof(Netlink__Proto__DpiSpeedItem) * k);
			netlink__proto__dpi_speed_item__init((ProtobufCMessage *)speedRsp.streamuidspeed[k]);
		}
		uid_count = 0;
		hlist_for_each_entry(pos_app, &s_match_app_result_head, node) {
			if((uid_size == 0) || check_u32_array_match(requestMsg->requestgetdpistreamspeed->uid, uid_size, pos_app->uid)) {
				hlist_for_each_entry(pos_func, &pos_app->child_list, node) {
					hlist_for_each_entry(pos_stream, &pos_func->child_list, node) {
						if (ifidx_count == 0) {
							if (dpi_stats_valid(cur_time, expire, &pos_stream->hash_stats.total_stats, speed_size)) {
								if (stream_added >= stream_count) {
									logt("get_dpi_stream_speed: stream_added >= stream_count, stream_added=%d, stream_count=%d ", stream_added, stream_count);
									break;
								}
								copy_data_to_dpi_speed(speedRsp.streamuidspeed[stream_added], pos_stream, cur_time, expire, &pos_stream->hash_stats.total_stats);
								stream_added++;
							}
						} else {
							dpi_stats_t *stats_pos = NULL;
							for(j = 0; j < ifidx_count; j++) {
								hash_for_each_possible(pos_stream->hash_stats.stats_map, stats_pos, node, requestMsg->requestgetdpistreamspeed->ifidx[j]) {
									if (stats_pos->if_idx == requestMsg->requestgetdpistreamspeed->ifidx[j]) {
										if (dpi_stats_valid(cur_time, expire, stats_pos, speed_size)) {
											if (stream_added >= stream_count) {
												logt("get_dpi_stream_speed: stream_added >= stream_count, stream_added=%d, stream_count=%d ", stream_added, stream_count);
												break;
											}
											copy_data_to_dpi_speed(speedRsp.streamuidspeed[stream_added], pos_stream, cur_time, expire, stats_pos);
											stream_added++;
										}
										break;
									}
								}
							}
						}
					}
				}
				if (uid_size) {
					uid_count++;
					if (uid_count == uid_size) {
						break;
					}
				}
			}
		}
	}

	spin_unlock_bh(&s_dpi_lock);

	if (stream_added != stream_count) {
		logt("get_dpi_stream_speed: stream_added < stream_count, stream_added=%d, stream_count=%d ", stream_added, stream_count);
		speedRsp.n_streamuidspeed = stream_added;
	}

	do {
		size_t out_buf_len = 0, pack_len = 0;
		char *out_buf = NULL;
		NETLINK_RSP_DATA_DECLARE(rsp_name, requestMsg->header->requestid, requestMsg->header->eventid, COMM_NETLINK_SUCC);

		rsp_name.response_data_case = NETLINK__PROTO__RESPONSE_MESSAGE__RESPONSE_DATA_RSP_GET_DPI_STREAM_SPEED;
		rsp_name.rspgetdpistreamspeed = &speedRsp;
		out_buf_len = netlink__proto__response_message__get_packed_size(&rsp_name);
		out_buf = kmalloc(out_buf_len, GFP_ATOMIC);
		if (!out_buf) {
			logt("malloc speed out buf failed!");
			kfree(speedRsp.streamuidspeed);
			return COMM_NETLINK_ERR_MEMORY;
		}

		pack_len = netlink__proto__response_message__pack(&rsp_name, out_buf);
		logi("get_dpi_stream_speed_uid_request pack len %lu, buf len %lu", pack_len, out_buf_len);

		*rsp_data = out_buf;
		*rsp_len = out_buf_len;
	} while (0);

	kfree(speedRsp.streamuidspeed);

	return 0;
}

static int get_all_uid_dpi_speed_request(u32 eventid, Netlink__Proto__RequestMessage *requestMsg, char **rsp_data, u32 *rsp_len) {
	u32 stream_added = 0;
	u32 stream_count = 0;
	u32 buf_len = 0;
	int i = 0, j = 0, k = 0;
	int ifidx_count = 0;
	u64 cur_time = 0;
	u64 expire = s_speed_expire;
	u64 speed_size = 0;
	struct timespec64 time;
	dpi_result_node *pos_all_uid = NULL;
	Netlink__Proto__ResponseGetDpiStreamSpeed speedRsp = NETLINK__PROTO__RESPONSE_GET_DPI_STREAM_SPEED__INIT;
	if ((requestMsg->request_data_case != NETLINK__PROTO__REQUEST_MESSAGE__REQUEST_DATA_REQUEST_GET_ALL_UID_SPEED)
		|| (!requestMsg->requestgetalluidspeed)) {
		return COMM_NETLINK_ERR_PARAM;
	}
	ifidx_count = requestMsg->requestgetalluidspeed->n_ifidx;
	speed_size = requestMsg->requestgetalluidspeed->speed_size;
	ktime_get_raw_ts64(&time);
	cur_time = time.tv_sec * NS_PER_SEC + time.tv_nsec;

	spin_lock_bh(&s_dpi_lock);
	hlist_for_each_entry(pos_all_uid, &s_match_uid_result_head, node) {
		if (ifidx_count == 0) {
			if (dpi_stats_valid(cur_time, expire, &pos_all_uid->hash_stats.total_stats, speed_size)) {
				stream_count++;
			}
		}
		else {
			dpi_stats_t *stats_pos = NULL;
			for(i = 0; i < ifidx_count; i++) {
				hash_for_each_possible(pos_all_uid->hash_stats.stats_map, stats_pos, node, requestMsg->requestgetalluidspeed->ifidx[i]) {
					if (stats_pos->if_idx == requestMsg->requestgetalluidspeed->ifidx[i]) {
						if (dpi_stats_valid(cur_time, expire, stats_pos, speed_size)) {
							stream_count++;
						}
						break;
					}
				}
			}
		}
	}
	if (stream_count != 0) {
		buf_len = (sizeof(void *) + sizeof(Netlink__Proto__DpiSpeedItem)) * stream_count;
		speedRsp.n_streamuidspeed = stream_count;
		speedRsp.streamuidspeed = kmalloc(buf_len, GFP_ATOMIC);
		if (speedRsp.streamuidspeed == NULL) {
			logt("malloc size %u failed!", buf_len);
			spin_unlock_bh(&s_dpi_lock);
			return COMM_NETLINK_ERR_MEMORY;
		}
		memset((char *)speedRsp.streamuidspeed, 0, buf_len);
		for (k = 0; k < stream_count; k++) {
			speedRsp.streamuidspeed[k] = (Netlink__Proto__DpiSpeedItem *)
						((char *)speedRsp.streamuidspeed + sizeof(void *) * stream_count + sizeof(Netlink__Proto__DpiSpeedItem) * k);
			netlink__proto__dpi_speed_item__init((ProtobufCMessage *)speedRsp.streamuidspeed[k]);
		}
		hlist_for_each_entry(pos_all_uid, &s_match_uid_result_head, node) {
			if (ifidx_count == 0) {
				if (dpi_stats_valid(cur_time, expire, &pos_all_uid->hash_stats.total_stats, speed_size)) {
					if (stream_added >= stream_count) {
						logt("get_dpi_stream_speed: stream_added >= stream_count, stream_added=%d, stream_count=%d ", stream_added, stream_count);
						break;
					}
					copy_data_to_dpi_speed(speedRsp.streamuidspeed[stream_added], pos_all_uid, cur_time, expire, &pos_all_uid->hash_stats.total_stats);
					stream_added++;
				}
			} else {
				dpi_stats_t *stats_pos = NULL;
				for(j = 0; j < ifidx_count; j++) {
					hash_for_each_possible(pos_all_uid->hash_stats.stats_map, stats_pos, node, requestMsg->requestgetalluidspeed->ifidx[j]) {
						if (stats_pos->if_idx == requestMsg->requestgetalluidspeed->ifidx[j]) {
							if (dpi_stats_valid(cur_time, expire, stats_pos, speed_size)) {
								if (stream_added >= stream_count) {
									logt("get_dpi_stream_speed: stream_added >= stream_count, stream_added=%d, stream_count=%d ", stream_added, stream_count);
									break;
								}
								copy_data_to_dpi_speed(speedRsp.streamuidspeed[stream_added], pos_all_uid, cur_time, expire, stats_pos);
								stream_added++;
							}
							break;
						}
					}
				}
			}
		}
	}
	spin_unlock_bh(&s_dpi_lock);
	do {
		size_t out_buf_len = 0, pack_len = 0;
		char *out_buf = NULL;
		NETLINK_RSP_DATA_DECLARE(rsp_name, requestMsg->header->requestid, requestMsg->header->eventid, COMM_NETLINK_SUCC);

		rsp_name.response_data_case = NETLINK__PROTO__RESPONSE_MESSAGE__RESPONSE_DATA_RSP_GET_DPI_STREAM_SPEED;
		rsp_name.rspgetdpistreamspeed = &speedRsp;
		out_buf_len = netlink__proto__response_message__get_packed_size(&rsp_name);
		out_buf = kmalloc(out_buf_len, GFP_ATOMIC);
		if (!out_buf) {
			logt("malloc speed out buf failed!");
			kfree(speedRsp.streamuidspeed);
			return COMM_NETLINK_ERR_MEMORY;
		}

		pack_len = netlink__proto__response_message__pack(&rsp_name, out_buf);
		logi("get_all_uid_dpi_speed_request pack len %lu, buf len %lu", pack_len, out_buf_len);

		*rsp_data = out_buf;
		*rsp_len = out_buf_len;
	} while (0);
	kfree(speedRsp.streamuidspeed);
	return 0;
}

static int response_get_dpi_record(u32 eventid, Netlink__Proto__RequestMessage *requestMsg, char **rsp_data, u32 *rsp_len) {
	u32 buf_len = 0;
	u32 k = 0;
	u32 record_add = 0;
	dpi_record_node *pos = NULL;
	struct hlist_node *n = NULL;

	Netlink__Proto__ResponseDpiRecordData speedRsp = NETLINK__PROTO__RESPONSE_DPI_RECORD_DATA__INIT;

	if(s_dpi_record_count != 0) {
		spin_lock_bh(&s_record_lock);
		speedRsp.n_recorddata = s_dpi_record_count;
		buf_len = (sizeof(void *) + sizeof(Netlink__Proto__ResponseDpiRecordItem)) * s_dpi_record_count;
		speedRsp.recorddata = kmalloc(buf_len, GFP_ATOMIC);
		if (speedRsp.recorddata == NULL) {
			logt("malloc size %u failed!", buf_len);
			spin_unlock_bh(&s_record_lock);
			return COMM_NETLINK_ERR_MEMORY;
		}
		memset((char *)speedRsp.recorddata, 0, buf_len);
		for (k = 0; k < s_dpi_record_count; k++) {
			speedRsp.recorddata[k] = (Netlink__Proto__ResponseDpiRecordItem *)
						((char *)speedRsp.recorddata + sizeof(void *) * s_dpi_record_count + sizeof(Netlink__Proto__ResponseDpiRecordItem) * k);
			netlink__proto__response_dpi_record_item__init((ProtobufCMessage *)speedRsp.recorddata[k]);
		}

		hlist_for_each_entry_safe(pos, n, &s_dpi_record_result_head, list_node) {
			speedRsp.recorddata[record_add]->dpi_id = pos->dpi_result;
			speedRsp.recorddata[record_add]->duration = pos->duration;
			speedRsp.recorddata[record_add]->rx_traffic = pos->rx_traffic;
			speedRsp.recorddata[record_add]->tx_traffic = pos->tx_traffic;
			speedRsp.recorddata[record_add]->total_traffic = pos->total_traffic;
			record_add++;
			hlist_del_init(&pos->list_node);
			kfree(pos);
			if(record_add == s_dpi_record_count) {
				break;
			}
		}
	} else {
		return COMM_NETLINK_FAIL;
	}

	if(record_add != s_dpi_record_count) {
		logt("response_get_dpi_record record_add < s_dpi_record_count, record_add = %u, s_dpi_record_count = %u", record_add, s_dpi_record_count);
		speedRsp.n_recorddata = record_add;
	}
	s_dpi_record_count = 0;
	spin_unlock_bh(&s_record_lock);

	do {
		size_t out_buf_len = 0, pack_len = 0;
		char *out_buf = NULL;
		NETLINK_RSP_DATA_DECLARE(rsp_name, requestMsg->header->requestid, requestMsg->header->eventid, COMM_NETLINK_SUCC);
		rsp_name.response_data_case = NETLINK__PROTO__RESPONSE_MESSAGE__RESPONSE_DATA_RESPONSE_DPI_RECORD_DATA;
		rsp_name.responsedpirecorddata = &speedRsp;
		out_buf_len = netlink__proto__response_message__get_packed_size(&rsp_name);
		out_buf = kmalloc(out_buf_len, GFP_ATOMIC);
		if (!out_buf) {
			logt("malloc record out buf failed!");
			kfree(speedRsp.recorddata);
			return COMM_NETLINK_ERR_MEMORY;
		}

		pack_len = netlink__proto__response_message__pack(&rsp_name, out_buf);
		logt("response_get_dpi_record pack len %lu, buf len %lu", pack_len, out_buf_len);

		*rsp_data = out_buf;
		*rsp_len = out_buf_len;
	} while (0);
	kfree(speedRsp.recorddata);

	return COMM_NETLINK_SUCC;
}

int oplus_dpi_module_init(void)
{
	int ret = 0;

	spin_lock_init(&s_dpi_lock);
	spin_lock_init(&s_match_lock);
	spin_lock_init(&s_record_lock);

	INIT_HLIST_HEAD(&s_notify_head);
	INIT_HLIST_HEAD(&s_match_app_head);

	INIT_HLIST_HEAD(&s_match_app_result_head);
	INIT_HLIST_HEAD(&s_match_uid_result_head);
	INIT_HLIST_HEAD(&s_dpi_record_result_head);

	oplus_dpi_table_hdr = register_net_sysctl(&init_net, "net/oplus_dpi", oplus_dpi_sysctl_table);
	logt("register_net_sysctl return %p", oplus_dpi_table_hdr);
	if(!oplus_dpi_table_hdr) {
		return ret;
	}

	ret |= nf_register_net_hooks(&init_net, dpi_netfilter_ops, ARRAY_SIZE(dpi_netfilter_ops));
	logt("nf_register_net_hooks return %d", ret);
	if(ret) {
		nf_unregister_net_hooks(&init_net, dpi_netfilter_ops, ARRAY_SIZE(dpi_netfilter_ops));
		return ret;
	}

	ret |= register_netlink_request(COMM_NETLINK_EVENT_GET_DPI_STREAM_SPEED, get_dpi_stream_speed_uid_request, data_free);
	if(ret) {
		logt("register_netlink_request failed, return %d", ret);
		return ret;
	}
	ret |= register_netlink_request(COMM_NETLINK_EVENT_GET_ALL_UID_DPI_SPEED, get_all_uid_dpi_speed_request, data_free);
	if(ret) {
		logt("register_netlink_request failed, return %d", ret);
		unregister_netlink_request(COMM_NETLINK_EVENT_GET_DPI_STREAM_SPEED);
		return ret;
	}
	ret |= register_netlink_request(COMM_NETLINK_EVENT_SET_DPI_MATCH_ALL_UID, request_set_match_all_uid_eable, data_free);
	if(ret) {
		logt("register_netlink_request failed, return %d", ret);
		unregister_netlink_request(COMM_NETLINK_EVENT_GET_ALL_UID_DPI_SPEED);
		unregister_netlink_request(COMM_NETLINK_EVENT_GET_DPI_STREAM_SPEED);
		return ret;
	}
	ret |= register_netlink_request(COMM_NETLINK_EVENT_GET_DPI_RECORD_DATA, response_get_dpi_record, data_free);
	timer_setup(&s_check_timeout_timer, dpi_check_timeout_fun, 0);
	mod_timer(&s_check_timeout_timer, jiffies + s_dpi_timeout * HZ / 1000);

	return ret;
}

void oplus_dpi_module_fini(void)
{
	del_timer_sync(&s_check_timeout_timer);
	nf_unregister_net_hooks(&init_net, dpi_netfilter_ops, ARRAY_SIZE(dpi_netfilter_ops));
	if (oplus_dpi_table_hdr) {
		unregister_net_sysctl_table(oplus_dpi_table_hdr);
	}
	unregister_netlink_request(COMM_NETLINK_EVENT_GET_DPI_STREAM_SPEED);
	unregister_netlink_request(COMM_NETLINK_EVENT_GET_ALL_UID_DPI_SPEED);
	unregister_netlink_request(COMM_NETLINK_EVENT_SET_DPI_MATCH_ALL_UID);
}
