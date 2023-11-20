/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2018-2020 Oplus. All rights reserved.
 */

#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <net/inet_sock.h>
#include <net/genetlink.h>
#include <net/tcp.h>
#include <net/inet_timewait_sock.h>
#include <net/request_sock.h>
#include <net/timewait_sock.h>
#include <net/inet_hashtables.h>
#include <net/inet6_hashtables.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "sk_pid_hook.h"
#include "../linkpower_netlink/linkpower_netlink.h"

/* Netlink */
extern int netlink_send_to_user(int msg_type, char *data, int data_len);

#define UNSOL_PUSH_SOCK_TYPE_DETECTED 1
#define UNSOL_PUSH_SOCK_TYPE_DESTROY 2
#define UNSOL_PUSH_SOCK_TYPE_STOP 3

#define PUSH_SK_TRANSPORT_IGNORE_TIME 3 * 1000
#define SKCONNECT_INFO_MONITOR_TIME 10 * 1000
#define SYN_RETRANSMITS_ERR_LIMIT 3

#define SPORT_PID_ARRAY_LEN 50
#define DESTROY_SK_ARRAY_LEN 50
#define PUSH_SK_ARRAY_LEN 5
#define SK_CONNECT_ARRAY_LEN 10

#define SYSTEM_UID 1000
#define TCP_CONNECT_NAME "tcp_connect"

static unsigned int my_input_hook_v4(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static unsigned int my_input_hook_v6(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static unsigned int my_output_hook_v4(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static unsigned int my_output_hook_v6(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static struct nf_hook_ops my_nf_hook_ops[] __read_mostly = {
	{
		.hook = my_input_hook_v4,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FILTER,
	},
	{
		.hook = my_input_hook_v6,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FILTER,
	},
	{
		.hook = my_output_hook_v4,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_FILTER,
	},
	{
		.hook = my_output_hook_v6,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_FILTER,
	},
};

static void destroy_sk_asyn(struct work_struct *work);
static DECLARE_WORK(destroy_sk_work, destroy_sk_asyn);

static void push_sk_detected_asyn(struct work_struct *work);
static DECLARE_WORK(push_sk_detected_work, push_sk_detected_asyn);

static void push_sk_destroyed_asyn(struct work_struct *work);
static DECLARE_WORK(push_sk_destroyed_work, push_sk_destroyed_asyn);

static int handler_tcp_connect(struct kprobe *kp, struct pt_regs *regs);
static struct kprobe kp_tcp_connect = {
	.symbol_name = TCP_CONNECT_NAME,
	.pre_handler = handler_tcp_connect,
};

static bool boot_monitor_push_sk = false;
static bool boot_monitor_sk_connect = false;
static uint64_t push_sk_transport_stamp = 0;
static netlink_ul_sport_pid_struct sprot_pid_array[SPORT_PID_ARRAY_LEN];
static sk_info_struct destroy_sk_array[DESTROY_SK_ARRAY_LEN];
static monitor_push_sk_struct push_sk_array[PUSH_SK_ARRAY_LEN];
static netlink_ul_sk_connect_info_struct sk_connect_array[SK_CONNECT_ARRAY_LEN];
static uint64_t sk_connect_deadline_array[SK_CONNECT_ARRAY_LEN];

/**
 * @brief      Determine whether the chain is empty.
 *
 * @param[in]  i     The index
 *
 * @return     True if empty, false otherwise.
 */
static bool empty_bucket(int i)
{
	return hlist_nulls_empty(&tcp_hashinfo.ehash[i].chain);
}

/**
 * @brief      Customized current kernel time function.
 *
 * @return     The current kernel time.
 */
static uint64_t current_kernel_time(void)
{
	struct timespec64 ts64;

	ktime_get_real_ts64(&ts64);
	return ts64.tv_sec * 1000 + ts64.tv_nsec / 1000000;
}

/**
 * @brief      Get the uid from sock.
 *
 * @param[in]  sk    The sock
 *
 * @return     The uid from sock.
 */
static uint32_t get_uid_from_sock(const struct sock *sk)
{
	uint32_t sk_uid = 0;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0))
	const struct file *filp = NULL;
#endif
	if (NULL == sk || !sk_fullsock(sk) || NULL == sk->sk_socket) {
		return 0;
	}
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0))
	filp = sk->sk_socket->file;
	if (NULL == filp) {
		return 0;
	}
	sk_uid = __kuid_val(filp->f_cred->fsuid);
#else
	sk_uid = __kuid_val(sk->sk_uid);
#endif
	return sk_uid;
}

/**
 * @brief      Get the pid from sock.
 *
 * @param[in]  sk    The sock
 *
 * @return     The pid from sock.
 */
static uint32_t get_pid_from_sock(const struct sock *sk)
{
	uint32_t sk_pid = 0;
	if (NULL == sk || !sk_fullsock(sk) || NULL == sk->sk_socket) {
		return 0;
	}
#ifdef CONFIG_ANDROID_KABI_RESERVE
	sk_pid = sk->android_kabi_reserved7;
#endif
	return sk_pid;
}

/**
 * @brief      Free inet_twsk.
 *
 * @param      tw    The timewait sock
 */
static void my_inet_twsk_free(struct inet_timewait_sock *tw)
{
	struct module *owner = tw->tw_prot->owner;
	twsk_destructor((struct sock *)tw);
	kmem_cache_free(tw->tw_prot->twsk_prot->twsk_slab, tw);
	module_put(owner);
}

/**
 * @brief      Sock gen put.
 *
 * @param      sk    The socket
 */
static void my_sock_gen_put(struct sock *sk)
{
	if (!refcount_dec_and_test(&sk->sk_refcnt))
		return;

	if (sk->sk_state == TCP_TIME_WAIT)
		my_inet_twsk_free(inet_twsk(sk));
	else if (sk->sk_state == TCP_NEW_SYN_RECV)
		reqsk_free(inet_reqsk(sk));
	else
		sk_free(sk);
}

/**
 * @brief      Lookup sk by 5-tuple information in sk_info.
 *
 * @param      sk_info  The socket information
 *
 * @return     struct sock* if successful, NULL otherwise.
 */
struct sock *my_lookup_sk(sk_info_struct *sk_info)
{
	struct sock *sk = NULL;

	if (sk_info == NULL) {
		printk("[sk_pid_hook] my_lookup_sk failed, sk_info is null!\n");
		return NULL;
	}

	if (!sk_info->is_ipv6) {
		sk = __inet_lookup_established(&init_net, &tcp_hashinfo, sk_info->v6_daddr32[0],
		                               sk_info->dport, sk_info->v6_saddr32[0],
		                               htons(sk_info->sport), 0, 0);
		if (NULL == sk || !sk_fullsock(sk) || NULL == sk->sk_socket) {
			sk = NULL;
		}
		return sk;
	}
	else {
#if defined(CONFIG_IPV6)
		const struct in6_addr saddr6 =
			{	{	.u6_addr32 = {sk_info->v6_saddr32[0], sk_info->v6_saddr32[1],
					sk_info->v6_saddr32[2], sk_info->v6_saddr32[3]
				}
			}
		};
		const struct in6_addr daddr6 =
			{	{	.u6_addr32 = {sk_info->v6_daddr32[0], sk_info->v6_daddr32[1],
					sk_info->v6_daddr32[2], sk_info->v6_daddr32[3]
				}
			}
		};
		sk = __inet6_lookup_established(&init_net, &tcp_hashinfo, &daddr6,
		                                sk_info->dport, &saddr6,
		                                htons(sk_info->sport), 0, 0);
		if (NULL == sk || !sk_fullsock(sk) || NULL == sk->sk_socket) {
			sk = NULL;
		}
		return sk;
#endif
	}

	return NULL;
}

/**
 * @brief      Monitor Tcp Push Package.
 *
 * @param      sk         The socket
 * @param      skb        The socket buffer
 * @param[in]  is_output  Indicates if output
 * @param[in]  is_ipv6    Indicates if IPv6
 */
static void monitor_push_sk(struct sock *sk, struct sk_buff *skb, bool is_output, bool is_ipv6)
{
	int i = 0;
	int tcp_len = 0;
	int header_len = 0;
	bool match = false;
	uint64_t now = 0;
	uint32_t sk_uid = 0;
	uint8_t *tcp_data = NULL;
	uint8_t *buffer = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;

	if (!boot_monitor_push_sk) {
		return;
	}

	sk_uid = get_uid_from_sock(sk);
	if (sk_uid == 0) {
		return;
	}

	for (i = 0; i < PUSH_SK_ARRAY_LEN; ++i) {
		if (push_sk_array[i].monitor.uid == sk_uid) {
			match = true;
			break;
		}
	}
	if (!match || i >= PUSH_SK_ARRAY_LEN) {
		return;
	}
	tcph = tcp_hdr(skb);
	if (is_ipv6) {
		header_len = sizeof(struct ipv6hdr) + tcph->doff * 4;
	} else {
		iph = ip_hdr(skb);
		header_len = iph->ihl * 4 + tcph->doff * 4;
	}
	tcp_len = skb->len - header_len;
	if (tcp_len <= 0) {
		return;
	}

	if (is_output && tcp_len == push_sk_array[i].monitor.beat_msg_len
	        && tcp_len >= push_sk_array[i].monitor.beat_feature_len) {
		if (push_sk_array[i].sk == sk) {
			push_sk_array[i].beat_count++;
		} else {
			if (push_sk_array[i].monitor.beat_feature_len != 0) {
				buffer = kvmalloc(tcp_len, GFP_ATOMIC);
				if (!buffer) {
					return;
				}
				memset(buffer, 0x0, tcp_len);
				tcp_data = (uint8_t *)skb_header_pointer(skb, header_len, tcp_len, buffer);
				if (tcp_data && (sizeof(push_sk_array[i].monitor.beat_feature)
				                 >= push_sk_array[i].monitor.beat_feature_len)
				        && (memcmp(tcp_data, push_sk_array[i].monitor.beat_feature,
				                   push_sk_array[i].monitor.beat_feature_len) == 0)) {
					push_sk_array[i].sk = sk;
					push_sk_array[i].type = UNSOL_PUSH_SOCK_TYPE_DETECTED;
					push_sk_array[i].pid = get_pid_from_sock(sk);
					push_sk_array[i].beat_count++;
					schedule_work(&push_sk_detected_work);
				}
				kfree(buffer);
			} else {
				push_sk_array[i].sk = sk;
				push_sk_array[i].type = UNSOL_PUSH_SOCK_TYPE_DETECTED;
				push_sk_array[i].pid = get_pid_from_sock(sk);
				push_sk_array[i].beat_count++;
				schedule_work(&push_sk_detected_work);
			}
		}
	}

	if (!is_output && tcp_len >= push_sk_array[i].monitor.push_feature_len) {
		if (push_sk_array[i].monitor.push_feature_len == 0) {
			if (push_sk_array[i].sk == sk) {
				now = current_kernel_time();
				if ((now - push_sk_transport_stamp) > PUSH_SK_TRANSPORT_IGNORE_TIME) {
					push_sk_array[i].push_count++;
					push_sk_transport_stamp = now;
				}
			}
		} else {
			buffer = kvmalloc(tcp_len, GFP_ATOMIC);
			if (!buffer) {
				return;
			}
			memset(buffer, 0x0, tcp_len);
			tcp_data = (uint8_t *)skb_header_pointer(skb, header_len, tcp_len, buffer);
			if (tcp_data && push_sk_array[i].sk == sk
			        && (sizeof(push_sk_array[i].monitor.push_feature) >= push_sk_array[i].monitor.push_feature_len)
			        && (memcmp(tcp_data, push_sk_array[i].monitor.push_feature,
			                   push_sk_array[i].monitor.push_feature_len) == 0)) {
				now = current_kernel_time();
				if ((now - push_sk_transport_stamp) > PUSH_SK_TRANSPORT_IGNORE_TIME) {
					push_sk_array[i].push_count++;
					push_sk_transport_stamp = now;
				}
			}
			kfree(buffer);
		}
	}
}

/**
 * @brief      Monitor Tcp Close Package.
 *
 * @param      sk         The socket
 * @param      skb        The socket buffer
 * @param[in]  is_output  Indicates if output
 * @param[in]  is_ipv6    Indicates if IPv6
 */
static void monitor_sk_close(struct sock *sk, struct sk_buff *skb, bool is_output, bool is_ipv6)
{
	int i = 0;
	bool match = false;
	uint32_t sk_uid = 0;
	struct tcphdr *tcph = NULL;

	sk_uid = get_uid_from_sock(sk);
	if (sk_uid == 0) {
		return;
	}

	if (boot_monitor_push_sk) {
		for (i = 0; i < PUSH_SK_ARRAY_LEN; ++i) {
			if (push_sk_array[i].monitor.uid == sk_uid && push_sk_array[i].sk == sk) {
				match = true;
				break;
			}
		}
		if (match && i < PUSH_SK_ARRAY_LEN) {
			push_sk_array[i].type = UNSOL_PUSH_SOCK_TYPE_DESTROY;
			schedule_work(&push_sk_destroyed_work);
		}
	}

	tcph = tcp_hdr(skb);
	if (boot_monitor_sk_connect && sk->sk_state == TCP_SYN_SENT && tcph->rst) {
		match = false;
		for (i = 0; i < SK_CONNECT_ARRAY_LEN; ++i) {
			if (sk_connect_array[i].proc.uid == sk_uid) {
				if (sk_connect_array[i].proc.pid == 0) {
					match = true;
				} else if (sk_connect_array[i].proc.pid == get_pid_from_sock(sk)) {
					match = true;
				}
				break;
			}
		}
		if (match && i < SK_CONNECT_ARRAY_LEN && (current_kernel_time() <= sk_connect_deadline_array[i])) {
			if (is_output)
				sk_connect_array[i].syn_snd_rst_count++;
			else
				sk_connect_array[i].syn_rcv_rst_count++;
		}
	}
}

/**
 * @brief      Monitor Tcp Syn Package.
 *
 * @param      sk         The socket
 * @param      skb        The socket buffer
 * @param[in]  is_output  Indicates if output
 * @param[in]  is_ipv6    Indicates if IPv6
 */
static void monitor_sk_syn(struct sock *sk, struct sk_buff *skb, bool is_output, bool is_ipv6)
{
	int i = 0;
	bool match = false;
	uint32_t sk_uid = 0;
	struct tcphdr *tcph = NULL;
	struct inet_connection_sock *icsk = NULL;

	if (!boot_monitor_sk_connect)
		return;

	if (!is_output)
		return;

	sk_uid = get_uid_from_sock(sk);
	if (sk_uid == 0)
		return;

	for (i = 0; i < SK_CONNECT_ARRAY_LEN; ++i) {
		if (sk_connect_array[i].proc.uid == sk_uid) {
			if (sk_connect_array[i].proc.pid == 0) {
				match = true;
			} else if (sk_connect_array[i].proc.pid == get_pid_from_sock(sk)) {
				match = true;
			}
			break;
		}
	}
	if (!match || i >= SK_CONNECT_ARRAY_LEN) {
		return;
	}

	icsk = inet_csk(sk);
	tcph = tcp_hdr(skb);
	if (sk->sk_state == TCP_SYN_SENT && icsk->icsk_retransmits == SYN_RETRANSMITS_ERR_LIMIT
	        && (current_kernel_time() <= sk_connect_deadline_array[i])) {
		sk_connect_array[i].syn_retrans_count++;
	}
}

/**
 * @brief      Get valid sk from skb.
 *
 * @param      skb      The socket buffer
 * @param[in]  is_ipv6  Indicates if ipv 6
 *
 * @return     struct sock* if successful, NULL otherwise.
 */
static struct sock *skb_to_valid_sk(struct sk_buff *skb, bool is_output, bool is_ipv6)
{
	struct sock *sk = NULL;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ipv6h = NULL;
	struct tcphdr *tcph = NULL;
	struct net_device *dev = NULL;

	if (is_ipv6) {
		ipv6h = ipv6_hdr(skb);
		tcph = tcp_hdr(skb);
		if (skb->protocol != htons(ETH_P_IPV6) || (!ipv6h))
			return NULL;

		if (ipv6h->nexthdr != NEXTHDR_TCP || !tcph)
			return NULL;
	} else {
		iph = ip_hdr(skb);
		tcph = tcp_hdr(skb);
		if (skb->protocol != htons(ETH_P_IP) || (!iph))
			return NULL;
		if (iph->protocol != IPPROTO_TCP || !tcph)
			return NULL;
	}

	sk = skb_to_full_sk(skb);
	if (!sk)
		return NULL;

	dev = skb->dev;
	if (!is_output && !dev)
		return NULL;

	return sk;
}

/**
 * @brief      IPv4 Input hook functions.
 *
 * @param      priv   The priv
 * @param      skb    The socket buffer
 * @param[in]  state  The state
 *
 * @return     Responses from hook functions.
 */
static unsigned int my_input_hook_v4(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct tcphdr *tcph = NULL;
	struct sock *sk = skb_to_valid_sk(skb, false, false);
	if (!sk)
		return NF_ACCEPT;

	tcph = tcp_hdr(skb);
	if (tcph->syn)
		monitor_sk_syn(sk, skb, false, false);
	if (tcph->psh)
		monitor_push_sk(sk, skb, false, false);
	if (tcph->fin || tcph->rst)
		monitor_sk_close(sk, skb, false, false);

	return NF_ACCEPT;
}

/**
 * @brief      IPv6 Input hook functions.
 *
 * @param      priv   The priv
 * @param      skb    The socket buffer
 * @param[in]  state  The state
 *
 * @return     Responses from hook functions.
 */
static unsigned int my_input_hook_v6(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct tcphdr *tcph = NULL;
	struct sock *sk = skb_to_valid_sk(skb, false, true);
	if (!sk)
		return NF_ACCEPT;

	tcph = tcp_hdr(skb);
	if (tcph->syn)
		monitor_sk_syn(sk, skb, false, true);
	if (tcph->psh)
		monitor_push_sk(sk, skb, false, true);
	if (tcph->fin || tcph->rst)
		monitor_sk_close(sk, skb, false, true);

	return NF_ACCEPT;
}

/**
 * @brief      IPv4 output hook functions.
 *
 * @param      priv   The priv
 * @param      skb    The socket buffer
 * @param[in]  state  The state
 *
 * @return     Responses from hook functions.
 */
static unsigned int my_output_hook_v4(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct tcphdr *tcph = NULL;
	struct sock *sk = skb_to_valid_sk(skb, true, false);
	if (!sk)
		return NF_ACCEPT;

	tcph = tcp_hdr(skb);
	if (tcph->syn)
		monitor_sk_syn(sk, skb, true, false);
	if (tcph->psh)
		monitor_push_sk(sk, skb, true, false);
	if (tcph->fin || tcph->rst)
		monitor_sk_close(sk, skb, true, false);

	return NF_ACCEPT;
}

/**
 * @brief      IPv6 output hook functions.
 *
 * @param      priv   The priv
 * @param      skb    The socket buffer
 * @param[in]  state  The state
 *
 * @return     Responses from hook functions.
 */
static unsigned int my_output_hook_v6(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct tcphdr *tcph = NULL;
	struct sock *sk = skb_to_valid_sk(skb, true, true);
	if (!sk)
		return NF_ACCEPT;

	tcph = tcp_hdr(skb);
	if (tcph->syn)
		monitor_sk_syn(sk, skb, true, true);
	if (tcph->psh)
		monitor_push_sk(sk, skb, true, true);
	if (tcph->fin || tcph->rst)
		monitor_sk_close(sk, skb, true, true);

	return NF_ACCEPT;
}

/**
 * @brief      The handler of tcp_connect kprobe hook.
 *
 * @param      kp    The kprobe
 * @param      regs  The regs
 *
 * @return     0
 */
static int handler_tcp_connect(struct kprobe *kp, struct pt_regs *regs)
{
	int i = 0;
	bool array_overflow = true;
	int sk_uid = 0, sk_pid = 0;
	int inet_sport = 0;
	struct sock *sk = NULL;
	struct inet_sock *inet = NULL;

	sk = (struct sock *) regs->regs[0];
	sk_pid = current->tgid;
	sk_uid = current_uid().val;

#ifdef CONFIG_ANDROID_KABI_RESERVE
	sk->android_kabi_reserved7 = sk_pid;
#endif

	if (boot_monitor_sk_connect) {
		for (i = 0; i < SK_CONNECT_ARRAY_LEN; ++i) {
			if (sk_connect_array[i].proc.uid == sk_uid) {
				if (sk_connect_array[i].proc.pid == 0) {
					sk_connect_array[i].connect_count++;
				} else if (sk_connect_array[i].proc.pid == sk_pid) {
					sk_connect_array[i].connect_count++;
				}
				break;
			}
		}
	}

	if (sk_uid != SYSTEM_UID) {
		return 0;
	}

	inet = inet_sk(sk);
	inet_sport = ntohs(inet->inet_sport);

	if ((inet_sport == 0) || (sk_pid == 0)) {
		return 0;
	}
	for (i = 0; i < SPORT_PID_ARRAY_LEN; i++) {
		if ((sprot_pid_array[i].sport == 0) && (sprot_pid_array[i].pid == 0)) {
			sprot_pid_array[i].sport = (uint16_t) inet_sport;
			sprot_pid_array[i].pid = (uint16_t) sk_pid;
			array_overflow = false;
			break;
		}
	}
	if (array_overflow) {
		printk("[sk_pid_hook] handler_tcp_connect sport=%u pid=%u, array overflow!\n", inet_sport, sk_pid);
	}

	return 0;
}

/**
 * @brief      Put sk to array to be destroyed.
 *
 * @param      sk    The socket
 */
static void destroy_sk_array_put(struct sock *sk)
{
	int i = 0;
	struct inet_sock *inet = NULL;
	struct ipv6_pinfo *np = NULL;
	bool array_overflow = true;

	for (i = 0; i < DESTROY_SK_ARRAY_LEN; i++) {
		if (destroy_sk_array[i].protocol != 0) {
			continue;
		}
		array_overflow = false;
		inet = inet_sk(sk);
		destroy_sk_array[i].protocol = sk->sk_protocol;
		destroy_sk_array[i].sport = inet->inet_sport;
		destroy_sk_array[i].dport = inet->inet_dport;
		if (sk->sk_family == PF_INET6) {
			np = inet6_sk(sk);
			if (np) {
				if ((np->saddr.s6_addr32[0] == 0) && (np->saddr.s6_addr32[1] == 0)
				        && sk->sk_v6_daddr.s6_addr32[0] == 0 && sk->sk_v6_daddr.s6_addr32[1] == 0) {
					destroy_sk_array[i].is_ipv6 = false;
					destroy_sk_array[i].v6_saddr32[0] = np->saddr.s6_addr32[3];
					destroy_sk_array[i].v6_daddr32[0] = sk->sk_v6_daddr.s6_addr32[3];
				} else {
					destroy_sk_array[i].is_ipv6 = true;
					memcpy(destroy_sk_array[i].v6_saddr32, (uint8_t *)np->saddr.s6_addr32, 16);
					memcpy(destroy_sk_array[i].v6_daddr32, (uint8_t *)sk->sk_v6_daddr.s6_addr32, 16);
				}
			}
		} else {
			destroy_sk_array[i].is_ipv6 = false;
			destroy_sk_array[i].v6_saddr32[0] = inet->inet_rcv_saddr;
			destroy_sk_array[i].v6_daddr32[0] = inet->inet_daddr;
		}
		break;
	}

	if (array_overflow) {
		printk("[sk_pid_hook] destroy_sk_array_put, array overflow!\n");
	}
}

/**
 * @brief      The asyn func of push sk detected.
 *
 * @param      work  The work
 */
static void push_sk_detected_asyn(struct work_struct *work)
{
	int i = 0;
	int ret = 0;
	char msg_buf[sizeof(netlink_unsol_monitor_push_sk_struct)] = { 0 };
	netlink_unsol_monitor_push_sk_struct *unsol_msg = (netlink_unsol_monitor_push_sk_struct *)msg_buf;

	for (i = 0; i < PUSH_SK_ARRAY_LEN; ++i) {
		if (push_sk_array[i].type == UNSOL_PUSH_SOCK_TYPE_DETECTED) {
			unsol_msg->uid = push_sk_array[i].monitor.uid;
			unsol_msg->pid = push_sk_array[i].pid;
			unsol_msg->type = UNSOL_PUSH_SOCK_TYPE_DETECTED;
			unsol_msg->beat_count = push_sk_array[i].beat_count;
			unsol_msg->push_count = push_sk_array[i].push_count;
			ret = netlink_send_to_user(NETLINK_UNSOL_MONITOR_PUSH_SOCK, (char *)msg_buf, sizeof(msg_buf));
			if (ret < 0) {
				printk("[sk_pid_hook] push_sk_detected_asyn failed, netlink_send_to_user ret=%d uid=%u.\n",
				       ret, push_sk_array[i].monitor.uid);
			}
			push_sk_array[i].type = 0;
		}
	}
}

/**
 * @brief      The asyn func of push sk destroyed.
 *
 * @param      work  The work
 */
static void push_sk_destroyed_asyn(struct work_struct *work)
{
	int i = 0;
	int ret = 0;
	char msg_buf[sizeof(netlink_unsol_monitor_push_sk_struct)] = { 0 };
	netlink_unsol_monitor_push_sk_struct *unsol_msg = (netlink_unsol_monitor_push_sk_struct *)msg_buf;

	for (i = 0; i < PUSH_SK_ARRAY_LEN; ++i) {
		if (push_sk_array[i].type == UNSOL_PUSH_SOCK_TYPE_DESTROY) {
			unsol_msg->uid = push_sk_array[i].monitor.uid;
			unsol_msg->pid = push_sk_array[i].pid;
			unsol_msg->type = UNSOL_PUSH_SOCK_TYPE_DESTROY;
			unsol_msg->beat_count = push_sk_array[i].beat_count;
			unsol_msg->push_count = push_sk_array[i].push_count;

			ret = netlink_send_to_user(NETLINK_UNSOL_MONITOR_PUSH_SOCK, (char *)msg_buf, sizeof(msg_buf));
			if (ret < 0) {
				printk("[sk_pid_hook] push_sk_destroyed_asyn failed, netlink_send_to_user ret=%d uid=%u.\n",
				       ret, push_sk_array[i].monitor.uid);
			}
			push_sk_array[i].sk = NULL;
			push_sk_array[i].pid = 0;
			push_sk_array[i].type = 0;
			push_sk_array[i].beat_count = 0;
			push_sk_array[i].push_count = 0;
		}
	}
}

/**
 * @brief      The asyn func of destroy sk.
 *
 * @param      work  The work
 */
static void destroy_sk_asyn(struct work_struct *work)
{
	int i = 0;
	int ret = 0;
	struct sock *sk = NULL;
	char msg_buf[sizeof(netlink_ul_close_sk_struct)] = { 0 };
	netlink_ul_close_sk_struct *response_msg = (netlink_ul_close_sk_struct *)msg_buf;

	memset(msg_buf, 0x0, sizeof(msg_buf));

	for (i = 0; i < DESTROY_SK_ARRAY_LEN; i++) {
		if (destroy_sk_array[i].protocol == 0) {
			continue;
		}
		sk = my_lookup_sk(&destroy_sk_array[i]);
		if (sk == NULL) {
			printk("[sk_pid_hook] destroy_sk_asyn failed, sk is null!\n");
			continue;
		}
		if (response_msg->uid == 0) {
			response_msg->uid = get_uid_from_sock(sk);
		}
		if (response_msg->pid == 0) {
			response_msg->pid = get_pid_from_sock(sk);
		}
		if (sk->sk_prot->diag_destroy) {
			sk->sk_prot->diag_destroy(sk, ECONNABORTED);
			if (sk->sk_protocol == IPPROTO_TCP) {
				my_sock_gen_put(sk);
			} else if (sk->sk_protocol == IPPROTO_UDP) {
				sock_put(sk);
			} else {
				printk("[sk_pid_hook] destroy_sk_asyn failed, unknown protocol!\n");
			}
			printk("[sk_pid_hook] destroy_sk_asyn ok index=%d.\n", i);
			response_msg->count++;
		}
	}
	memset(destroy_sk_array, 0x0, sizeof(sk_info_struct) * DESTROY_SK_ARRAY_LEN);

	ret = netlink_send_to_user(NETLINK_RESPONSE_CLOSE_SK_FOR_PROC, (char *)msg_buf, sizeof(msg_buf));
	if (ret < 0) {
		printk("[sk_pid_hook] destroy_sk_asyn failed, netlink_send_to_user ret=%d.\n", ret);
	}
	return;
}

/**
 * @brief      The handler of request sport and pid info from user space.
 *
 * @return     0 if successful, negative otherwise.
 */
static int request_sk_port_and_pid(void)
{
	int ret = 0;
	char msg_buf[sizeof(netlink_ul_sport_pid_struct) * SPORT_PID_ARRAY_LEN] = { 0 };

	memcpy(msg_buf, sprot_pid_array, sizeof(netlink_ul_sport_pid_struct) * SPORT_PID_ARRAY_LEN);
	memset(sprot_pid_array, 0x0, sizeof(netlink_ul_sport_pid_struct) * SPORT_PID_ARRAY_LEN);

	ret = netlink_send_to_user(NETLINK_RESPONSE_SK_PORT_AND_PID, (char *)msg_buf, sizeof(msg_buf));
	if (ret < 0) {
		printk("[sk_pid_hook] request_sk_port_and_pid failed, netlink_send_to_user ret=%d.\n", ret);
	}

	return ret;
}

/**
 * @brief      The handler of request close sk for proc from user space.
 *
 * @param      nla   The nla
 *
 * @return     0 if successful, negative otherwise.
 */
static int request_close_sk_for_proc(struct nlattr *nla)
{
	int i = 0;
	int ret = 0;
	bool match = false;
	spinlock_t *lock = NULL;
	struct sock *sk = NULL;
	struct hlist_nulls_node *node = NULL;
	struct inet_sock *inet = NULL;
	netlink_dl_proc_struct *netlink_msg = (netlink_dl_proc_struct *)NLA_DATA(nla);
	char msg_buf[sizeof(netlink_ul_close_sk_struct)] = { 0 };
	netlink_ul_close_sk_struct *response_msg = (netlink_ul_close_sk_struct *)msg_buf;

	if (netlink_msg->uid <= 0 || netlink_msg->pid <= 0) {
		printk("[sk_pid_hook] request_close_sk_for_proc failed, invalid uid=%u pid=%u.\n",
		       netlink_msg->uid, netlink_msg->pid);
		return -EINVAL;
	}

	for (i = 0; i <= tcp_hashinfo.ehash_mask; ++i) {
		lock = inet_ehash_lockp(&tcp_hashinfo, i);
		if (empty_bucket(i)) {
			continue;
		}

		spin_lock_bh(lock);
		sk_nulls_for_each(sk, node, &tcp_hashinfo.ehash[i].chain) {
			if (IS_ERR(sk)) {
				continue;
			}
			if ((sk->sk_family != PF_INET) && (sk->sk_family != PF_INET6)) {
				continue;
			}
			if (!sk_fullsock(sk) || NULL == sk->sk_socket) {
				continue;
			}
			if ((sk->sk_protocol != IPPROTO_TCP) && (sk->sk_protocol != IPPROTO_UDP)) {
				continue;
			}
			inet = inet_sk(sk);
			if (get_uid_from_sock(sk) == netlink_msg->uid && get_pid_from_sock(sk) == netlink_msg->pid) {
				printk("[sk_pid_hook] request_close_sk_for_proc uid=%u pid=%u do destroy!\n",
				       netlink_msg->uid, netlink_msg->pid);
				match = true;
				destroy_sk_array_put(sk);
			}
		}
		spin_unlock_bh(lock);
	}
	if (match) {
		schedule_work(&destroy_sk_work);
	} else {
		response_msg->uid = netlink_msg->uid;
		response_msg->pid = netlink_msg->pid;
		ret = netlink_send_to_user(NETLINK_RESPONSE_CLOSE_SK_FOR_PROC, (char *)msg_buf, sizeof(msg_buf));
		if (ret < 0) {
			printk("[sk_pid_hook] request_close_sk_for_proc failed, netlink_send_to_user ret=%d.\n", ret);
		}
	}

	return ret;
}

/**
 * @brief      The handler of request start monitor push sock from user space.
 *
 * @param      nla   The nla
 *
 * @return     0 if successful, negative otherwise.
 */
static int request_start_monitor_push_sock(struct nlattr *nla)
{
	int i = 0;
	bool array_overflow = true;
	netlink_dl_start_monitor_push_sk_struct *netlink_msg = (netlink_dl_start_monitor_push_sk_struct *)NLA_DATA(nla);

	for (i = 0; i < PUSH_SK_ARRAY_LEN; ++i) {
		if (push_sk_array[i].monitor.uid == netlink_msg->uid) {
			printk("[sk_pid_hook] request_start_monitor_push_sock failed, uid=%u, repeated uid!\n",
			       netlink_msg->uid);
			return -EAGAIN;
		} else if (push_sk_array[i].monitor.uid == 0) {
			array_overflow = false;
			break;
		}
	}
	if (array_overflow || i >= PUSH_SK_ARRAY_LEN) {
		printk("[sk_pid_hook] request_start_monitor_push_sock failed, uid=%u, array_overflow!.\n",
		       netlink_msg->uid);
		return -ENOMEM;
	}

	push_sk_array[i].monitor.uid = netlink_msg->uid;
	push_sk_array[i].monitor.beat_msg_len = netlink_msg->beat_msg_len;
	push_sk_array[i].monitor.beat_feature_len = netlink_msg->beat_feature_len;
	push_sk_array[i].monitor.push_feature_len = netlink_msg->push_feature_len;
	memcpy(push_sk_array[i].monitor.beat_feature, (uint8_t *)&netlink_msg->beat_feature, 8);
	memcpy(push_sk_array[i].monitor.push_feature, (uint8_t *)&netlink_msg->push_feature, 8);
	boot_monitor_push_sk = true;

	return 0;
}

/**
 * @brief      The handler of request stop monitor push sock from user space.
 *
 * @param      nla   The nla
 *
 * @return     0 if successful, negative otherwise.
 */
static int request_stop_monitor_push_sock(struct nlattr *nla)
{
	int i = 0;
	int ret = 0;
	bool match = false;
	bool clean = true;
	char msg_buf[sizeof(netlink_unsol_monitor_push_sk_struct)] = { 0 };
	netlink_unsol_monitor_push_sk_struct *unsol_msg = (netlink_unsol_monitor_push_sk_struct *)msg_buf;
	netlink_dl_uid_struct *netlink_msg = (netlink_dl_uid_struct *)NLA_DATA(nla);

	memset(msg_buf, 0x0, sizeof(msg_buf));

	for (i = 0; i < PUSH_SK_ARRAY_LEN; ++i) {
		if (push_sk_array[i].monitor.uid == netlink_msg->uid) {
			match = true;
			break;
		}
	}

	if (match && i < PUSH_SK_ARRAY_LEN) {
		unsol_msg->uid = push_sk_array[i].monitor.uid;
		unsol_msg->pid = push_sk_array[i].pid;
		unsol_msg->type = UNSOL_PUSH_SOCK_TYPE_STOP;
		unsol_msg->beat_count = push_sk_array[i].beat_count;
		unsol_msg->push_count = push_sk_array[i].push_count;

		ret = netlink_send_to_user(NETLINK_UNSOL_MONITOR_PUSH_SOCK, (char *)msg_buf, sizeof(msg_buf));
		if (ret < 0) {
			printk("[sk_pid_hook] request_stop_monitor_push_sock failed, netlink_send_to_user ret=%d.\n", ret);
		}
		memset(&push_sk_array[i], 0x0, sizeof(monitor_push_sk_struct));
		for (i = 0; i < PUSH_SK_ARRAY_LEN; ++i) {
			if (push_sk_array[i].monitor.uid != 0) {
				clean = false;
			}
		}
		if (clean) {
			boot_monitor_push_sk = false;
		}
		return ret;
	} else {
		printk("[sk_pid_hook] request_stop_monitor_push_sock failed, uid=%u not match!\n", netlink_msg->uid);
		return -ENODEV;
	}
}

/**
 * @brief      The handler of request monitor sk connect from user space.
 *
 * @param      nla   The nla
 *
 * @return     0 if successful, negative otherwise.
 */
static int request_monitor_skconnect(struct nlattr *nla)
{
	int i = 0;
	bool array_overflow = true;
	netlink_dl_proc_struct *netlink_msg = (netlink_dl_proc_struct *)NLA_DATA(nla);

	for (i = 0; i < SK_CONNECT_ARRAY_LEN; ++i) {
		if (sk_connect_array[i].proc.uid == netlink_msg->uid
		        && sk_connect_array[i].proc.pid == netlink_msg->pid) {
			printk("[sk_pid_hook] request_monitor_skconnect failed, uid=%u pid=%u, repeated uid!\n",
			       netlink_msg->uid, netlink_msg->pid);
			return -EAGAIN;
		} else if (sk_connect_array[i].proc.uid == 0) {
			array_overflow = false;
			break;
		}
	}
	if (array_overflow || i >= SK_CONNECT_ARRAY_LEN) {
		printk("[sk_pid_hook] request_monitor_skconnect failed, uid=%u pid=%u, array_overflow!.\n",
		       netlink_msg->uid, netlink_msg->pid);
		return -ENOMEM;
	}

	sk_connect_array[i].proc.uid = netlink_msg->uid;
	sk_connect_array[i].proc.pid = netlink_msg->pid;
	sk_connect_deadline_array[i] = current_kernel_time() + SKCONNECT_INFO_MONITOR_TIME;
	boot_monitor_sk_connect = true;

	return 0;
}

/**
 * @brief      The handler of request sk connect info from user space.
 *
 * @return     0 if successful, negative otherwise.
 */
static int request_skconnect_info(void)
{
	int ret = 0;
	char msg_buf[sizeof(netlink_ul_sk_connect_info_struct) * SK_CONNECT_ARRAY_LEN] = { 0 };

	memcpy(msg_buf, sk_connect_array, sizeof(netlink_ul_sk_connect_info_struct) * SK_CONNECT_ARRAY_LEN);
	memset(sk_connect_array, 0x0, sizeof(netlink_ul_sk_connect_info_struct) * SK_CONNECT_ARRAY_LEN);
	memset(sk_connect_deadline_array, 0x0, sizeof(sk_connect_deadline_array));
	boot_monitor_sk_connect = false;

	ret = netlink_send_to_user(NETLINK_RESPONSE_SKCONNECT_INFO, (char *)msg_buf, sizeof(msg_buf));
	if (ret < 0) {
		printk("[sk_pid_hook] request_skconnect_info failed, netlink_send_to_user ret=%d.\n", ret);
	}

	return ret;
}

/**
 * @brief      The handler of sk pid hook netlink message from user space.
 *
 * @param      skb   The socket buffer
 * @param      info  The information
 *
 * @return     0 if successful, negative otherwise.
 */
int sk_pid_hook_netlink_nlmsg_handle(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;

	struct nlmsghdr *nlhdr;
	struct genlmsghdr *genlhdr;
	struct nlattr *nla;

	nlhdr = nlmsg_hdr(skb);
	genlhdr = nlmsg_data(nlhdr);
	nla = genlmsg_data(genlhdr);

	switch (nla->nla_type) {
	case NETLINK_REQUEST_SK_PORT_AND_PID:
		ret = request_sk_port_and_pid();
		break;
	case NETLINK_REQUEST_CLOSE_SK_FOR_PROC:
		ret = request_close_sk_for_proc(nla);
		break;
	case NETLINK_REQUEST_START_MONITOR_PUSH_SOCK:
		ret = request_start_monitor_push_sock(nla);
		break;
	case NETLINK_REQUEST_STOP_MONITOR_PUSH_SOCK:
		ret = request_stop_monitor_push_sock(nla);
		break;
	case NETLINK_REQUEST_MONITOR_SKCONNECT:
		ret = request_monitor_skconnect(nla);
		break;
	case NETLINK_REQUEST_SKCONNECT_INFO:
		ret = request_skconnect_info();
		break;
	default:
		printk("[sk_pid_hook] sk_pid_hook_netlink_nlmsg_handle failed, unknown nla type=%d.\n", nla->nla_type);
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * @brief      Initialize sk pid hook.
 *
 * @return     0 if successful, negative otherwise.
 */
int sk_pid_hook_init(void)
{
	int ret = 0;

	ret = register_kprobe(&kp_tcp_connect);
	if (ret < 0) {
		printk("[sk_pid_hook] register tcp connect kprobe failed with %d", ret);
		return ret;
	}

	ret = nf_register_net_hooks(&init_net, my_nf_hook_ops, ARRAY_SIZE(my_nf_hook_ops));
	if (ret < 0) {
		printk("[sk_pid_hook] module failed to init netfilter.\n");
		unregister_kprobe(&kp_tcp_connect);
		return ret;
	}

	memset(sprot_pid_array, 0x0, sizeof(netlink_ul_sport_pid_struct) * SPORT_PID_ARRAY_LEN);
	memset(destroy_sk_array, 0x0, sizeof(sk_info_struct) * DESTROY_SK_ARRAY_LEN);
	memset(push_sk_array, 0x0, sizeof(monitor_push_sk_struct) * PUSH_SK_ARRAY_LEN);
	memset(sk_connect_array, 0x0, sizeof(netlink_ul_sk_connect_info_struct) * SK_CONNECT_ARRAY_LEN);
	memset(sk_connect_deadline_array, 0x0, sizeof(sk_connect_deadline_array));

	printk("[sk_pid_hook] module init successfully!");

	return 0;
}

/**
 * @brief      Uninstall sk pid hook.
 */
void sk_pid_hook_fini(void)
{
	unregister_kprobe(&kp_tcp_connect);
	nf_unregister_net_hooks(&init_net, my_nf_hook_ops, ARRAY_SIZE(my_nf_hook_ops));
}
