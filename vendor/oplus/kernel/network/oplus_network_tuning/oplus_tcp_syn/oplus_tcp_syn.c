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
#include "../oplus_kernel_common/oplus_kernel_common.h"
#include "oplus_tcp_syn.h"

#define TCP_SYN_DATA_SIZE 8
#define FOREGROUND_UID_MAX_NUM 10

static int s_oplus_tuning_tcpsyn_enable_flag = 0;
static u32 s_tcp_syn_retransmission[TCP_SYN_DATA_SIZE];
static u32 s_oplus_tuning_tcpsyn_foreground_uid[FOREGROUND_UID_MAX_NUM];
static u32 tcp_syn_enable_test = 10;

static inline __u32 reset_syn_timeout(struct inet_connection_sock *icsk) {
	int timer = -1;
	switch (icsk->icsk_retransmits) {
		case 0:
			timer = (1 * HZ);
			break;
		case 1:
			timer = (1 * HZ);
			break;
		case 2:
			timer = (1 * HZ);
			break;
		case 3:
			timer = (2 * HZ);
			break;
		case 4:
			timer = (4 * HZ);
			break;
		case 5:
			timer = (4 * HZ);
			break;
		default:
			timer = (4 * HZ);
	}
	return timer;
}

static inline void try_reset_syn_timer(struct sk_buff *skb) {
	struct tcphdr *tcph = NULL;
	struct sock *sk;
	struct inet_connection_sock *icsk;

	tcph = tcp_hdr(skb);
	sk = skb->sk;
	icsk = inet_csk(sk);

	if ((tcph == NULL) || (sk == NULL) || (icsk == NULL)) {
		return;
	}

	/* it is only syn packet */
	if ((tcph->syn == 1) && (tcph->ack == 0)) {
		if (net_ratelimit()) {
			printk("before change: sk = %p, rto = %d, timeout = %ld, syn_backoff = %d, retry = %d, icsk_retransmits = %d\n",
			sk, icsk->icsk_rto, icsk->icsk_timeout, icsk->icsk_backoff,
			icsk->icsk_ack.retry, icsk->icsk_retransmits);
		}

		icsk->icsk_rto = reset_syn_timeout(icsk);
		if (net_ratelimit()) {
			printk("after  change: sk = %p, rto = %d, timeout = %ld, syn_backoff = %d, retry = %d, icsk_retransmits = %d\n",
			sk, icsk->icsk_rto, icsk->icsk_timeout, icsk->icsk_backoff,
			icsk->icsk_ack.retry, icsk->icsk_retransmits);
		}
	}
}

static inline void __tcp_syn_freq_report(struct sk_buff *skb) {
	struct tcphdr *tcph = NULL;
	struct sock *sk;
	struct inet_connection_sock *icsk;

	tcph = tcp_hdr(skb);
	sk = skb->sk;
	icsk = inet_csk(sk);

	if ((tcph == NULL) || (sk == NULL) || (icsk == NULL)) {
		return;
	}

	/* state is TCP_SYN_SENT, receive syn-ack packet, state will convert established. */
	if ((sk->sk_state == TCP_SYN_SENT) && (tcph->syn == 1) && (tcph->ack == 1)) {
		if (net_ratelimit()) {
			printk("tcp connect successful in :%d\n", icsk->icsk_retransmits);
		}
		/* if some people change syn retransmission more than 8, remove if statement, it will out of range array*/
		if (icsk->icsk_retransmits < TCP_SYN_DATA_SIZE) {
			s_tcp_syn_retransmission[icsk->icsk_retransmits]++;
		}
	}
}

static inline int is_foreground_uid(int uid) {
	int i;
	for (i = 0; i < FOREGROUND_UID_MAX_NUM; i++) {
		if (uid == s_oplus_tuning_tcpsyn_foreground_uid[i]) {
			return OPLUS_TRUE;
		}
	}
	return OPLUS_FALSE;
}

void tcp_syn_report(void *priv, struct sk_buff *skb,
	const struct nf_hook_state *state) {
	uid_t sk_uid;
	struct sock *sk;

	if (!s_oplus_tuning_tcpsyn_enable_flag) {
		return;
	}

	sk = skb_to_full_sk(skb);
	if (!sk) {
		return;
	}

	sk_uid = get_uid_from_sock(sk);
	if (!is_foreground_uid(sk_uid)) {
		return;
	}

	__tcp_syn_freq_report(skb);
}

void tcp_syn_hook(void *priv, struct sk_buff *skb,
	const struct nf_hook_state *state) {
	uid_t sk_uid;
	struct sock *sk;
	struct tcphdr *tcph = tcp_hdr(skb);

	if (!s_oplus_tuning_tcpsyn_enable_flag) {
		return;
	}

	sk = skb_to_full_sk(skb);
	if (!sk) {
		return;
	}

	if (!tcph || !(tcph->syn)) {
		return;
	}

	if (sk->sk_state != TCP_SYN_SENT) {
		return;
	}

	sk_uid = get_uid_from_sock(sk);
	if (!is_foreground_uid(sk_uid)) {
		return;
	}

	try_reset_syn_timer(skb);

	return;
}

void oplus_tuning_tcpsyn_enable(struct nlattr *nla) {
	u32 *data = (u32 *) NLA_DATA(nla);
	s_oplus_tuning_tcpsyn_enable_flag = data[0];
	logt("oplus_tuning_tcpsyn_enable_flag = %u", s_oplus_tuning_tcpsyn_enable_flag);
}

void oplus_tuning_tcpsyn_set_foreground_uid(struct nlattr *nla) {
	u32 *data;
	int i, num;

	data = (u32 *) NLA_DATA(nla);
	num = data[0];
	if (num <= 0 || num > FOREGROUND_UID_MAX_NUM) {
		logt("foreground uid num out of range, num = %d", num);
		return;
	}

	memset(s_oplus_tuning_tcpsyn_foreground_uid, 0,
		   sizeof(s_oplus_tuning_tcpsyn_foreground_uid));
	for (i = 0; i < num; i++) {
		s_oplus_tuning_tcpsyn_foreground_uid[i] = data[i + 1];
		logt("add tcpsyn uid, num = %d, index = %d, uid=%u\n", num, i,
			 data[i + 1]);
	}
}

void oplus_tuning_tcpsyn_request_report(struct nlattr *nla) {
	int i;
	oplus_network_tuning_send_netlink_msg(OPLUS_TUNING_MSG_TCPSYN_INFO_REPORT, (char *) s_tcp_syn_retransmission, sizeof(s_tcp_syn_retransmission));

	for(i = 0; i < TCP_SYN_DATA_SIZE; i++) {
		logt("report: syn_build_freq[%d] = %d\n", i, s_tcp_syn_retransmission[i]);
	}
	memset(s_tcp_syn_retransmission, 0, sizeof(s_tcp_syn_retransmission));
}

static struct ctl_table_header *oplus_bbr_table_hrd = NULL;
static struct ctl_table oplus_bbr_sysctl_table[] =
{
	{
		.procname	= "tcp_syn_enable_test",
		.data		= &tcp_syn_enable_test,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{}
};

int oplus_tuning_tcpsyn_init(void) {
	s_oplus_tuning_tcpsyn_enable_flag = 1;
	memset(s_oplus_tuning_tcpsyn_foreground_uid, 0, sizeof(s_oplus_tuning_tcpsyn_foreground_uid));
	memset(s_tcp_syn_retransmission, 0, sizeof(s_tcp_syn_retransmission));

	oplus_bbr_table_hrd = register_net_sysctl(&init_net, "net/oplus_bbr", oplus_bbr_sysctl_table);
	if (oplus_bbr_table_hrd == NULL) {
		printk("register oplus_bbr_sysctl_table error!\n");
		return -1;
	}
	return 0;
}

void oplus_tuning_tcpsyn_fini(void) {
	if (oplus_bbr_table_hrd) {
		unregister_net_sysctl_table(oplus_bbr_table_hrd);
		oplus_bbr_table_hrd = NULL;
	}
}
