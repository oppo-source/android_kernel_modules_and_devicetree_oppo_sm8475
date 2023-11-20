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
#include "oplus_bbr.h"
#include "oplus_tcp_congest_control.h"

#define BBR_UID_MAX_NUM 10
#define DAFAULT_MTU 1400
#define INVALID_LINK_TYPE -1
#define LINK_TYPE_MAX 2
#define STAT_PACKET_PERIOD 4000

struct tcp_bbr_stat_info_st
{
	u32 link_type;		//0:wifi,1:data
	int is_use_bbr;
	int count;
	int srtt;			//ms
	int lost_rate;		//lost rate * 10000
	u64 rate;			//kbit/s
};

struct tcp_bbr_stat_report_st
{
	int wifi_use_bbr;
	int wifi_lost_rate;
	int wifi_srtt;
	int wifi_count;
	u64 wifi_rate;
	int data_use_bbr;
	int data_lost_rate;
	int data_srtt;
	int data_count;
	u64 data_rate;
};

static u32 s_oplus_tcp_congest_control_enable = OPLUS_TRUE;
static u32 s_oplus_tcp_bbr_uid_list[BBR_UID_MAX_NUM];
static spinlock_t s_bbr_lock;
static struct tcp_bbr_stat_info_st s_tcp_bbr_stat_info[LINK_TYPE_MAX];
static u32 s_bbr_stat_uid = 0;
static u32 bbr_enable_all_app = 0;
static struct ctl_table_header *oplus_tcp_congest_table_hrd = NULL;

static inline int is_bbr_list_uid(unsigned int uid)
{
	int i;

	spin_lock_bh(&s_bbr_lock);
	for (i = 0; i < BBR_UID_MAX_NUM; i++) {
		if (uid == s_oplus_tcp_bbr_uid_list[i]) {
			spin_unlock_bh(&s_bbr_lock);
			return OPLUS_TRUE;
		}
	}

	spin_unlock_bh(&s_bbr_lock);
	return OPLUS_FALSE;
}

static int is_set_oplus_bbr(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if(icsk->icsk_ca_ops == 0) {
		return OPLUS_FALSE;
	}

	if (strcmp(icsk->icsk_ca_ops->name, "oplus_bbr") == 0) {
		return OPLUS_TRUE;
	} else {
		return OPLUS_FALSE;
	}
}

static void try_set_oplus_bbr(struct sock *sk, struct sk_buff *skb)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);

	if (is_set_oplus_bbr(sk)) {
		return;
	}

	if (icsk->icsk_ca_ops) {
		if (icsk->icsk_ca_ops->release) {
			icsk->icsk_ca_ops->release(sk);
		}
		module_put(icsk->icsk_ca_ops->owner);
	}

	icsk->icsk_ca_ops = oplus_get_bbr_cong_ops();
	memset(icsk->icsk_ca_priv, 0, sizeof(icsk->icsk_ca_priv));
	if (!((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN))) {
		tcp_sk(sk)->prior_ssthresh = 0;
		if (icsk->icsk_ca_ops->init) {
			icsk->icsk_ca_ops->init(sk);
		}
		icsk->icsk_ca_initialized = 1;
		printk(LOG_TAG "set oplus_bbr success,sk=%p,uid=%u,segout=%u,sport=%u,dport=%u,state=%u\n",
			sk, sk->sk_uid.val, tp->segs_out, htons(inet->inet_sport), htons(inet->inet_dport),
			sk->sk_state);
	}
}

static int get_link_type(struct sk_buff *skb)
{
	if (skb->dev) {
		if (strncmp(skb->dev->name, "wlan", 4) == 0) {
			return 0;
		} else {
			return 1;
		}
	}

	return INVALID_LINK_TYPE;
}

static u64 oplus_tcp_compute_delivery_rate(struct tcp_sock *tp)
{
	u32 rate = READ_ONCE(tp->rate_delivered);
	u32 intv = READ_ONCE(tp->rate_interval_us);
	u64 rate64 = 0;

	if (rate && intv) {
		rate64 = (u64)rate * tp->mss_cache * USEC_PER_SEC;
		do_div(rate64, intv);
	}
	return rate64;
}

static void try_update_tcp_bbr_stat_info(struct sock *sk, u32 uid, struct sk_buff *skb)
{
	int link_type;
	struct tcp_sock *tp = tcp_sk(sk);
	u32 m_rtt;   //ms
	u32 m_lost_rate;
	u64 m_rate;  //kbis/s
	u32 count = 0;
	int is_use_bbr;

	if(uid != s_bbr_stat_uid) {
		return;
	}

	if (tp->segs_out == 0) {
		printk(LOG_TAG "segs_out=%u\n", tp->segs_out);
		return;
	}

	if ((tp->segs_out % STAT_PACKET_PERIOD) != 0) {
		return;
	}

	link_type = get_link_type(skb);
	if (link_type == INVALID_LINK_TYPE) {
		return;
	}

	is_use_bbr = is_set_oplus_bbr(sk);
	m_rtt = (tp->srtt_us >> 3) / 1000;
	m_lost_rate = tp->lost * 10000 / tp->segs_out;
	m_rate = oplus_tcp_compute_delivery_rate(tp) * 8 / 1000;

	printk(LOG_TAG "stat_sample:sk=%p,mrtt=%u,m_lost_rate=%u,m_rate=%llu,link_type=%u,seq_out=%u,app_limited=%u32\n",
		sk, m_rtt, m_lost_rate, m_rate, link_type, tp->segs_out, tp->app_limited);

	spin_lock_bh(&s_bbr_lock);
	count = s_tcp_bbr_stat_info[link_type].count;
	s_tcp_bbr_stat_info[link_type].srtt = (s_tcp_bbr_stat_info[link_type].srtt * count + m_rtt) / (count + 1);
	s_tcp_bbr_stat_info[link_type].lost_rate = (s_tcp_bbr_stat_info[link_type].lost_rate * count + m_lost_rate) / (count + 1);
	s_tcp_bbr_stat_info[link_type].rate = (s_tcp_bbr_stat_info[link_type].rate * count + m_rate) / (count + 1);
	s_tcp_bbr_stat_info[link_type].count++;
	s_tcp_bbr_stat_info[link_type].is_use_bbr = is_use_bbr;
	s_tcp_bbr_stat_info[link_type].link_type = link_type;
	printk(LOG_TAG "stat_info:sk=%p,srtt=%u,lost_rate=%u,rate=%llu,link_type=%u,count=%u\n",
		sk, s_tcp_bbr_stat_info[link_type].srtt, s_tcp_bbr_stat_info[link_type].lost_rate,
		s_tcp_bbr_stat_info[link_type].rate, link_type, s_tcp_bbr_stat_info[link_type].count);
	spin_unlock_bh(&s_bbr_lock);
}

void tcp_congest_control_post_routing_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	uid_t sk_uid;
	struct sock *sk;

	sk = skb_to_full_sk(skb);
	if (!sk) {
		return;
	}

	sk_uid = get_uid_from_sock(sk);
	if (!is_bbr_list_uid(sk_uid) && !bbr_enable_all_app) {
		return;
	}

	if (((sk->sk_state == TCP_SYN_SENT) || (sk->sk_state == TCP_ESTABLISHED))
		&& s_oplus_tcp_congest_control_enable) {
		try_set_oplus_bbr(sk, skb);
	}

	if (sk->sk_state == TCP_ESTABLISHED) {
		try_update_tcp_bbr_stat_info(sk, (u32)sk_uid, skb);
	}
	return;
}

void oplus_tcp_congest_control_enable(struct nlattr *nla)
{
	u32 *data = (u32*)NLA_DATA(nla);
	s_oplus_tcp_congest_control_enable = data[0];
	printk(LOG_TAG "oplus_tcp_congest_control_enable = %u", s_oplus_tcp_congest_control_enable);
}

void oplus_tcp_congest_control_set_bbr_uid(struct nlattr *nla)
{
	u32 *data;
	int i, num;

	data = (u32 *)NLA_DATA(nla);
	num = data[0];
	if (num <= 0 || num > BBR_UID_MAX_NUM) {
		printk(LOG_TAG "bbr uid num out of range, num = %d", num);
		return;
	}

	spin_lock_bh(&s_bbr_lock);
	memset(s_oplus_tcp_bbr_uid_list, 0, sizeof(s_oplus_tcp_bbr_uid_list));
	for (i = 0; i < num; i++) {
		s_oplus_tcp_bbr_uid_list[i] = data[i + 1];
		printk(LOG_TAG "update bbr_uid, num = %d, index = %d, uid=%u\n", num, i, data[i + 1]);
	}
	spin_unlock_bh(&s_bbr_lock);
}

void oplus_tcp_congest_control_set_bbr_stat_uid(struct nlattr *nla)
{
	s_bbr_stat_uid = *((u32 *)NLA_DATA(nla));
	printk(LOG_TAG "s_bbr_stat_uid = %u\n", s_bbr_stat_uid);
}

void oplus_tcp_congest_control_request_report(struct nlattr *nla)
{
	struct tcp_bbr_stat_report_st tcp_bbr_stat;

	printk(LOG_TAG "enter oplus_tcp_congest_control_request_report!\n");
	spin_lock_bh(&s_bbr_lock);
	tcp_bbr_stat.wifi_use_bbr = s_tcp_bbr_stat_info[0].is_use_bbr;
	tcp_bbr_stat.wifi_count = s_tcp_bbr_stat_info[0].count;
	tcp_bbr_stat.wifi_srtt = s_tcp_bbr_stat_info[0].srtt;
	tcp_bbr_stat.wifi_lost_rate = s_tcp_bbr_stat_info[0].lost_rate;
	tcp_bbr_stat.wifi_rate = s_tcp_bbr_stat_info[0].rate;
	tcp_bbr_stat.data_use_bbr = s_tcp_bbr_stat_info[1].is_use_bbr;
	tcp_bbr_stat.data_count = s_tcp_bbr_stat_info[1].count;
	tcp_bbr_stat.data_srtt = s_tcp_bbr_stat_info[1].srtt;
	tcp_bbr_stat.data_lost_rate = s_tcp_bbr_stat_info[1].lost_rate;
	tcp_bbr_stat.data_rate = s_tcp_bbr_stat_info[1].rate;
	memset((void*)&s_tcp_bbr_stat_info, 0,  sizeof(struct tcp_bbr_stat_info_st) * LINK_TYPE_MAX);
	spin_unlock_bh(&s_bbr_lock);

	printk(LOG_TAG "w_srtt=%u,w_lost_rate=%u,w_rate=%llu,d_srtt=%u,d_lost_rate=%u,d_rate=%llu\n",
			tcp_bbr_stat.wifi_srtt,tcp_bbr_stat.wifi_lost_rate,tcp_bbr_stat.wifi_rate,
			tcp_bbr_stat.data_srtt,tcp_bbr_stat.data_lost_rate,tcp_bbr_stat.data_rate);
	oplus_network_tuning_send_netlink_msg(OPLUS_TUNING_MSG_TCP_BBR_INFO_REPORT, (char *)&tcp_bbr_stat, sizeof(tcp_bbr_stat));
}

static struct ctl_table oplus_tcp_congest_sysctl_table[] =
{
	{
		.procname	= "bbr_enable_all_app",
		.data		= &bbr_enable_all_app,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "s_oplus_tcp_congest_control_enable",
		.data		= &s_oplus_tcp_congest_control_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{}
};

int oplus_tcp_congest_control_init(void)
{
	s_oplus_tcp_congest_control_enable = OPLUS_FALSE;
	memset((void*)&s_oplus_tcp_bbr_uid_list, 0, sizeof(u32) * BBR_UID_MAX_NUM);
	spin_lock_init(&s_bbr_lock);
	memset((void*)&s_tcp_bbr_stat_info, 0,  sizeof(struct tcp_bbr_stat_info_st) * LINK_TYPE_MAX);
	if(oplus_bbr_register()) {
		printk("oplus_bbr_register success!");
		return -1;
	}

	oplus_tcp_congest_table_hrd = register_net_sysctl(&init_net, "net/oplus_bbr", oplus_tcp_congest_sysctl_table);
	if (oplus_tcp_congest_table_hrd == NULL) {
		printk("register oplus_tcp_congest_table_hrd fail!");
	}
	return 0;
}


void oplus_tcp_congest_control_fini(void)
{
	oplus_bbr_unregister();
	if (oplus_tcp_congest_table_hrd) {
		unregister_net_sysctl_table(oplus_tcp_congest_table_hrd);
		oplus_tcp_congest_table_hrd = 0;
	}
}
