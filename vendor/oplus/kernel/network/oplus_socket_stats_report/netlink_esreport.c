#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <net/sock.h>
#include "netlink_es.h"
#include <net/netfilter/nf_conntrack.h>
#include <linux/netlink.h>
#include <net/genetlink.h>

#define LOG_TAG "netlink_esreport"

static int s_debug = 0;

#define LOGK(flag, fmt, args...)     \
    do {                             \
        if (flag || s_debug) {       \
            printk("[%s]:" fmt "\n", LOG_TAG, ##args);\
        }                                             \
    } while (0)

static u32 s_esreport_user_pid = 0;
static int s_esreport_enable_flag = 0;

#define MAX_REPORT_IP_TRIPLES_COUNT 1000

static ip_triple oplus_esreport_ip_triples[MAX_REPORT_IP_TRIPLES_COUNT];
static int s_ip_triples_count = 0;

static int es_nl_msglen(int msgtype)
{
	int ret = 0;
#if 0

	switch (msgtype) {
	case ES_NL_MSG_TCP_ESTABLISH:
		ret = sizeof(struct es_nl_msg_tcp_establish);
		break;

	case ES_NL_MSG_UDP_ESTABLISH:
		ret = sizeof(struct es_nl_msg_udp_establish);
		break;

	default:
		break;
	}
#else
    ret = sizeof(es_nl_msg_establish);
#endif
	return ret;
}

static inline int genl_msg_mk_usr_msg(struct sk_buff *skb, int type, void *data, int len)
{
	int ret;

	/* add a netlink attribute to a socket buffer */
	if ((ret = nla_put(skb, type, len, data)) != 0) {
		LOGK(1, "nla_put %d", ret);
		return ret;
	}

	return 0;
}

static int esreport_netlink_rcv_msg(struct sk_buff *skb, struct genl_info *info);
static const struct genl_ops esreport_genl_ops[] =
{
	{
		.cmd = ESREPORT_CMD_DOWN,
		.flags = 0,
		.doit = esreport_netlink_rcv_msg,
		.dumpit = NULL,
	},
};

static struct genl_family esreport_genl_family =
{
	.id = 0,
	.hdrsize = 0,
	.name = ESREPORT_FAMILY_NAME,
	.version = ESREPORT_FAMILY_VERSION,
	.maxattr = ES_NL_MSG_MAX,
	.ops = esreport_genl_ops,
	.n_ops = ARRAY_SIZE(esreport_genl_ops),
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
	//netlink的头部数据：pid, sequence, family_id, family->hdrsize+GENL_HDRLEN, flags
	genlmsg_put(skb, pid, 0, &esreport_genl_family, 0, cmd);
	LOGK(1, "genl_msg_prepare_usr_msg_1,skb_len=%u,pid=%u,cmd=%u,id=%u\n",
	skb->len, (unsigned int)pid, cmd, esreport_genl_family.id);
	*skbp = skb;
	return 0;
}

/* send to user space */
static int esreport_send_netlink_msg(int msg_type, char *payload, int payload_len)
{
	int ret = 0;
	void * head;
	struct sk_buff *skbuff;
	size_t size;

	if (!s_esreport_user_pid) {
		LOGK(1, "s_esreport_user_pid=0\n");
		return -1;
	}

	/* allocate new buffer cache */
	size = nla_total_size(payload_len);
	ret = genl_msg_prepare_usr_msg(ESREPORT_CMD_DOWN, size, s_esreport_user_pid, &skbuff);
	if (ret) {
		LOGK(1, "genl_msg_prepare_usr_msg %d", ret);
		return ret;
	}

	ret = genl_msg_mk_usr_msg(skbuff, msg_type, payload, payload_len);
	if (ret) {
		kfree_skb(skbuff);
		LOGK(1, "genl_msg_mk_usr_msg %d", ret);
		return ret;
	}

	head = genlmsg_data(nlmsg_data(nlmsg_hdr(skbuff)));
	genlmsg_end(skbuff, head);

	/* send data */
	ret = genlmsg_unicast(&init_net, skbuff, s_esreport_user_pid);
	if(ret < 0) {
		LOGK(1, "esreport_send_netlink_msg error, ret = %d\n", ret);
		return -1;
	}

	return 0;
}

static int es_netlink_event(/* struct notifier_block *this, */unsigned long event, void *ptr)
{

	switch (event) {
        case TCP_ESTABLISH_EVENT:
               LOGK(1, "es_netlink_event: receive tcp establish event, notify----");
			   esreport_send_netlink_msg(ES_NL_MSG_TCP_ESTABLISH, ptr, es_nl_msglen(ES_NL_MSG_TCP_ESTABLISH));
		break;
		case UDP_ESTABLISH_EVENT:
			   LOGK(1, "es_netlink_event: receive udp establish event, notify----");
			   esreport_send_netlink_msg(ES_NL_MSG_UDP_ESTABLISH, ptr, es_nl_msglen(ES_NL_MSG_UDP_ESTABLISH));
		break;
        case TCP_CLOSE_EVENT:
               LOGK(1, "es_netlink_event: receive tcp close event, notify----");
			   esreport_send_netlink_msg(ES_NL_MSG_TCP_CLOSE, ptr, es_nl_msglen(ES_NL_MSG_TCP_CLOSE));
		break;
		case UDP_CLOSE_EVENT:
			   esreport_send_netlink_msg(ES_NL_MSG_UDP_CLOSE, ptr, es_nl_msglen(ES_NL_MSG_UDP_CLOSE));
			   LOGK(1, "es_netlink_event: receive udp close event, notify----");
		break;
#if IS_ENABLED(CONFIG_IPV6)
	    case TCP6_ESTABLISH_EVENT:
               LOGK(1, "es_netlink_event: receive tcp6 establish event, notify----");
			   esreport_send_netlink_msg(ES_NL_MSG_TCP6_ESTABLISH, ptr, es_nl_msglen(ES_NL_MSG_TCP6_ESTABLISH));
		break;
		case UDP6_ESTABLISH_EVENT:
			   LOGK(1, "es_netlink_event: receive udp6 establish event, notify----");
			   esreport_send_netlink_msg(ES_NL_MSG_UDP6_ESTABLISH, ptr, es_nl_msglen(ES_NL_MSG_UDP6_ESTABLISH));
		break;
        case TCP6_CLOSE_EVENT:
               LOGK(1, "es_netlink_event: receive tcp6 close event, notify----");
			   esreport_send_netlink_msg(ES_NL_MSG_TCP6_CLOSE, ptr, es_nl_msglen(ES_NL_MSG_TCP6_CLOSE));
		break;
		case UDP6_CLOSE_EVENT:
			   LOGK(1, "es_netlink_event: receive udp6 close event, notify----");
			   esreport_send_netlink_msg(ES_NL_MSG_UDP6_CLOSE, ptr, es_nl_msglen(ES_NL_MSG_UDP6_CLOSE));
		break;
#endif
	default:
	    LOGK(1, "es_netlink_event: Receive event %u Invalid\n" ,event);
		break;
	}
	return 0;
}

int if_es_filter_open(int etype)
{
    return 1;//filter_info.flag & flag;
}
EXPORT_SYMBOL(if_es_filter_open);

// d_ipv4: big endian server ip
void establish_notify(int ip_protocol, uint32_t d_ipv4, uint8_t d_ipv6[16], uint16_t d_port,
                        uint32_t s_ipv4, uint8_t s_ipv6[16], uint16_t s_port, uint16_t proto, int etype)
{
    LOGK(1, "establish_notify begin");
    if(if_es_filter_open(etype))
    {
        int event = etype;
		es_nl_msg_establish msg={0};

		if(ip_protocol == NFPROTO_IPV4)
        {
            LOGK(1, "establish_notify NFPROTO_IPV4");
        } else if(ip_protocol == NFPROTO_IPV6) {
            LOGK(1, "establish_notify NFPROTO_IPV6");
        }

        LOGK(1, "establish_notify 1");
		msg.event =event;
		msg.s_port = s_port;
		msg.d_port = d_port;
		msg.protocol = proto;
        LOGK(1, "establish_notify msg event %d, s_port %d, d_port %d, protocol %d", msg.event, msg.s_port, msg.d_port, msg.protocol);

        if(ip_protocol == NFPROTO_IPV4)
		{
	        char *evet_str[]={"NULL","NULL","TCP_ESTABLISH","UDP_ESTABLISH","TCP_CLOSE","UDP_CLOSE"};
	        unsigned char *saddr = (unsigned char *)&(s_ipv4);
	        unsigned char *daddr = (unsigned char *)&(d_ipv4);
            msg.s_addr = s_ipv4;
			msg.d_addr = d_ipv4;
	        LOGK(1, "Alicia : ---esnotify:(%x)--------%s establish notify (%d.%d.%d.%d:%d ---->%d.%d.%d.%d:%d) uid=%u protocol=%d\n"
                ,ip_protocol,evet_str[event],
                saddr[0],saddr[1],saddr[2],saddr[3],msg.s_port,
                daddr[0],daddr[1],daddr[2],daddr[3],msg.d_port,
                msg.uid,msg.protocol);
			es_netlink_event(event,&msg);
	    }
#if IS_ENABLED(CONFIG_IPV6)
		else if(ip_protocol == NFPROTO_IPV6)
		{
	        char *evet_str[]={"NULL","NULL","TCP6_ESTABLISH","UDP6_ESTABLISH","TCP6_CLOSE","UDP6_CLOSE"};
	        unsigned short *saddr = (unsigned short *)s_ipv6;
	        unsigned short *daddr = (unsigned short *)d_ipv6;
		    memcpy(msg.s_addr6,s_ipv6,sizeof(msg.s_addr6));
		    memcpy(msg.d_addr6,d_ipv6,sizeof(msg.d_addr6));
            // todo: 考虑下大小端的问题
            LOGK(1, "Alicia : ---esnotify:(%x)--------%s establish notify (%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x-%d ---->%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x-%d) uid=%u protocol=%d\n",
            ip_protocol,evet_str[event &0x0f],
            saddr[0],saddr[1],saddr[2],saddr[3],saddr[4],saddr[5],saddr[6],saddr[7],msg.s_port,
            daddr[0],daddr[1],daddr[2],daddr[3],daddr[4],daddr[5],daddr[6],daddr[7],msg.d_port,
            msg.uid,msg.protocol);

            es_netlink_event(event,&msg);
	    }
#endif
        else {
            LOGK(1, "establish_notify event error!");
        }
    }
}

EXPORT_SYMBOL(establish_notify);

// addr6 little endian, d_addr6 big endian
// equal return 1
static int addr6_little_meet_big_endian(uint8_t addr6[16], uint8_t d_addr6_big_endian[16]) {
    int i;
    for (i = 0; i < 16; i++) {
        if (addr6[i] != d_addr6_big_endian[15-i]) {
            return 0;
        }
    }
    return 1;
}

static int port_meet(ip_triple it, uint32_t dport) {
    if ((dport == it.port) || (it.port == 0 && it.start_port == 0 && it.end_port == 0) || (it.port == 0 && it.start_port <= dport && it.end_port >= dport)) {
        return 1;
    }
    return 0;
}

static unsigned int oplus_esreport_output_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	struct sock *sk;
	const struct iphdr *iph = NULL;
    const struct ipv6hdr *ipv6h = NULL;
	struct nf_conn *ct = NULL;
	enum ip_conntrack_info ctinfo;
    int if_match = 0;
	const struct tcphdr *th = NULL;
	const struct udphdr *uh = NULL;
    enum esreport_msg_type_et msg_type;

    uint32_t proto = 0;
    uint32_t dport = 0;
    uint32_t daddr = 0;
    uint8_t daddr6[16] = {0};
    uint32_t sport = 0;
    uint32_t saddr = 0;
    uint8_t saddr6[16] = {0};
    int ip_protocol;
    int i;

    if (state->pf == NFPROTO_IPV4) {
        ip_protocol = NFPROTO_IPV4;
    	iph = ip_hdr(skb);
        if (!iph) {
            return NF_ACCEPT;
        }
        daddr = iph->daddr;
        saddr = iph->saddr;
        if (iph->protocol == IPPROTO_TCP) {
	        proto = IPPROTO_TCP;
        } else if (iph->protocol == IPPROTO_UDP) {
            proto = IPPROTO_UDP;
        } else {
            return NF_ACCEPT;
        }
    } else if (state->pf == NFPROTO_IPV6) {
        ip_protocol = NFPROTO_IPV6;
    	ipv6h = ipv6_hdr(skb);
        if (!ipv6h) {
            return NF_ACCEPT;
        }
        memcpy(daddr6, &ipv6h->daddr, 16);
        memcpy(saddr6, &ipv6h->saddr, 16);
        if (ipv6h->nexthdr == IPPROTO_TCP) {
            proto = IPPROTO_TCP;
        } else if (ipv6h->nexthdr == IPPROTO_UDP) {
            proto = IPPROTO_UDP;
        } else {
            return NF_ACCEPT;
        }
    } else {
        return NF_ACCEPT;
    }

    if (proto == IPPROTO_TCP) {
        th = tcp_hdr(skb);
        if (!th) {
            return NF_ACCEPT;
        }
        dport = ntohs(th->dest);
        sport = ntohs(th->source);
    } else if (proto == IPPROTO_UDP) {
        uh = udp_hdr(skb);
        if (!uh) {
            return NF_ACCEPT;
        }
        dport = ntohs(uh->dest);
        sport = ntohs(uh->source);
    }
	ct = nf_ct_get(skb, &ctinfo);

    // 无论上行还是下行：
    // 服务端的port始终是sk->__sk_common.skc_dport，是大端，需要转化为小端；
    // 客户端的port始终是sk->__sk_common.skc_num，是小端；
    // 服务端的ipv4始终是sk->sk_daddr，是大端，需要转化为小端；
    // 客户端的ipv4始终是sk->sk_rcv_saddr，是大端，需要转化为小端；
    // 服务端的ipv6始终是sk->sk_v6_daddr，是大端，需要转化为小端；
    // 客户端的ipv6始终是sk->sk_v6_rcv_saddr，是大端，需要转化为小端；

    //根据中间件下发的ip三元组数据，判断是否要上报该socket
    for (i = 0; i < s_ip_triples_count; i++) {
        ip_triple it = oplus_esreport_ip_triples[i];
        if (state->pf == NFPROTO_IPV4) {
            if (!daddr || it.addr != ntohl(daddr)) {
                // LOGK(1, "oplus_esreport_output_hook IPV4 not hit ip triple");
                continue;
            }
        } else if (state->pf == NFPROTO_IPV6) {
            if (!addr6_little_meet_big_endian(it.addr6, daddr6)) {
                // LOGK(1, "oplus_esreport_output_hook IPV6 not hit ip triple");
                continue;
            }
        } else {
            // LOGK(1, "oplus_esreport_output_hook is not IPV4 or IPV6");
            return NF_ACCEPT;
        }
        if (port_meet(it, dport) && (!it.proto || it.proto == proto)) {
            if_match = 1;
            break;
        }
    }
    if (!if_match) {
        return NF_ACCEPT;
    }

	//udp且socket为new状态，udp连接
    if (iph != NULL && iph->protocol == IPPROTO_UDP && ctinfo == IP_CT_NEW) {
        if (state->pf == NFPROTO_IPV4) {
            msg_type = UDP_ESTABLISH_EVENT;
        } else if (state->pf == NFPROTO_IPV6) {
            msg_type = UDP6_ESTABLISH_EVENT;
        } else {
            LOGK(1, "oplus_esreport_output_hook NFPROTO ERROR!");
		    return NF_ACCEPT;
        }
    	establish_notify(ip_protocol, daddr, daddr6, dport, saddr, saddr6, sport, proto, msg_type);
		return NF_ACCEPT;
	}

	//syn_sent发SYN，tcp连接
	//time_wait发ACK，tcp断开
	if (iph != NULL && iph->protocol == IPPROTO_TCP && th) {
        if (th->rst) {
            if (state->pf == NFPROTO_IPV4) {
                msg_type = TCP_CLOSE_EVENT;
            } else if (state->pf == NFPROTO_IPV6) {
                msg_type = TCP6_CLOSE_EVENT;
            } else {
                LOGK(1, "oplus_esreport_output_hook TCP RST ERROR!");
                return NF_ACCEPT;
            }
    	    establish_notify(ip_protocol, daddr, daddr6, dport, saddr, saddr6, sport, proto, msg_type);
            return NF_ACCEPT;
        } else {
            sk = skb_to_full_sk(skb);
            if (!sk) {
                LOGK(1, "oplus_esreport_output_hook sk NULL!");
                return NF_ACCEPT;
            }
            switch (sk->sk_state) {
		        case TCP_SYN_SENT:
		        	if (th->syn) {
                        if (state->pf == NFPROTO_IPV4) {
                            msg_type = TCP_ESTABLISH_EVENT;
                        } else if (state->pf == NFPROTO_IPV6) {
                            msg_type = TCP6_ESTABLISH_EVENT;
                        } else {
                            LOGK(1, "oplus_esreport_output_hook TCP_SYN_SENT NFPROTO ERROR!");
		        		    return NF_ACCEPT;
                        }
    	                establish_notify(ip_protocol, daddr, daddr6, dport, saddr, saddr6, sport, proto, msg_type);
		        		return NF_ACCEPT;
		        	}
		        	break;
		        case TCP_TIME_WAIT:
		        	if (th->ack) {
                        LOGK(1, "oplus_esreport_output_hook TCP_TIME_WAIT ack!");
                    } else {
                        LOGK(1, "oplus_esreport_output_hook TCP_TIME_WAIT!");
                    }
                    if (state->pf == NFPROTO_IPV4) {
                        msg_type = TCP_CLOSE_EVENT;
                    } else if(state->pf == NFPROTO_IPV6) {
                        msg_type = TCP6_CLOSE_EVENT;
                    } else {
                        LOGK(1, "oplus_esreport_output_hook TCP_TIME_WAIT NFPROTO ERROR!");
                        return NF_ACCEPT;
                    }
    	            establish_notify(ip_protocol, daddr, daddr6, dport, saddr, saddr6, sport, proto, msg_type);
                    return NF_ACCEPT;
                case TCP_LAST_ACK:
                    if (th->ack) {
                        LOGK(1, "oplus_esreport_output_hook TCP_LAST_ACK ack!");
                    } else {
                        LOGK(1, "oplus_esreport_output_hook TCP_LAST_ACK!");
                    }
                    if (state->pf == NFPROTO_IPV4) {
                        msg_type = TCP_CLOSE_EVENT;
                    } else if(state->pf == NFPROTO_IPV6) {
                        msg_type = TCP6_CLOSE_EVENT;
                    } else {
                        LOGK(1, "oplus_esreport_output_hook TCP_LAST_ACK NFPROTO ERROR!");
                        return NF_ACCEPT;
                    }
    	            establish_notify(ip_protocol, daddr, daddr6, dport, saddr, saddr6, sport, proto, msg_type);
                    return NF_ACCEPT;
		        default:
		        	return NF_ACCEPT;
	        }
        }
    }
	return NF_ACCEPT;
}

static unsigned int oplus_esreport_input_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	struct sock *sk;
	const struct iphdr *iph = NULL;
    const struct ipv6hdr *ipv6h = NULL;
	struct nf_conn *ct = NULL;
	enum ip_conntrack_info ctinfo;
    int if_match = 0;
	const struct tcphdr *th = NULL;
	const struct udphdr *uh = NULL;
    enum esreport_msg_type_et msg_type;
    
    uint32_t proto = 0;
    uint32_t dport = 0;
    // server ip
    uint32_t daddr = 0;
    uint8_t daddr6[16] = {0};
    uint32_t sport = 0;
    uint32_t saddr = 0;
    uint8_t saddr6[16] = {0};
    int ip_protocol;
    int i;

    if (state->pf == NFPROTO_IPV4) {
        ip_protocol = NFPROTO_IPV4;
    	iph = ip_hdr(skb);
        if (!iph) {
            return NF_ACCEPT;
        }
        saddr = iph->daddr;
        daddr = iph->saddr;
        if (iph->protocol == IPPROTO_TCP) {
	        proto = IPPROTO_TCP;
        } else if (iph->protocol == IPPROTO_UDP) {
            proto = IPPROTO_UDP;
        } else {
            return NF_ACCEPT;
        }
    } else if (state->pf == NFPROTO_IPV6) {
        ip_protocol = NFPROTO_IPV6;
    	ipv6h = ipv6_hdr(skb);
        if (!ipv6h) {
            return NF_ACCEPT;
        }
        memcpy(saddr6, &ipv6h->daddr, 16);
        memcpy(daddr6, &ipv6h->saddr, 16);
        if (ipv6h->nexthdr == IPPROTO_TCP) {
            proto = IPPROTO_TCP;
        } else if (ipv6h->nexthdr == IPPROTO_UDP) {
            proto = IPPROTO_UDP;
        } else {
            return NF_ACCEPT;
        }
    } else {
        return NF_ACCEPT;
    }

    if (proto == IPPROTO_TCP) {
        th = tcp_hdr(skb);
        if (!th) {
            return NF_ACCEPT;
        }
        sport = ntohs(th->dest);
        dport = ntohs(th->source);
    } else if (proto == IPPROTO_UDP) {
        uh = udp_hdr(skb);
        if (!uh) {
            return NF_ACCEPT;
        }
        sport = ntohs(uh->dest);
        dport = ntohs(uh->source);
    }

	ct = nf_ct_get(skb, &ctinfo);

    // 无论上行还是下行：
    // 服务端的port始终是sk->__sk_common.skc_dport，是大端，需要转化为小端；
    // 客户端的port始终是sk->__sk_common.skc_num，是小端；
    // 服务端的ipv4始终是sk->sk_daddr，是大端，需要转化为小端；
    // 客户端的ipv4始终是sk->sk_rcv_saddr，是大端，需要转化为小端；
    // 服务端的ipv6始终是sk->sk_v6_daddr，是大端，需要转化为小端；
    // 客户端的ipv6始终是sk->sk_v6_rcv_saddr，是大端，需要转化为小端；

    //根据中间件下发的ip三元组数据，判断是否要上报该socket
    for (i = 0; i < s_ip_triples_count; i++) {
        ip_triple it = oplus_esreport_ip_triples[i];
        if (state->pf == NFPROTO_IPV4) {
            if (!daddr || it.addr != ntohl(daddr)) {
                continue;
            }
        } else if (state->pf == NFPROTO_IPV6) {
            if (!addr6_little_meet_big_endian(it.addr6, daddr6)) {
                continue;
            }
        } else {
            return NF_ACCEPT;
        }
        if (port_meet(it, dport) && (!it.proto || it.proto == proto)) {
            if_match = 1;
            break;
        }
    }
    if (!if_match) {
        return NF_ACCEPT;
    }

    //tcp收rst，tcp断开
	if (iph != NULL && iph->protocol == IPPROTO_TCP && th) {
        if (th->rst) {
            if (state->pf == NFPROTO_IPV4) {
                msg_type = TCP_CLOSE_EVENT;
            } else if (state->pf == NFPROTO_IPV6) {
                msg_type = TCP6_CLOSE_EVENT;
            } else {
                LOGK(1, "oplus_esreport_input_hook RESET TCP ERROR!");
                return NF_ACCEPT;
            }
    	    establish_notify(ip_protocol, daddr, daddr6, dport, saddr, saddr6, sport, proto, msg_type);
            return NF_ACCEPT;
        } else {
            sk = skb_to_full_sk(skb);
            if (!sk) {
                LOGK(1, "oplus_esreport_input_hook sk NULL!");
                return NF_ACCEPT;
            }
            switch (sk->sk_state) {
                case TCP_LAST_ACK:
                case TCP_TIME_WAIT:
                    if (th->ack) {
                        LOGK(1, "oplus_esreport_input_hook TCP_LAST_ACK or TCP_TIME_WAIT ack!");
                    } else {
                        LOGK(1, "oplus_esreport_input_hook TCP_LAST_ACK or TCP_TIME_WAIT!");
                    }
                    if (state->pf == NFPROTO_IPV4) {
                        msg_type = TCP_CLOSE_EVENT;
                    } else if (state->pf == NFPROTO_IPV6) {
                        msg_type = TCP6_CLOSE_EVENT;
                    } else {
                        LOGK(1, "oplus_esreport_input_hook TCP_LAST_ACK or TCP_TIME_WAIT NFPROTO ERROR!");
                        return NF_ACCEPT;
                    }
    	            establish_notify(ip_protocol, daddr, daddr6, dport, saddr, saddr6, sport, proto, msg_type);
                    return NF_ACCEPT;
                default:
                    break;
	        }
        }
	}
	return NF_ACCEPT;
}


static struct nf_hook_ops oplus_esreport_netfilter_ops[] __read_mostly = {
	{
		.hook		= oplus_esreport_output_hook,
		.pf			= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP_PRI_FILTER + 1,
	},
	{
		.hook		= oplus_esreport_input_hook,
		.pf			= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_FILTER + 1,
	},
	{
		.hook		= oplus_esreport_output_hook,
		.pf			= NFPROTO_IPV6,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP_PRI_FILTER + 1,
	},
	{
		.hook		= oplus_esreport_input_hook,
		.pf			= NFPROTO_IPV6,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_FILTER + 1,
	},
};

static void esreport_enable(struct nlattr* nla) {
	u32 *data = (u32*)NLA_DATA(nla);
	s_esreport_enable_flag = data[0];
	LOGK(1, "s_esreport_enable_flag = %u", s_esreport_enable_flag);
	return;
}

static void fourIntToByteList(int fourIntList[4], uint8_t addr6[16]) {
    int i, j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            addr6[i * 4 + j] = (fourIntList[i] >> ((3 - j) * 8)) & 0xff;
        }
    }
}

static void esreport_config_ip_triple(struct nlattr* nla) {
    u32 *data = (u32*)NLA_DATA(nla);
    int nla_length = nla->nla_len;
    int i;
    int size;
    int size_to_byte_length;

    LOGK(1, "esreport_config_ip_triple nla length: %d", nla_length);

    if (nla_length < (NLA_HDRLEN + 4)) {
        LOGK(1, "esreport_config_ip_triple nla length error! %d", nla_length);
        return;
    }
    size = data[0];
    if (size < 0 || size > MAX_REPORT_IP_TRIPLES_COUNT) {
        LOGK(1, "esreport_config_ip_triple size error! %d", size);
        return;
    }
    LOGK(1, "esreport_config_ip_triple size: %d", size);

    size_to_byte_length = NLA_HDRLEN + 4 + size * 9 * 4;
    if (size_to_byte_length != nla_length) {
        LOGK(1, "esreport_config_ip_triple size is not equal to nla length! %d %d", size_to_byte_length, nla_length);
        return;
    }

    memset(oplus_esreport_ip_triples, 0, MAX_REPORT_IP_TRIPLES_COUNT * sizeof(ip_triple));
    s_ip_triples_count = size;
    for (i = 0; i < size; i++) {
        uint8_t addr6[16] = {0};
        int fourIntList[4] = {data[1+i*9+5], data[1+i*9+6], data[1+i*9+7], data[1+i*9+8]};
        ip_triple it;
        fourIntToByteList(fourIntList, addr6);
        it.port = data[1+i*9+0];
        it.start_port = data[1+i*9+1];
        it.end_port = data[1+i*9+2];
        it.proto = data[1+i*9+3];
        it.addr = data[1+i*9+4];
        // 下发的ipv6是按照string的顺序来存的，其实是大端，因为值最大的数字放在了数组0号下标
        memcpy(it.addr6, addr6, sizeof(it.addr6));
        oplus_esreport_ip_triples[i] = it;
        LOGK(1, "esreport_config_ip_triple count: %d, ip triple: %u %u %u %u %u v6: %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u"
            , s_ip_triples_count, oplus_esreport_ip_triples[i].port, oplus_esreport_ip_triples[i].start_port, oplus_esreport_ip_triples[i].end_port, oplus_esreport_ip_triples[i].proto, oplus_esreport_ip_triples[i].addr
            , oplus_esreport_ip_triples[i].addr6[0], oplus_esreport_ip_triples[i].addr6[1], oplus_esreport_ip_triples[i].addr6[2], oplus_esreport_ip_triples[i].addr6[3], oplus_esreport_ip_triples[i].addr6[4]
            , oplus_esreport_ip_triples[i].addr6[5], oplus_esreport_ip_triples[i].addr6[6], oplus_esreport_ip_triples[i].addr6[7], oplus_esreport_ip_triples[i].addr6[8], oplus_esreport_ip_triples[i].addr6[9]
            , oplus_esreport_ip_triples[i].addr6[10], oplus_esreport_ip_triples[i].addr6[11], oplus_esreport_ip_triples[i].addr6[12], oplus_esreport_ip_triples[i].addr6[13], oplus_esreport_ip_triples[i].addr6[14]
            , oplus_esreport_ip_triples[i].addr6[15]);
    }
}

static int esreport_netlink_rcv_msg(struct sk_buff *skb, struct genl_info *info)
{
	int ret = 0;
	struct nlmsghdr *nlhdr;
	struct genlmsghdr *genlhdr;
	struct nlattr *nla;

	nlhdr = nlmsg_hdr(skb);
	genlhdr = nlmsg_data(nlhdr);
	nla = genlmsg_data(genlhdr);

	if (s_esreport_user_pid == 0) {
		s_esreport_user_pid = nlhdr->nlmsg_pid;
		LOGK(1, "set s_esreport_user_pid=%u.\n", s_esreport_user_pid);
	}

	/* to do: may need to some head check here*/
	LOGK(1, "esreport_netlink_rcv_msg type=%u.\n", nla->nla_type);
	switch (nla->nla_type) {
	case ES_NL_MSG_ENABLE:
		esreport_enable(nla);
		break;
    case ES_NL_MSG_CONFIG_IP_TRIPLE:
        esreport_config_ip_triple(nla);
        break;
    default:
		return -EINVAL;
	}

	return ret;
}

static int __init nl_es_init(void)
{
    //es_nl_msg_establish msg;
	int ret = 0;

    LOGK(1, "esnotify: %s initialed ok!\n",__func__);

	ret = genl_register_family(&esreport_genl_family);
	if (ret) {
		LOGK(1, "genl_register_family: failed,ret = %d\n", ret);
		return ret;
	} else {
		LOGK(1, "genl_register_family complete, id = %d!\n", esreport_genl_family.id);
	}

	ret = nf_register_net_hooks(&init_net, oplus_esreport_netfilter_ops, ARRAY_SIZE(oplus_esreport_netfilter_ops));
	if (ret < 0) {
  		LOGK(1,"nl_es_init netfilter register failed, ret=%d\n", ret);
  		return ret;
  	} else {
  		LOGK(1,"nl_es_init netfilter register successfully.\n");
  	}

    return ret;
}

static void __exit nl_es_exit(void)
{
    LOGK(1, "esnotify: %s existing...\n",__func__);
}


module_init(nl_es_init);
module_exit(nl_es_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(" netlink establish report protocol");
MODULE_AUTHOR("TS");

