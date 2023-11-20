#ifndef __OPLUS_TCP_CONGEST_CONTROL_H__
#define __OPLUS_TCP_CONGEST_CONTROL_H__

void tcp_congest_control_post_routing_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
void oplus_tcp_congest_control_enable(struct nlattr *nla);
void oplus_tcp_congest_control_set_bbr_uid(struct nlattr *nla);
void oplus_tcp_congest_control_set_bbr_stat_uid(struct nlattr *nla);
void oplus_tcp_congest_control_request_report(struct nlattr *nla);
int oplus_tcp_congest_control_init(void);
void oplus_tcp_congest_control_fini(void);

#endif