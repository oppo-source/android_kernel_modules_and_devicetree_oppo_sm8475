#ifndef __OPLUS_TCP_SYN_H__
#define __OPLUS_TCP_SYN_H__

void tcp_syn_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
void tcp_syn_report(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
void oplus_tuning_tcpsyn_enable(struct nlattr *nla);
void oplus_tuning_tcpsyn_set_foreground_uid(struct nlattr *nla);
void oplus_tuning_tcpsyn_request_report(struct nlattr *nla);
int oplus_tuning_tcpsyn_init(void);
void oplus_tuning_tcpsyn_fini(void);

#endif
