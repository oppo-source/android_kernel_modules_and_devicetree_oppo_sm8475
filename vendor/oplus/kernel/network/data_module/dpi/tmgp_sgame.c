/***********************************************************
** Copyright (C), 2008-2022, oplus Mobile Comm Corp., Ltd.
** File: tgmp_sgame.c
** Description: add tgmp sgame
**
** Version: 1.0
** Date : 2022/7/5
** Author: ShiQianhua
**
** ------------------ Revision History:------------------------
** <author> <data> <version > <desc>
** shiqianhua 2022/7/5 1.0 build this module
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

#include "dpi_main.h"
#include "dpi_core.h"
#include "tmgp_sgame.h"

#include "../include/netlink_api.h"
#include "../include/comm_def.h"
#include "../include/dpi_api.h"

#define LOG_TAG "TMGP_SGAME"

#define logt(fmt, args...) LOG(LOG_TAG, fmt, ##args)

u32 s_tmgp_sgame_uid = 0;

static u32 s_game_server_ip = 0;
static u16 s_target_udp_server_port = 0;
static bool s_is_wzry_playing = false;
static dpi_stream_character_data *s_wzry_battle_character_data = NULL;
static long s_wzry_battle_downpkgth = 0;

#define TGMP_SGAME_UID_SIZE 4

static u32 get_game_server_ip(struct sk_buff * skb, int dir)
{
	struct iphdr *iph = NULL;

	if (skb->protocol != htons(ETH_P_IP)) {
		return 0;
	}
	iph = ip_hdr(skb);
	if (dir) {
		return (u32)ntohl(iph->daddr);
	} else {
		return (u32)ntohl(iph->saddr);
	}
}

static int wzry_request_get_server_ip(u32 eventid, Netlink__Proto__RequestMessage *requestMsg, char **rsp_data, u32 *rsp_len)
{
	size_t out_buf_len = 0;
	char *out_buf = NULL;
	Netlink__Proto__ResponseGetWzryServerIp serverIpRsp = NETLINK__PROTO__RESPONSE_GET_WZRY_SERVER_IP__INIT;
	NETLINK_RSP_DATA_DECLARE(rsp_name, requestMsg->header->requestid, requestMsg->header->eventid, COMM_NETLINK_SUCC);

	serverIpRsp.battleip = s_game_server_ip;
	rsp_name.response_data_case = NETLINK__PROTO__RESPONSE_MESSAGE__RESPONSE_DATA_RSP_WZRY_SERVER_IP;
	rsp_name.rspwzryserverip = &serverIpRsp;
	out_buf_len = netlink__proto__response_message__get_packed_size(&rsp_name);
	out_buf = kmalloc(out_buf_len, GFP_ATOMIC);
	if (!out_buf) {
		logt("malloc speed out buf failed!");
		return COMM_NETLINK_ERR_MEMORY;
	}

	out_buf_len = netlink__proto__response_message__pack(&rsp_name, out_buf);

	*rsp_data = out_buf;
	*rsp_len = out_buf_len;

	return 0;
}

static void wzry_netlink_free(void *data)
{
	if (data) {
		kfree(data);
	}
}

static void notify_wzry_server_ip(void) {
	char *buffer = NULL;
	int size = 0;
	Netlink__Proto__NotifyMessage msg = NETLINK__PROTO__NOTIFY_MESSAGE__INIT;
	Netlink__Proto__MessageHeader header = NETLINK__PROTO__MESSAGE_HEADER__INIT;
	Netlink__Proto__NotifyWzryServerIp data = NETLINK__PROTO__NOTIFY_WZRY_SERVER_IP__INIT;
	header.requestid = 0;
	header.eventid = NETLINK__PROTO__NETLINK_MSG_ID__COMM_NETLINK_EVENT_NOTIFY_WZRY_SERVER_IP;
	header.retcode = 0;
	data.battleip = s_game_server_ip;
	msg.header = &header;
	msg.notify_data_case = NETLINK__PROTO__NOTIFY_MESSAGE__NOTIFY_DATA_NOTIFY_WZRY_SERVER_IP;
	msg.notifywzryserverip = &data;

	size = netlink__proto__notify_message__get_packed_size(&msg);
	buffer = kmalloc(size, GFP_ATOMIC);
	if (!buffer) {
		logt("malloc wzry server ip out buffer failed!");
		return;
	}
	size = netlink__proto__notify_message__pack(&msg, buffer);
	notify_netlink_event(buffer, size);
	kfree(buffer);
}


static int tmgp_sgame_match(struct sk_buff *skb, int dir, dpi_match_data_t *data)
{
	struct udphdr *udph = NULL;
	u32 server_ip;
	struct timespec64 time;
	u64 cur_time = 0;

	if (!s_is_wzry_playing) {
		return 0;
	}
	if (dir) {
		return 0;
	}
	udph = get_udp_header(skb);
	if ((!udph) ||
		(data->tuple.peer_port == DNS_SERVER_PORT) ||
		((s_target_udp_server_port != 0) &&
		(data->tuple.peer_port != s_target_udp_server_port))) {
		data->dpi_result |= DPI_ID_TMGP_SGAME_APP;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}
	ktime_get_raw_ts64(&time);
	cur_time = time.tv_sec * NS_PER_SEC + time.tv_nsec;
	if (data->tgmp_data.record_time == 0) {
		data->tgmp_data.record_time = cur_time;
	}
	if ((cur_time - data->tgmp_data.record_time) <= NS_PER_SEC) {
		data->tgmp_data.dl_packets_count++;
		if (data->tgmp_data.dl_packets_count == s_wzry_battle_downpkgth) {
			s_target_udp_server_port = data->tuple.peer_port;
			logt("s_target_udp_server_port = %hu", s_target_udp_server_port);
			data->dpi_result |= DPI_ID_TMGP_SGAME_STREAM_GAME_DATA;
			data->state = DPI_MATCH_STATE_COMPLETE;
			server_ip = get_game_server_ip(skb, dir);
			if (server_ip != s_game_server_ip) {
				s_game_server_ip = server_ip;
				notify_wzry_server_ip();
			}
		}
	} else {
		data->dpi_result |= DPI_ID_TMGP_SGAME_APP;
		data->state = DPI_MATCH_STATE_COMPLETE;
	}

	return 0;
}

static int set_wzry_scene(u32 scene, u32 is_enter) {
	if (scene == DPI_SCENE_GAME_PLAYING) {
		if (is_enter) {
			logt("wzry playing begin");
			s_is_wzry_playing = true;
		} else {
			logt("wzry playing end");
			s_is_wzry_playing = false;
			s_target_udp_server_port = 0;
		}
	}
	return 0;
}

int set_tmgp_sgame_uid(u32 uid)
{
	int ret = 0;

	u32 old_uid = s_tmgp_sgame_uid;
	s_tmgp_sgame_uid = uid;
	if (s_tmgp_sgame_uid != old_uid) {
		if (old_uid == 0) {
			ret = dpi_register_app_match(s_tmgp_sgame_uid, tmgp_sgame_match);
			logt("dpi_register_app_match tmgp uid %u return %d", s_tmgp_sgame_uid, ret);
			ret = dpi_register_deepthinker_scene(s_tmgp_sgame_uid, set_wzry_scene);
			logt("dpi_register_deepthinker_scene tmgp uid %u return %d", s_tmgp_sgame_uid, ret);
		} else if (s_tmgp_sgame_uid == 0) {
			ret = dpi_unregister_app_match(old_uid);
			logt("dpi_unregister_app_match tmgp uid %u return %d", s_tmgp_sgame_uid, ret);
			ret = dpi_unregister_deepthinker_scene(old_uid);
			logt("dpi_unregister_deepthinker_scene tmgp uid %u return %d", s_tmgp_sgame_uid, ret);
		} else {
			ret |= dpi_unregister_app_match(old_uid);
			ret |= dpi_register_app_match(s_tmgp_sgame_uid, tmgp_sgame_match);
			logt("dpi app uid change! tmgp uid %u %u return %d", s_tmgp_sgame_uid, old_uid, ret);
			ret |= dpi_unregister_deepthinker_scene(old_uid);
			ret |= dpi_register_deepthinker_scene(s_tmgp_sgame_uid, set_wzry_scene);
			logt("dpi scene uid change! tmgp uid %u %u return %d", s_tmgp_sgame_uid, old_uid, ret);
		}
	}

	return ret;
}

static int wzry_action_event(u64 dpi_id, int startStop)
{
	logt("wzry_action_event %llx, %d", dpi_id, startStop);
	if (!startStop) {
		s_target_udp_server_port = 0;
	}
	return 0;
}

int set_wzry_stream_character(dpi_stream_character_data *data) {
	int err = 0;

	if(data->stream_id == DPI_ID_TMGP_SGAME_STREAM_GAME_DATA) {
		if(s_wzry_battle_character_data == NULL) {
			s_wzry_battle_character_data = kmalloc(sizeof(dpi_stream_character_data), GFP_ATOMIC);
			if (!s_wzry_battle_character_data) {
				logt("malloc s_wechat_audio_call_character_data failed!");
				return -1;
			}
		}
		memset(s_wzry_battle_character_data, 0, sizeof(dpi_stream_character_data));
		memcpy(s_wzry_battle_character_data, data, sizeof(dpi_stream_character_data));
		err = kstrtol(s_wzry_battle_character_data->downpkgth, 10, &s_wzry_battle_downpkgth);
		logt("set wzry battle downpkgth = %ld", s_wzry_battle_downpkgth);
	}
	return err;
}

int tmgp_sgame_init(void)
{
	int ret = 0;

	ret = register_netlink_request(COMM_NETLINK_EVENT_GET_WZRY_SERVER_IP, wzry_request_get_server_ip, wzry_netlink_free);
	if (ret) {
		logt("register cmd COMM_NETLINK_EVENT_GET_WZRY_GAME_SERVER failed ");
		return -1;
	}

	ret = dpi_register_result_notify(DPI_ID_TMGP_SGAME_STREAM_GAME_DATA, wzry_action_event);
	if (ret) {
		logt("dpi_register_result_notify return %d", ret);
		goto dpi_failed;
	}

	return 0;
dpi_failed:
	unregister_netlink_request(COMM_NETLINK_EVENT_GET_WZRY_SERVER_IP);
	return -1;
}

void tmgp_sgame_fini(void)
{
	int ret = 0;

	if (s_tmgp_sgame_uid) {
		ret = dpi_unregister_app_match(s_tmgp_sgame_uid);
		logt("dpi_unregister_app_match tmgp uid %u return %d", s_tmgp_sgame_uid, ret);
		s_tmgp_sgame_uid = 0;
	}
	unregister_netlink_request(COMM_NETLINK_EVENT_GET_WZRY_SERVER_IP);
	dpi_unregister_result_notify(DPI_ID_TMGP_SGAME_STREAM_GAME_DATA, wzry_action_event);
	if (s_wzry_battle_character_data) {
		kfree(s_wzry_battle_character_data);
		s_wzry_battle_character_data = NULL;
	}

	return;
}



