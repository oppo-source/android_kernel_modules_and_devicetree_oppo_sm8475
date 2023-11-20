/***********************************************************
** Copyright (C), 2008-2022, oplus Mobile Comm Corp., Ltd.
** File: douyin.c
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

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <net/genetlink.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/inet.h>
#include "dpi_core.h"
#include "douyin.h"

#include "../include/netlink_api.h"
#include "../include/comm_def.h"
#include "../include/dpi_api.h"
#include "dpi_main.h"

#define LOG_TAG "DOUYIN"
static int s_debug = 0;

#define logt(fmt, args...) LOG(LOG_TAG, fmt, ##args)
#define logi(fmt, args...) do { \
	if (s_debug) { \
		LOG(LOG_TAG, fmt, ##args); \
	} \
} while (0)

#define DOUYIN_UID_SIZE 4
#define MAX_IP_COUNT 10
#define HTTP_REQUEST_MATCHED_PKGTH 4

u32 s_douyin_uid = 0;
static u32 s_ipv4_addr[MAX_IP_COUNT];
static struct in6_addr s_ipv6_addr[MAX_IP_COUNT];
static int s_ipv4_count = 0;
static int s_ipv6_count = 0;

static separate_str_data *s_douyin_http_field_str_data = NULL;
static char s_douyin_http_type[MAX_HTTP_TYPE];
static long s_douyin_live_broadcast_dst_port = 0;
static long s_douyin_live_broadcast_pkgth = 0;
static struct ctl_table_header *s_douyin_table_header = NULL;
static spinlock_t s_douyin_lock;
static u16 s_douyin_scene = 0;

static int is_douyin_short_video_stream(dpi_match_data_t *data, struct sk_buff *skb) {
	int idx = 0;

	if (skb->protocol == htons(ETH_P_IP)) {
		spin_lock_bh(&s_douyin_lock);
		for (idx = 0; idx < s_ipv4_count; idx++) {
			if (data->tuple.peer_ip == s_ipv4_addr[idx]) {
				spin_unlock_bh(&s_douyin_lock);
				return 1;
			}
		}
		spin_unlock_bh(&s_douyin_lock);
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		spin_lock_bh(&s_douyin_lock);
		for (idx = 0; idx < s_ipv6_count; idx++) {
			if (memcmp(data->tuple.peer_ipv6, (void *)&s_ipv6_addr[idx], sizeof(data->tuple.peer_ipv6)) == 0) {
				spin_unlock_bh(&s_douyin_lock);
				return 1;
			}
		}
		spin_unlock_bh(&s_douyin_lock);
	}
	return 0;
}

static int is_douyin_live_broadcast_stream(struct sk_buff *skb, int dir, dpi_match_data_t *data) {
	u16 server_port = 0;

	server_port = data->tuple.peer_port;
	if (server_port == s_douyin_live_broadcast_dst_port) {
		return 1;
	}

	if (dir) {
		data->douyin_data.ul_skb_len_sum += skb->len;
	} else {
		data->douyin_data.dl_skb_len_sum += skb->len;
	}
	spin_lock_bh(&s_douyin_lock);
	if ((data->douyin_data.packet_count2 == s_douyin_live_broadcast_pkgth) &&
	(data->douyin_data.ul_skb_len_sum > data->douyin_data.dl_skb_len_sum)) {
		spin_unlock_bh(&s_douyin_lock);
		return 1;
	}
	spin_unlock_bh(&s_douyin_lock);
	return 0;
}

static int is_douyin_live_play_stream(struct sk_buff *skb, int dir, dpi_match_data_t *data, struct tcphdr *tcph) {
	if (!dir) {
		return 0;
	}
	spin_lock_bh(&s_douyin_lock);
	if (http_request_match(skb, tcph, s_douyin_http_type, s_douyin_http_field_str_data)) {
		spin_unlock_bh(&s_douyin_lock);
		return 1;
	}
	spin_unlock_bh(&s_douyin_lock);
	return 0;
}

static int douyin_match(struct sk_buff *skb, int dir, dpi_match_data_t *data)
{
	struct tcphdr *tcph = NULL;

	tcph = get_tcp_header(skb);
	if (!tcph) {
		data->dpi_result |= DPI_ID_DOUYIN_APP;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}

	if (s_douyin_scene != DPI_SCENE_VIDEO_LIVE) {
		data->douyin_data.packet_count1++;
		if (data->douyin_data.packet_count1 > HTTP_REQUEST_MATCHED_PKGTH) {
			data->dpi_result |= DPI_ID_DOUYIN_APP;
			data->state = DPI_MATCH_STATE_COMPLETE;
		}
		if (is_douyin_short_video_stream(data, skb)) {
			data->dpi_result |= DPI_ID_DOUYIN_SHORT_VIDEO_DATA;
			data->state = DPI_MATCH_STATE_COMPLETE;
			return 0;
		}
		if (is_douyin_live_play_stream(skb, dir, data, tcph)) {
			data->dpi_result |= DPI_ID_DOUYIN_LIVE_PLAY_DATA;
			data->state = DPI_MATCH_STATE_COMPLETE;
			return 0;
		}
	} else if (s_douyin_scene == DPI_SCENE_VIDEO_LIVE) {
		data->douyin_data.packet_count2++;
		if (data->douyin_data.packet_count2 > s_douyin_live_broadcast_pkgth) {
			data->dpi_result |= DPI_ID_DOUYIN_APP;
			data->state = DPI_MATCH_STATE_COMPLETE;
			return 0;
		}

		if (is_douyin_live_broadcast_stream(skb, dir, data)) {
			data->dpi_result |= DPI_ID_DOUYIN_LIVE_BROADCAST_DATA;
			data->state = DPI_MATCH_STATE_COMPLETE;
			return 0;
		}
	}
	return 0;
}

static int set_douyin_scene(u32 scene, u32 is_enter) {
	if (scene != DPI_SCENE_VIDEO_LIVE) {
		return 0;
	}
	if (is_enter) {
		s_douyin_scene = scene;
	} else {
		s_douyin_scene = 0;
	}
	logt("receive douyin scene notify, scene = %u, is_enter = %u", scene, is_enter);
	return 0;
}

int set_douyin_uid(u32 uid)
{
	int ret = 0;

	u32 old_uid = s_douyin_uid;
	s_douyin_uid = uid;
	if (s_douyin_uid != old_uid) {
		if (old_uid == 0) {
			ret = dpi_register_app_match(s_douyin_uid, douyin_match);
			logt("dpi_register_app_match douyin uid %u return %d", s_douyin_uid, ret);
			ret = dpi_register_deepthinker_scene(s_douyin_uid, set_douyin_scene);
			logt("dpi_register_deepthinker_scene douyin scene notify uid %u return %d", s_douyin_uid, ret);
		} else if (s_douyin_uid == 0) {
			ret = dpi_unregister_app_match(old_uid);
			logt("dpi_unregister_app_match douyin uid %u return %d", s_douyin_uid, ret);
			ret = dpi_unregister_deepthinker_scene(old_uid);
			logt("dpi_unregister_deepthinker_scene douyin scene notify uid %u return %d", s_douyin_uid, ret);
		} else {
			ret |= dpi_unregister_app_match(old_uid);
			ret |= dpi_register_app_match(s_douyin_uid, douyin_match);
			logt("dpi app uid change! tmgp uid %u %u return %d", s_douyin_uid, old_uid, ret);
			ret = dpi_unregister_deepthinker_scene(old_uid);
			ret = dpi_register_deepthinker_scene(s_douyin_uid, set_douyin_scene);
			logt("dpi_register_deepthinker_scene douyin scene notify uid %u return %d", s_douyin_uid, ret);
		}
	}

	return ret;
}


static int douyin_short_video_event(u64 dpi_id, int startStop)
{
	logi("douyin_short_video_event %llx, %d", dpi_id, startStop);
	return 0;
}

static int douyin_live_broadcast_event(u64 dpi_id, int startStop)
{
	logi("douyin_live_broadcast_event %llx, %d", dpi_id, startStop);
	return 0;
}

static int douyin_live_play_event(u64 dpi_id, int startStop)
{
	logi("douyin_live_play_event %llx, %d", dpi_id, startStop);
	return 0;
}

static int douyin_set_ip_addr(u32 eventid, Netlink__Proto__RequestMessage *requestMsg, char **rsp_data, u32 *rsp_len)
{
	int i = 0;
	if ((requestMsg->request_data_case != NETLINK__PROTO__REQUEST_MESSAGE__REQUEST_DATA_REQUEST_SET_DOUYIN_IP)
		|| (!requestMsg->requestsetdouyinip)) {
		return COMM_NETLINK_ERR_PARAM;
	}

	memset(s_ipv4_addr, '\0', sizeof(s_ipv4_addr));
	s_ipv4_count = requestMsg->requestsetdouyinip->n_ipaddr;

	if (s_ipv4_count > MAX_IP_COUNT) {
		s_ipv4_count = MAX_IP_COUNT;
	}
	if (s_ipv4_count > 0) {
		memcpy(s_ipv4_addr, requestMsg->requestsetdouyinip->ipaddr, s_ipv4_count * sizeof(uint32_t));
	}

	memset(s_ipv6_addr, '\0', sizeof(s_ipv6_addr));
	s_ipv6_count = requestMsg->requestsetdouyinip->n_ipv6addr;
	if (s_ipv6_count > MAX_IP_COUNT) {
		s_ipv6_count = MAX_IP_COUNT;
	}
	for (i = 0; i < s_ipv6_count; i++) {
		in6_pton(requestMsg->requestsetdouyinip->ipv6addr[i], -1, (void *)&s_ipv6_addr[i], -1, NULL);
	}

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
		logi("request_douyin_set_ip_addr pack len %lu  buf len %lu", pack_len, len);
		*rsp_data = buf;
		*rsp_len = len;
	} while (0);

	return COMM_NETLINK_SUCC;
}

static void data_free(void *data)
{
	if (data) {
		kfree(data);
	}
}

static struct ctl_table s_douyin_sysctl_table[] __read_mostly = {
	{
		.procname = "debug",
		.data = &s_debug,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = proc_dointvec,
	},
	{}
};

int set_douyin_stream_character(dpi_stream_character_data *data) {
	int err = 0;

	if (data->stream_id == DPI_ID_DOUYIN_LIVE_PLAY_DATA) {
		spin_lock_bh(&s_douyin_lock);
		strncpy(s_douyin_http_type, data->httptype, sizeof(s_douyin_http_type) - 1);
		if (s_douyin_http_field_str_data != NULL) {
			free_str_array(s_douyin_http_field_str_data);
			s_douyin_http_field_str_data = NULL;
		}
		s_douyin_http_field_str_data = split_str_by_symbol(data->httpfield, ",");
		if (!s_douyin_http_field_str_data) {
			logt("get s_douyin_http_field_str_data failed");
			spin_unlock_bh(&s_douyin_lock);
			return -1;
		}
		spin_unlock_bh(&s_douyin_lock);
		logt("receive douyin live play character, streamId = 0x%llx", data->stream_id);
	} else if (data->stream_id == DPI_ID_DOUYIN_LIVE_BROADCAST_DATA) {
		spin_lock_bh(&s_douyin_lock);
		err = kstrtol(data->dstport, 10, &s_douyin_live_broadcast_dst_port);
		if (err) {
			logt("live broadcast dstport is not a number, err = %d", err);
		} else {
			logt("receive live broadcast stream character, streamId = 0x%llx, dstport = %ld", data->stream_id, s_douyin_live_broadcast_dst_port);
		}
		err = kstrtol(data->pkgth, 10, &s_douyin_live_broadcast_pkgth);
		if (err) {
			logt("pkgth is not a number, err = %d", err);
		} else {
			logt("receive live broadcast stream character, streamId = 0x%llx, pkgth = %ld", data->stream_id, s_douyin_live_broadcast_pkgth);
		}
		spin_unlock_bh(&s_douyin_lock);
	}
	return 0;
}

int douyin_init(void)
{
	int ret = 0;
	spin_lock_init(&s_douyin_lock);

	ret = dpi_register_result_notify(DPI_ID_DOUYIN_SHORT_VIDEO_DATA, douyin_short_video_event);
	if (ret) {
		logt("douyin_short_video_event_register return %d", ret);
		return -1;
	}

	ret = dpi_register_result_notify(DPI_ID_DOUYIN_LIVE_BROADCAST_DATA, douyin_live_broadcast_event);
	if (ret) {
		logt("douyin_live_broadcast_event_register return %d", ret);
		goto douyin_live_broadcast_event_register_failed;
	}

	ret = dpi_register_result_notify(DPI_ID_DOUYIN_LIVE_PLAY_DATA, douyin_live_play_event);
	if (ret) {
		logt("douyin_live_play_event_register return %d", ret);
		goto douyin_live_play_event_register_failed;
	}
	ret = register_netlink_request(COMM_NETLINK_EVENT_SET_DOUYIN_IPADDR, douyin_set_ip_addr, data_free);
	if (ret < 0) {
		logt("register cmd COMM_NETLINK_EVENT_SET_DOUYIN_IPADDR failed, ret=%d", ret);
		goto netlink_failed;
	}

	s_douyin_table_header = register_net_sysctl(&init_net, "net/douyin", s_douyin_sysctl_table);
	logt("register_net_sysctl return %p", s_douyin_table_header);
	if (!s_douyin_table_header) {
		goto ctl_failed;
	}

	return 0;

ctl_failed:
	unregister_netlink_request(COMM_NETLINK_EVENT_SET_DOUYIN_IPADDR);
netlink_failed:
	dpi_unregister_result_notify(DPI_ID_DOUYIN_LIVE_PLAY_DATA, douyin_live_play_event);
douyin_live_play_event_register_failed:
	dpi_unregister_result_notify(DPI_ID_DOUYIN_LIVE_BROADCAST_DATA, douyin_live_broadcast_event);
douyin_live_broadcast_event_register_failed:
	dpi_unregister_result_notify(DPI_ID_DOUYIN_SHORT_VIDEO_DATA, douyin_short_video_event);
	return -1;
}

void douyin_fini(void)
{
	int ret = 0;

	if (s_douyin_uid) {
		ret = dpi_unregister_app_match(s_douyin_uid);
		logt("dpi_unregister_app_match tmgp uid %u return %d", s_douyin_uid, ret);
		s_douyin_uid = 0;
	}
	unregister_netlink_request(COMM_NETLINK_EVENT_GET_WZRY_SERVER_IP);
	dpi_unregister_result_notify(DPI_ID_DOUYIN_SHORT_VIDEO_DATA, douyin_short_video_event);
	dpi_unregister_result_notify(DPI_ID_DOUYIN_LIVE_BROADCAST_DATA, douyin_live_broadcast_event);
	dpi_unregister_result_notify(DPI_ID_DOUYIN_LIVE_PLAY_DATA, douyin_live_play_event);
	unregister_netlink_request(COMM_NETLINK_EVENT_SET_DOUYIN_IPADDR);
	if (s_douyin_http_field_str_data) {
		free_str_array(s_douyin_http_field_str_data);
	}
	if (s_douyin_table_header) {
		unregister_net_sysctl_table(s_douyin_table_header);
	}

	return;
}



