/***********************************************************
** Copyright (C), 2008-2023, oplus Mobile Comm Corp., Ltd.
** File: kuaishou.c
** Description: add kuaishou
**
** Version: 1.0
** Date : 2023/8/13
** Author: Tanzhoumei
**
** ------------------ Revision History:------------------------
** <author> <data> <version > <desc>
** Tanzhoumei 2023/8/13 1.0 build this module
****************************************************************/
#include <linux/file.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/types.h>
#include "dpi_core.h"
#include "dpi_main.h"

#include "../include/netlink_api.h"
#include "../include/comm_def.h"
#include "../include/dpi_api.h"

#define LOG_TAG "KUAISHOU"

static int s_debug = 0;
static struct ctl_table_header *s_kuaishou_table_header = NULL;

#define logt(fmt, args...) LOG(LOG_TAG, fmt, ##args)
#define logi(fmt, args...) do { if (s_debug) LOG(LOG_TAG, fmt, ##args); } while (0)
#define MAX_CONFIGURADLE_PORT_COUNT 2

static u32 s_kuaishou_uid = 0;
static separate_str_data *s_short_video_http_field_str_data = NULL;
static separate_str_data *s_live_play_http_field_str_data = NULL;
static char s_short_video_http_type[MAX_HTTP_TYPE];
static char s_live_play_http_type[MAX_HTTP_TYPE];
static long s_kuaishou_live_play_dstport[MAX_CONFIGURADLE_PORT_COUNT];
static long s_kuaishou_live_broadcast_dstport[MAX_CONFIGURADLE_PORT_COUNT];
static spinlock_t s_kuaishou_lock;
#define KUAISHOU_UID_SIZE 4

static int is_kuaishou_short_video_stream(struct sk_buff *skb, dpi_match_data_t *data) {
	struct tcphdr *tcph = NULL;

	tcph = get_tcp_header(skb);
	if (!tcph) {
		return 0;
	}
	spin_lock_bh(&s_kuaishou_lock);
	if (http_request_match(skb, tcph, s_short_video_http_type, s_short_video_http_field_str_data)) {
		spin_unlock_bh(&s_kuaishou_lock);
		return 1;
	}
	spin_unlock_bh(&s_kuaishou_lock);
	return 0;
}

static int is_kuaishou_live_play_stream(struct sk_buff *skb, dpi_match_data_t *data) {
	u16 peer_port = 0;
	struct tcphdr *tcph = NULL;
	int i = 0;

	peer_port = data->tuple.peer_port;
	for (i = 0; i < 2; i++) {
		spin_lock_bh(&s_kuaishou_lock);
		if (peer_port == s_kuaishou_live_play_dstport[i]) {
			spin_unlock_bh(&s_kuaishou_lock);
			return 1;
		}
		spin_unlock_bh(&s_kuaishou_lock);
	}

	tcph = get_tcp_header(skb);
	if (!tcph) {
		return 0;
	}
	spin_lock_bh(&s_kuaishou_lock);
	if (http_request_match(skb, tcph, s_live_play_http_type, s_live_play_http_field_str_data)) {
		spin_unlock_bh(&s_kuaishou_lock);
		return 1;
	}
	spin_unlock_bh(&s_kuaishou_lock);
	return 0;
}

static int is_kuaishou_live_broadcast_stream(struct sk_buff *skb, dpi_match_data_t *data, int dir) {
	u16 peer_port = data->tuple.peer_port;

	spin_lock_bh(&s_kuaishou_lock);
	if (peer_port >= s_kuaishou_live_broadcast_dstport[0] && peer_port <= s_kuaishou_live_broadcast_dstport[1]) {
		spin_unlock_bh(&s_kuaishou_lock);
		return 1;
	}
	spin_unlock_bh(&s_kuaishou_lock);

	return 0;
}

static int kuaishou_match(struct sk_buff *skb, int dir, dpi_match_data_t *data)
{
	if (!dir) {
		return 0;
	}

	data->kuaishou_data.ul_packet_count++;
	if (data->kuaishou_data.ul_packet_count > 3) {
		data->dpi_result |= DPI_ID_KUAISHOU_APP;
		data->state = DPI_MATCH_STATE_COMPLETE;
	}

	if (is_kuaishou_short_video_stream(skb, data)) {
		data->dpi_result |= DPI_ID_KUAISHOU_SHORT_VIDEO_DATA;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}

	if (is_kuaishou_live_play_stream(skb, data)) {
		data->dpi_result |= DPI_ID_KUAISHOU_LIVE_PLAY_DATA;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}

	if (is_kuaishou_live_broadcast_stream(skb, data, dir)) {
		data->dpi_result |= DPI_ID_KUAISHOU_LIVE_BROADCAST_DATA;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}

	return 0;
}

int set_kuaishou_uid(u32 uid)
{
	int ret = 0;

	u32 old_uid = s_kuaishou_uid;
	s_kuaishou_uid = uid;
	if (s_kuaishou_uid != old_uid) {
		if (old_uid == 0) {
			ret = dpi_register_app_match(s_kuaishou_uid, kuaishou_match);
			logt("dpi_register_app_match kuaishou uid %u return %d", s_kuaishou_uid, ret);
		} else if (s_kuaishou_uid == 0) {
			ret = dpi_unregister_app_match(old_uid);
			logt("dpi_unregister_app_match kuaishou uid %u return %d", s_kuaishou_uid, ret);
		} else {
			ret |= dpi_unregister_app_match(old_uid);
			ret |= dpi_register_app_match(s_kuaishou_uid, kuaishou_match);
			logt("dpi app uid change! kuaishou uid %u %u return %d", s_kuaishou_uid, old_uid, ret);
		}
	}

	return ret;
}

static int kuaishou_short_video_event(u64 dpi_id, int startStop)
{
	logi("kuaishou_short_video_event %llx, %d", dpi_id, startStop);
	return 0;
}

static int kuaishou_live_broadcast_event(u64 dpi_id, int startStop)
{
	logi("kuaishou_live_broadcast_event %llx, %d", dpi_id, startStop);
	return 0;
}

static int kuaishou_live_play_event(u64 dpi_id, int startStop)
{
	logi("kuaishou_live_play_event %llx, %d", dpi_id, startStop);
	return 0;
}

int set_kuaishou_stream_character(dpi_stream_character_data *data) {
	int err = 0;
	int i = 0;
	separate_str_data *kuaishou_dstport_arr = NULL;

	if (data->stream_id == DPI_ID_KUAISHOU_SHORT_VIDEO_DATA) {
		spin_lock_bh(&s_kuaishou_lock);
		strncpy(s_short_video_http_type, data->httptype, sizeof(s_short_video_http_type) - 1);
		if (s_short_video_http_field_str_data != NULL) {
			free_str_array(s_short_video_http_field_str_data);
			s_short_video_http_field_str_data = NULL;
		}
		s_short_video_http_field_str_data = split_str_by_symbol(data->httpfield, ",");
		if (!s_short_video_http_field_str_data) {
			logt("get s_short_video_http_field_str_data failed");
			spin_unlock_bh(&s_kuaishou_lock);
			return -1;
		}
		logt("receive kuaishou short video character, streamId = 0x%llx, httpfield = %s", data->stream_id, data->httpfield);
		spin_unlock_bh(&s_kuaishou_lock);
		return 0;
	} else if (data->stream_id == DPI_ID_KUAISHOU_LIVE_PLAY_DATA) {
		spin_lock_bh(&s_kuaishou_lock);
		strncpy(s_live_play_http_type, data->httptype, sizeof(s_live_play_http_type) - 1);
		if (s_live_play_http_field_str_data != NULL) {
			free_str_array(s_live_play_http_field_str_data);
			s_live_play_http_field_str_data = NULL;
		}
		s_live_play_http_field_str_data = split_str_by_symbol(data->httpfield, ",");
		if (!s_live_play_http_field_str_data) {
			logt("get s_live_play_http_field_str_data failed");
			spin_unlock_bh(&s_kuaishou_lock);
			return -1;
		}
		logt("receive kuaishou live play character, streamId = 0x%llx, httpfield = %s", data->stream_id, data->httpfield);
		kuaishou_dstport_arr = split_str_by_symbol(data->dstport, ",");
		if (!kuaishou_dstport_arr) {
			logt("get kuaishou_dstport_arr failed");
			spin_unlock_bh(&s_kuaishou_lock);
			return -1;
		}
		for (i = 0; i < kuaishou_dstport_arr->field_length; i++) {
			err = kstrtol(kuaishou_dstport_arr->field[i], 10, &s_kuaishou_live_play_dstport[i]);
			if (err) {
				logt("pkgth is not a number, err = %d", err);
			} else {
				logt("set kuaishou live play dstport = %ld", s_kuaishou_live_play_dstport[i]);
			}
		}
		free_str_array(kuaishou_dstport_arr);
		spin_unlock_bh(&s_kuaishou_lock);
	} else if (data->stream_id == DPI_ID_KUAISHOU_LIVE_BROADCAST_DATA) {
		kuaishou_dstport_arr = split_str_by_symbol(data->dstport, ",");
		if (!kuaishou_dstport_arr) {
			logt("get kuaishou_dstport_arr failed");
			return -1;
		}
		spin_lock_bh(&s_kuaishou_lock);
		for (i = 0; i < kuaishou_dstport_arr->field_length; i++) {
			err = kstrtol(kuaishou_dstport_arr->field[i], 10, &s_kuaishou_live_broadcast_dstport[i]);
			if (err) {
				logt("pkgth is not a number, err = %d", err);
			} else {
				logt("set kuaishou live broadcast dstport = %ld", s_kuaishou_live_broadcast_dstport[i]);
			}
		}
		free_str_array(kuaishou_dstport_arr);
		spin_unlock_bh(&s_kuaishou_lock);
	}
	return err;
}

static struct ctl_table s_kuaishou_sysctl_table[] __read_mostly = {
	{
		.procname = "debug",
		.data = &s_debug,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = proc_dointvec,
	},
	{}
};

int kuaishou_init(void)
{
	int ret = 0;

	spin_lock_init(&s_kuaishou_lock);
	ret = dpi_register_result_notify(DPI_ID_KUAISHOU_SHORT_VIDEO_DATA, kuaishou_short_video_event);
	if (ret) {
		logt("kuaishou_short_video_event_register return %d", ret);
		return -1;
	}

	ret = dpi_register_result_notify(DPI_ID_KUAISHOU_LIVE_BROADCAST_DATA, kuaishou_live_broadcast_event);
	if (ret) {
		logt("kuaishou_live_broadcast_event_register return %d", ret);
		goto kuaishou_live_broadcast_event_register_failed;
	}

	ret = dpi_register_result_notify(DPI_ID_KUAISHOU_LIVE_PLAY_DATA, kuaishou_live_play_event);
	if (ret) {
		logt("kuaishou_live_play_event_register return %d", ret);
		goto kuaishou_live_play_event_register_failed;
	}

	s_kuaishou_table_header = register_net_sysctl(&init_net, "net/kuaishou", s_kuaishou_sysctl_table);
	logt("register_net_sysctl return %p", s_kuaishou_table_header);
	if (!s_kuaishou_table_header) {
		goto ctl_failed;
	}
	return 0;

ctl_failed:
	dpi_unregister_result_notify(DPI_ID_KUAISHOU_LIVE_PLAY_DATA, kuaishou_live_play_event);
kuaishou_live_play_event_register_failed:
	dpi_unregister_result_notify(DPI_ID_KUAISHOU_LIVE_BROADCAST_DATA, kuaishou_live_broadcast_event);
kuaishou_live_broadcast_event_register_failed:
	dpi_unregister_result_notify(DPI_ID_KUAISHOU_SHORT_VIDEO_DATA, kuaishou_short_video_event);
	return -1;
}

void kuaishou_fini(void)
{
	int ret = 0;

	if (s_kuaishou_uid) {
		ret = dpi_unregister_app_match(s_kuaishou_uid);
		logt("dpi_unregister_app_match tmgp uid %u return %d", s_kuaishou_uid, ret);
		s_kuaishou_uid = 0;
	}
	unregister_netlink_request(COMM_NETLINK_EVENT_GET_WZRY_SERVER_IP);
	dpi_unregister_result_notify(DPI_ID_KUAISHOU_SHORT_VIDEO_DATA, kuaishou_short_video_event);
	dpi_unregister_result_notify(DPI_ID_KUAISHOU_LIVE_BROADCAST_DATA, kuaishou_live_broadcast_event);
	dpi_unregister_result_notify(DPI_ID_KUAISHOU_LIVE_PLAY_DATA, kuaishou_live_play_event);


	if (s_short_video_http_field_str_data) {
		free_str_array(s_short_video_http_field_str_data);
	}

	if (s_live_play_http_field_str_data) {
		free_str_array(s_live_play_http_field_str_data);
	}

	if (s_kuaishou_table_header) {
		unregister_net_sysctl_table(s_kuaishou_table_header);
	}

	return;
}



