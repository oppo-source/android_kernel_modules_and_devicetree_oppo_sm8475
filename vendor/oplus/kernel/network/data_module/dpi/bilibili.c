/***********************************************************
** Copyright (C), 2008-2022, oplus Mobile Comm Corp., Ltd.
** File: bilibili.h
** Description: add bilibili stream identify
**
** Version: 1.0
** Date : 2023/06/27
** Author: Zhangpeng
**
** ------------------ Revision History:------------------------
** <author> <data> <version > <desc>
** Zhangpeng 2023/06/27 1.0 build this module
****************************************************************/

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/genetlink.h>

#include "dpi_main.h"
#include "dpi_core.h"
#include "bilibili.h"

#include "../include/netlink_api.h"
#include "../include/comm_def.h"
#include "../include/dpi_api.h"

#define LOG_TAG "BILIBILI"

#define MATCH_VIDEO_STREAM_TIME_INTERVAL 500  /* unit ms */
#define BILIBILI_VIDEO_STREAM_MATCH_COUNT 3
#define BILIBILI_PACKAGE_MATCH_MATCH_COUNT 8

#define logt(fmt, args...) LOG(LOG_TAG, fmt, ##args)

static spinlock_t s_bilibili_lock;

static dpi_stream_character_data *s_bilibili_video_charater_data = NULL;
static dpi_stream_character_data *s_bilibili_live_charater_data = NULL;
static dpi_stream_character_data *s_bilibili_living_charater_data = NULL;

static separate_str_data *s_bilibili_video_http_field_str_data = NULL;
static separate_str_data *s_bilibili_live_http_field_str_data = NULL;

static char s_bilibili_video_http_type[MAX_HTTP_TYPE];
static char s_bilibili_live_http_type[MAX_HTTP_TYPE];

static char s_bilibili_video_stream[] = {0x00, 0x01, 0x00};

static long s_bilibili_living_dst_port = 0;
static u32 s_bilibili_uid = 0;
/*
s_bilibili_scene == 2 video
s_bilibili_scene == 3 living
*/
static u32 s_bilibili_scene = 0;
static u32 s_is_enter_bilibili = 0;

static int is_bilibili_video_stream(struct sk_buff *skb, struct udphdr *udph, dpi_match_data_t *data) {
	char *payload = NULL;
	struct timespec64 time;
	u64 cur_time = 0;
	u32 payload_length = 0;
	ktime_get_raw_ts64(&time);
	cur_time = time.tv_sec * NS_PER_SEC + time.tv_nsec;
	payload = (char *)((char *)udph + sizeof(struct udphdr));
	payload_length = udph->len - sizeof(struct udphdr);
	if(!skb_is_nonlinear(skb) && payload_length > sizeof(s_bilibili_video_stream)) {
		if(memcmp(payload, s_bilibili_video_stream, sizeof(s_bilibili_video_stream)) == 0) {
			data->bilibili_data.match_count++;
			if(data->bilibili_data.match_count == 1) {
				data->bilibili_data.record_time = cur_time;
			}
			if(data->bilibili_data.match_count >= BILIBILI_VIDEO_STREAM_MATCH_COUNT
				&& (cur_time - data->bilibili_data.record_time < MATCH_VIDEO_STREAM_TIME_INTERVAL * 1000000)) {
				data->bilibili_data.match_count = 0;
				return 1;
			}
		}
	}
	return 0;
}

static int bilibili_stream_match(struct sk_buff *skb, int dir, dpi_match_data_t *data)
{
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;

	if(data->tuple.peer_port == DNS_SERVER_PORT) {
		data->dpi_result |= DPI_ID_BILIBILI_APP;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}
	tcph = get_tcp_header(skb);
	spin_lock_bh(&s_bilibili_lock);
	if (dir == 1 && tcph && http_request_match(skb, tcph, s_bilibili_live_http_type, s_bilibili_live_http_field_str_data)) {
		logt("match bilibili live stream success");
		data->dpi_result |= DPI_ID_BILIBILI_LIVE_STREAM_DATA;
		data->state = DPI_MATCH_STATE_COMPLETE;
		spin_unlock_bh(&s_bilibili_lock);
		return 0;
	} else if (dir == 1 && tcph && http_request_match(skb, tcph, s_bilibili_video_http_type, s_bilibili_video_http_field_str_data)) {
		logt("match bilibili video stream success");
		data->dpi_result |= DPI_ID_BILIBILI_VIDEO_STREAM_DATA;
		data->state = DPI_MATCH_STATE_COMPLETE;
		spin_unlock_bh(&s_bilibili_lock);
		return 0;
	}
	spin_unlock_bh(&s_bilibili_lock);
	udph = udp_hdr(skb);
	if (udph && data->tuple.peer_port == s_bilibili_living_dst_port) {
		logt("match bilibili living success");
		data->dpi_result |= DPI_ID_BILIBILI_LIVING_STREAM_DATA;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}
	if (udph && is_bilibili_video_stream(skb, udph, data)) {
		logt("match bilibili video stream success");
		data->dpi_result |= DPI_ID_BILIBILI_VIDEO_STREAM_DATA;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}
	data->package_count++;
	if (data->package_count > BILIBILI_PACKAGE_MATCH_MATCH_COUNT) {
		data->dpi_result |= DPI_ID_BILIBILI_APP;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}
	return 0;
}

static int set_bilibili_scene(u32 scene, u32 is_enter) {
	s_bilibili_scene = scene;
	s_is_enter_bilibili = is_enter;
	logt("receive bilibili scene notify, scene = %u, is_enter = %u", scene, is_enter);
	return 0;
}

int set_bilibili_stream_character(dpi_stream_character_data *data) {
	int err = 0;

	if(data->stream_id == DPI_ID_BILIBILI_VIDEO_STREAM_DATA) {
		if(s_bilibili_video_charater_data == NULL) {
			s_bilibili_video_charater_data = kmalloc(sizeof(dpi_stream_character_data), GFP_ATOMIC);
			if (!s_bilibili_video_charater_data) {
				logt("malloc s_bilibili_video_charater_data failed!");
				return -1;
			}
		}
		spin_lock_bh(&s_bilibili_lock);
		memset(s_bilibili_video_charater_data, 0, sizeof(dpi_stream_character_data));
		memcpy(s_bilibili_video_charater_data, data, sizeof(dpi_stream_character_data));
		strncpy(s_bilibili_video_http_type, s_bilibili_video_charater_data->httptype, sizeof(s_bilibili_video_http_type) - 1);
		if(s_bilibili_video_http_field_str_data != NULL) {
			free_str_array(s_bilibili_video_http_field_str_data);
			s_bilibili_video_http_field_str_data = NULL;
		}
		s_bilibili_video_http_field_str_data = split_str_by_symbol(s_bilibili_video_charater_data->httpfield, ",");
		spin_unlock_bh(&s_bilibili_lock);
		logt("receive stream video character, streamId = %llx", data->stream_id);
	}
	if(data->stream_id == DPI_ID_BILIBILI_LIVE_STREAM_DATA) {
		if(s_bilibili_live_charater_data == NULL) {
			s_bilibili_live_charater_data = kmalloc(sizeof(dpi_stream_character_data), GFP_ATOMIC);
			if (!s_bilibili_live_charater_data) {
				logt("malloc s_bilibili_live_charater_data failed!");
				return -1;
			}
		}
		spin_lock_bh(&s_bilibili_lock);
		memset(s_bilibili_live_charater_data, 0, sizeof(dpi_stream_character_data));
		memcpy(s_bilibili_live_charater_data, data, sizeof(dpi_stream_character_data));
		memset(s_bilibili_live_http_type, 0, sizeof(s_bilibili_live_http_type));
		strncpy(s_bilibili_live_http_type, s_bilibili_live_charater_data->httptype, sizeof(s_bilibili_live_http_type) - 1);
		if(s_bilibili_live_http_field_str_data != NULL) {
			free_str_array(s_bilibili_live_http_field_str_data);
			s_bilibili_live_http_field_str_data = NULL;
		}
		s_bilibili_live_http_field_str_data = split_str_by_symbol(s_bilibili_live_charater_data->httpfield, ",");
		spin_unlock_bh(&s_bilibili_lock);
		logt("receive live stream character, streamId = %llx", data->stream_id);
	}
	if(data->stream_id == DPI_ID_BILIBILI_LIVING_STREAM_DATA) {
		if(s_bilibili_living_charater_data == NULL) {
			s_bilibili_living_charater_data = kmalloc(sizeof(dpi_stream_character_data), GFP_ATOMIC);
			if (!s_bilibili_living_charater_data) {
				logt("malloc s_bilibili_living_charater_data failed!");
				return -1;
			}
		}
		memset(s_bilibili_living_charater_data, 0, sizeof(dpi_stream_character_data));
		memcpy(s_bilibili_living_charater_data, data, sizeof(dpi_stream_character_data));
		err = kstrtol(s_bilibili_living_charater_data->dstport, 10, &s_bilibili_living_dst_port);
		if(err) {
			logt("dstport is not a number, err = %d", err);
		}
		logt("receive living stream character, streamId = %llx", data->stream_id);
	}

	return 0;
}

int set_bilibili_uid(u32 uid)
{
	int ret = 0;
	u32 old_uid = s_bilibili_uid;
	s_bilibili_uid = uid;
	logt("s_bilibili_uid == %u", uid);
	if (s_bilibili_uid != old_uid) {
		if (old_uid == 0) {
			ret = dpi_register_app_match(s_bilibili_uid, bilibili_stream_match);
			logt("dpi_register_app_match bilibili uid %u return %d", s_bilibili_uid, ret);
			ret = dpi_register_deepthinker_scene(s_bilibili_uid, set_bilibili_scene);
			logt("dpi_register_deepthinker_scene bilibili scene notify");
		} else if (uid == 0) {
			ret = dpi_unregister_app_match(old_uid);
			logt("dpi_unregister_app_match bilibili uid %u return %d", s_bilibili_uid, ret);
			ret = dpi_unregister_deepthinker_scene(old_uid);
		} else {
			ret |= dpi_unregister_app_match(old_uid);
			ret |= dpi_register_app_match(s_bilibili_uid, bilibili_stream_match);
			logt("dpi app uid change! bilibili uid %u %u return %d", s_bilibili_uid, old_uid, ret);
			ret |= dpi_unregister_deepthinker_scene(old_uid);
			ret = dpi_register_deepthinker_scene(s_bilibili_uid, set_bilibili_scene);
			logt("dpi_register_deepthinker_scene bilibili scene notify");
		}
	}
	return ret;
}

/* start 1, stop 0 */
static int bilibili_status_event(u64 dpi_id, int startStop)
{
	if(startStop) {
		logt("bilibili stream start, streamId = %llx", dpi_id & DPI_ID_STREAM_MASK);
	} else {
		logt("bilibili stream stop, streamId = %llx", dpi_id & DPI_ID_STREAM_MASK);
	}
	return 0;
}

int bilibili_init(void)
{
	int ret = 0;

	spin_lock_init(&s_bilibili_lock);

	ret |= dpi_register_result_notify(DPI_ID_BILIBILI_VIDEO_STREAM_DATA, bilibili_status_event);
	if(ret) {
		logt("dpi_register_result_notify failed, return %d", ret);
		return ret;
	}
	ret |= dpi_register_result_notify(DPI_ID_BILIBILI_LIVE_STREAM_DATA, bilibili_status_event);
	if(ret) {
		logt("dpi_register_result_notify failed, return %d", ret);
		dpi_unregister_result_notify(DPI_ID_BILIBILI_VIDEO_STREAM_DATA, bilibili_status_event);
		return ret;
	}
	ret |= dpi_register_result_notify(DPI_ID_BILIBILI_LIVING_STREAM_DATA, bilibili_status_event);
	if(ret) {
		logt("dpi_register_result_notify failed, return %d", ret);
		dpi_unregister_result_notify(DPI_ID_BILIBILI_VIDEO_STREAM_DATA, bilibili_status_event);
		dpi_unregister_result_notify(DPI_ID_BILIBILI_LIVE_STREAM_DATA, bilibili_status_event);
		return ret;
	}

	return ret;
}

void bilibili_fini(void)
{
	int ret = 0;

	if (s_bilibili_uid) {
		ret = dpi_unregister_app_match(s_bilibili_uid);
		logt("dpi_unregister_app_match bilibili uid %u return %d", s_bilibili_uid, ret);
		s_bilibili_uid = 0;
	}

	if(s_bilibili_live_charater_data) {
		kfree(s_bilibili_live_charater_data);
		s_bilibili_live_charater_data = NULL;
	}
	if(s_bilibili_living_charater_data) {
		kfree(s_bilibili_living_charater_data);
		s_bilibili_living_charater_data = NULL;
	}
	if(s_bilibili_video_charater_data) {
		kfree(s_bilibili_video_charater_data);
		s_bilibili_video_charater_data = NULL;
	}

	if(s_bilibili_live_http_field_str_data) {
		free_str_array(s_bilibili_live_http_field_str_data);
	}

	if(s_bilibili_video_http_field_str_data) {
		free_str_array(s_bilibili_video_http_field_str_data);
	}

	dpi_unregister_result_notify(DPI_ID_BILIBILI_VIDEO_STREAM_DATA, bilibili_status_event);
	dpi_unregister_result_notify(DPI_ID_BILIBILI_LIVE_STREAM_DATA, bilibili_status_event);
	dpi_unregister_result_notify(DPI_ID_BILIBILI_LIVING_STREAM_DATA, bilibili_status_event);

	return;
}
