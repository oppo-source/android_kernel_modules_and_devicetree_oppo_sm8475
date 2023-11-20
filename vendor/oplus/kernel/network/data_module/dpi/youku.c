/***********************************************************
** Copyright (C), 2008-2022, oplus Mobile Comm Corp., Ltd.
** File: youku.h
** Description: add youku stream identify
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
#include <linux/if_arp.h>
#include <net/genetlink.h>
#include <linux/netdevice.h>

#include "dpi_main.h"
#include "dpi_core.h"
#include "youku.h"

#include "../include/netlink_api.h"
#include "../include/comm_def.h"
#include "../include/dpi_api.h"

#define LOG_TAG "YOUKU"

#define logt(fmt, args...) LOG(LOG_TAG, fmt, ##args)

#define YOUKU_PACKAGE_MATCH_MATCH_COUNT 5

static dpi_stream_character_data *s_youku_video_charater_data = NULL;
static separate_str_data *s_youku_http_field_str_data = NULL;


static char s_youku_http_type[MAX_HTTP_TYPE];

static spinlock_t s_youku_lock;

static u32 s_youku_uid = 0;
static u32 s_youku_flag = 0;
/* s_youku_scene == 2 video */
static u32 s_youku_scene = 0;
static u32 s_is_enter_youku = 0;

static int youku_match(struct sk_buff *skb, int dir, dpi_match_data_t *data)
{
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	if(data->tuple.peer_port == DNS_SERVER_PORT) {
		data->dpi_result |= DPI_ID_YOUKU_APP;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}
	tcph = get_tcp_header(skb);
	spin_lock_bh(&s_youku_lock);
	if(dir == 1 && tcph && http_request_match(skb, tcph, s_youku_http_type, s_youku_http_field_str_data)) {
		logt("match youku video stream success");
		data->dpi_result |= DPI_ID_YOUKU_VIDEO_STREAM_DATA;
		data->state = DPI_MATCH_STATE_COMPLETE;
		spin_unlock_bh(&s_youku_lock);
		return 0;
	}
	spin_unlock_bh(&s_youku_lock);
	udph = get_udp_header(skb);
	if(udph && s_youku_scene == 2 && s_is_enter_youku == 1) {
		logt("match youku video stream success");
		data->dpi_result |= DPI_ID_YOUKU_VIDEO_STREAM_DATA;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}
	data->package_count += 1;
	if(data->package_count >= YOUKU_PACKAGE_MATCH_MATCH_COUNT) {
		data->dpi_result |= DPI_ID_DOUYU_APP;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}
	return 0;
}

static int set_youku_scene(u32 scene, u32 is_enter) {
	s_youku_scene = scene;
	s_is_enter_youku = is_enter;
	logt("receive youku scene notify, scene = %u, is_enter = %u", scene, is_enter);
	return 0;
}

int set_youku_stream_character(dpi_stream_character_data *data) {
	if(data->stream_id == DPI_ID_YOUKU_VIDEO_STREAM_DATA) {
		if(s_youku_video_charater_data == NULL) {
			s_youku_video_charater_data = kmalloc(sizeof(dpi_stream_character_data), GFP_ATOMIC);
			if (!s_youku_video_charater_data) {
				logt("malloc s_youku_video_charater_data failed!");
				return -1;
			}
		}
		spin_lock_bh(&s_youku_lock);
		memset(s_youku_video_charater_data, 0, sizeof(dpi_stream_character_data));
		memcpy(s_youku_video_charater_data, data, sizeof(dpi_stream_character_data));
		strncpy(s_youku_http_type, s_youku_video_charater_data->httptype, sizeof(s_youku_http_type) - 1);
		if(s_youku_http_field_str_data != NULL) {
			free_str_array(s_youku_http_field_str_data);
			s_youku_http_field_str_data = NULL;
		}
		s_youku_http_field_str_data = split_str_by_symbol(s_youku_video_charater_data->httpfield, ",");
		spin_unlock_bh(&s_youku_lock);
		logt("receive youku stream character, streamId = %llx", data->stream_id);
	}
	return 0;
}

int set_youku_uid(u32 uid)
{
	int ret = 0;
	u32 old_uid = s_youku_uid;
	s_youku_uid = uid;
	logt("s_youku_uid == %u", uid);
	if (s_youku_uid != old_uid) {
		if (old_uid == 0) {
			ret = dpi_register_app_match(s_youku_uid, youku_match);
			logt("dpi_register_app_match youku uid %u return %d", s_youku_uid, ret);
			ret = dpi_register_deepthinker_scene(s_youku_uid, set_youku_scene);
			logt("dpi_register_deepthinker_scene youku scene notify");
		} else if (uid == 0) {
			ret = dpi_unregister_app_match(old_uid);
			logt("dpi_unregister_app_match youku uid %u return %d", s_youku_uid, ret);
			ret = dpi_unregister_deepthinker_scene(old_uid);
		} else {
			ret |= dpi_unregister_app_match(old_uid);
			ret |= dpi_register_app_match(s_youku_uid, youku_match);
			logt("dpi app uid change! youku uid %u %u return %d", s_youku_uid, old_uid, ret);
			ret = dpi_unregister_deepthinker_scene(old_uid);
			ret = dpi_register_deepthinker_scene(s_youku_uid, set_youku_scene);
			logt("dpi_register_deepthinker_scene youku scene notify");
		}
	}
	return ret;
}

/* start 1, stop 0 */
static int youku_status_event(u64 dpi_id, int startStop)
{
	if(startStop) {
		if(s_youku_flag == 0) {
			s_youku_flag = 1;
			logt("youku video stream start, streamId = %llx", dpi_id & DPI_ID_STREAM_MASK);
		}
	} else {
		s_youku_flag = 0;
		logt("youku video stream stop, streamId = %llx", dpi_id & DPI_ID_STREAM_MASK);
	}
	return 0;
}

int youku_init(void)
{
	int ret = 0;

	spin_lock_init(&s_youku_lock);

	ret = dpi_register_result_notify(DPI_ID_YOUKU_VIDEO_STREAM_DATA, youku_status_event);
	return ret;
}

void youku_fini(void)
{
	int ret = 0;

	if (s_youku_uid) {
		ret = dpi_unregister_app_match(s_youku_uid);
		logt("dpi_unregister_app_match youku uid %u return %d", s_youku_uid, ret);
		s_youku_uid = 0;
	}

	if(s_youku_video_charater_data) {
		kfree(s_youku_video_charater_data);
		s_youku_video_charater_data = NULL;
	}

	if(s_youku_http_field_str_data) {
		free_str_array(s_youku_http_field_str_data);
	}

	dpi_unregister_result_notify(DPI_ID_YOUKU_VIDEO_STREAM_DATA, youku_status_event);

	return;
}