/***********************************************************
** Copyright (C), 2008-2022, oplus Mobile Comm Corp., Ltd.
** File: iqiyi.h
** Description: add iqiyi stream identify
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
#include <linux/if_arp.h>

#include "dpi_main.h"
#include "dpi_core.h"
#include "iqiyi.h"

#include "../include/netlink_api.h"
#include "../include/comm_def.h"
#include "../include/dpi_api.h"

#define LOG_TAG "IQIYI"

#define logt(fmt, args...) LOG(LOG_TAG, fmt, ##args)

#define IQIYI_PACKAGE_MATCH_MATCH_COUNT 5

static dpi_stream_character_data *s_iqiyi_video_charater_data = NULL;
static separate_str_data *s_iqiyi_http_field_str_data = NULL;

static spinlock_t s_iqiyi_lock;

static u32 s_iqiyi_uid = 0;
static u32 s_iqiyi_flag = 0;
/* s_iqiyi_scene == 2 video */
static u32 s_iqiyi_scene = 0;
static u32 s_is_enter_iqiyi = 0;
static char s_iqiyi_http_type[MAX_HTTP_TYPE];

static int iqiyi_match(struct sk_buff *skb, int dir, dpi_match_data_t *data)
{
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	if (data->tuple.peer_port == DNS_SERVER_PORT) {
		data->dpi_result |= DPI_ID_IQIYI_APP;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}
	tcph = get_tcp_header(skb);
	spin_lock_bh(&s_iqiyi_lock);
	if(tcph && dir == 1 && http_request_match(skb, tcph, s_iqiyi_http_type, s_iqiyi_http_field_str_data)) {
		logt("match iqiyi video stream success");
		data->dpi_result |= DPI_ID_IQIYI_VIDEO_STREAM_DATA;
		data->state = DPI_MATCH_STATE_COMPLETE;
		spin_unlock_bh(&s_iqiyi_lock);
		return 0;
	}
	spin_unlock_bh(&s_iqiyi_lock);
	udph = get_udp_header(skb);
	if(udph && s_iqiyi_scene == 2 && s_is_enter_iqiyi == 1) {
		logt("match iqiyi video stream success");
		data->dpi_result |= DPI_ID_IQIYI_VIDEO_STREAM_DATA;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}
	data->package_count += 1;
	if(data->package_count >= IQIYI_PACKAGE_MATCH_MATCH_COUNT) {
		data->dpi_result |= DPI_ID_IQIYI_APP;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}
	return 0;
}

static int set_iqiyi_scene(u32 scene, u32 is_enter) {
	s_iqiyi_scene = scene;
	s_is_enter_iqiyi = is_enter;
	logt("receive iqiyi scene notify, scene = %u, is_enter = %u", scene, is_enter);
	return 0;
}

int set_iqiyi_stream_character(dpi_stream_character_data *data) {
	if(data->stream_id == DPI_ID_IQIYI_VIDEO_STREAM_DATA) {
		if(s_iqiyi_video_charater_data == NULL) {
			s_iqiyi_video_charater_data = kmalloc(sizeof(dpi_stream_character_data), GFP_ATOMIC);
			if (!s_iqiyi_video_charater_data) {
				logt("malloc s_iqiyi_video_charater_data failed!");
				return -1;
			}
		}
		spin_lock_bh(&s_iqiyi_lock);
		memset(s_iqiyi_video_charater_data, 0, sizeof(dpi_stream_character_data));
		memcpy(s_iqiyi_video_charater_data, data, sizeof(dpi_stream_character_data));
		memset(s_iqiyi_http_type, 0, sizeof(s_iqiyi_http_type));
		strncpy(s_iqiyi_http_type, s_iqiyi_video_charater_data->httptype, sizeof(s_iqiyi_http_type) - 1);
		if(s_iqiyi_http_field_str_data != NULL) {
			free_str_array(s_iqiyi_http_field_str_data);
			s_iqiyi_http_field_str_data = NULL;
		}
		s_iqiyi_http_field_str_data = split_str_by_symbol(s_iqiyi_video_charater_data->httpfield, ",");
		spin_unlock_bh(&s_iqiyi_lock);
		logt("receive iqiyi video stream character, streamId = %llx", data->stream_id);
	}
	return 0;
}

int set_iqiyi_uid(u32 uid)
{
	int ret = 0;
	u32 old_uid = s_iqiyi_uid;
	s_iqiyi_uid = uid;
	logt("s_iqiyi_uid == %u", uid);
	if (s_iqiyi_uid != old_uid) {
		if (old_uid == 0) {
			ret = dpi_register_app_match(s_iqiyi_uid, iqiyi_match);
			logt("dpi_register_app_match iqiyi uid %u return %d", s_iqiyi_uid, ret);
			ret = dpi_register_deepthinker_scene(s_iqiyi_uid, set_iqiyi_scene);
			logt("dpi_register_deepthinker_scene iqiyi scene notify");
		} else if (uid == 0) {
			ret = dpi_unregister_app_match(old_uid);
			logt("dpi_unregister_app_match iqiyi uid %u return %d", s_iqiyi_uid, ret);
			ret = dpi_unregister_deepthinker_scene(old_uid);
		} else {
			ret |= dpi_unregister_app_match(old_uid);
			ret |= dpi_register_app_match(s_iqiyi_uid, iqiyi_match);
			logt("dpi app uid change! iqiyi uid %u %u return %d", s_iqiyi_uid, old_uid, ret);
			ret = dpi_unregister_deepthinker_scene(old_uid);
			ret = dpi_register_deepthinker_scene(s_iqiyi_uid, set_iqiyi_scene);
			logt("dpi_register_deepthinker_scene iqiyi scene notify");
		}
	}
	return ret;
}

/* start 1, stop 0 */
static int iqiyi_status_event(u64 dpi_id, int startStop)
{
	if(startStop) {
		if(s_iqiyi_flag == 0) {
			s_iqiyi_flag = 1;

			logt("iqiyi video start, streamId = %llx", dpi_id & DPI_ID_STREAM_MASK);
		}
	} else {
		s_iqiyi_flag = 0;
		logt("iqiyi video stop, streamId = %llx", dpi_id & DPI_ID_STREAM_MASK);
	}
	return 0;
}

int iqiyi_init(void)
{
	int ret = 0;

	spin_lock_init(&s_iqiyi_lock);

	ret = dpi_register_result_notify(DPI_ID_IQIYI_VIDEO_STREAM_DATA, iqiyi_status_event);
	return ret;
}

void iqiyi_fini(void)
{
	int ret = 0;

	if (s_iqiyi_uid) {
		ret = dpi_unregister_app_match(s_iqiyi_uid);
		logt("dpi_unregister_app_match iqiyi uid %u return %d", s_iqiyi_uid, ret);
		s_iqiyi_uid = 0;
	}

	if(s_iqiyi_video_charater_data) {
		kfree(s_iqiyi_video_charater_data);
		s_iqiyi_video_charater_data = NULL;
	}

	if(s_iqiyi_http_field_str_data) {
		free_str_array(s_iqiyi_http_field_str_data);
	}

	dpi_unregister_result_notify(DPI_ID_IQIYI_VIDEO_STREAM_DATA, iqiyi_status_event);

	return;
}
