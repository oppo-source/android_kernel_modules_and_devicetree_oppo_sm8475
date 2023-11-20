/***********************************************************
** Copyright (C), 2008-2022, oplus Mobile Comm Corp., Ltd.
** File: zoom_meeting.h
** Description: add zoom_meeting stream identify
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
#include "zoom.h"

#include "../include/netlink_api.h"
#include "../include/comm_def.h"
#include "../include/dpi_api.h"

#define LOG_TAG "ZOOM-MEETING"

#define logt(fmt, args...) LOG(LOG_TAG, fmt, ##args)

static dpi_stream_character_data *s_zoom_meeting_charater_data = NULL;

static long s_zoom_meeting_dst_port = 0;
static u32 s_zoom_uid = 0;
static u32 s_zoom_meeting_flag = 0;
/* 1 video meeting status */
static u32 s_zoom_scene = 0;
static u32 s_is_enter_zoom = 0;

static int zoom_meeting_stream_match(struct sk_buff *skb, int dir, dpi_match_data_t *data)
{
	struct udphdr *udph = NULL;
	udph = get_udp_header(skb);
	if (!udph || data->tuple.peer_port == DNS_SERVER_PORT) {
		data->dpi_result |= DPI_ID_ZOOM_APP;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}
	if (data->tuple.peer_port == s_zoom_meeting_dst_port) {
		logt("match zoom stream success");
		data->dpi_result |= DPI_ID_ZOOM_MEETING_STREAM_DATA;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}
	return 0;
}

static int set_zoom_scene(u32 scene, u32 is_enter) {
	s_zoom_scene = scene;
	s_is_enter_zoom = is_enter;
	logt("receive zoom scene notify, scene = %u, is_enter = %u", scene, is_enter);
	return 0;
}

int set_zoom_stream_character(dpi_stream_character_data *data) {
	int err;
	if(data->stream_id == DPI_ID_ZOOM_MEETING_STREAM_DATA) {
		if(s_zoom_meeting_charater_data == NULL) {
			s_zoom_meeting_charater_data = kmalloc(sizeof(dpi_stream_character_data), GFP_ATOMIC);
			if (!s_zoom_meeting_charater_data) {
				logt("malloc s_zoom_meeting_charater_data failed!");
				return COMM_NETLINK_ERR_MEMORY;
			}
		}
		memset(s_zoom_meeting_charater_data, 0, sizeof(dpi_stream_character_data));
		memcpy(s_zoom_meeting_charater_data, data, sizeof(dpi_stream_character_data));
		err = kstrtol(s_zoom_meeting_charater_data->dstport, 10, &s_zoom_meeting_dst_port);
		if (err) {
			logt("kstrtol s_zoom_meeting_dst_port failed!");
		}
		logt("receive stream character, streamId = %llx", data->stream_id);
	}
	return 0;
}

int set_zoom_uid(u32 uid)
{
	int ret = 0;
	u32 old_uid = s_zoom_uid;
	s_zoom_uid = uid;
	logt("s_zoom_uid == %u", uid);
	if (s_zoom_uid != old_uid) {
		if (old_uid == 0) {
			ret = dpi_register_app_match(s_zoom_uid, zoom_meeting_stream_match);
			logt("dpi_register_app_match zoom uid %u return %d", s_zoom_uid, ret);
			ret = dpi_register_deepthinker_scene(s_zoom_uid, set_zoom_scene);
			logt("dpi_register_deepthinker_scene zoom scene notify");
		} else if (s_zoom_uid == 0) {
			ret = dpi_unregister_app_match(old_uid);
			logt("dpi_unregister_app_match zoom uid %u return %d", s_zoom_uid, ret);
			ret = dpi_unregister_deepthinker_scene(old_uid);
		} else {
			ret |= dpi_unregister_app_match(old_uid);
			ret |= dpi_register_app_match(s_zoom_uid, zoom_meeting_stream_match);
			logt("dpi app uid change! zoom uid %u %u return %d", s_zoom_uid, old_uid, ret);
			ret = dpi_register_deepthinker_scene(s_zoom_uid, set_zoom_scene);
			logt("dpi_register_deepthinker_scene zoom scene notify");
		}
	}
	return ret;
}

/* start 1, stop 0 */
static int zoom_meeting_status_event(u64 dpi_id, int startStop)
{
	if(startStop) {
		if(s_zoom_meeting_flag == 0) {
			s_zoom_meeting_flag = 1;
		}
	} else {
		s_zoom_meeting_flag = 0;
	}
	return 0;
}

int zoom_init(void)
{
	int ret = 0;
	ret = dpi_register_result_notify(DPI_ID_ZOOM_MEETING_STREAM_DATA, zoom_meeting_status_event);
	if (ret) {
		logt("dpi_register_result_notify return %d", ret);
		return ret;
	}
	return 0;
}

void zoom_fini(void)
{
	int ret = 0;

	if (s_zoom_uid) {
		ret = dpi_unregister_app_match(s_zoom_uid);
		logt("dpi_unregister_app_match zoom meeting uid %u return %d", s_zoom_uid, ret);
		s_zoom_uid = 0;
	}

	if(s_zoom_meeting_charater_data) {
		kfree(s_zoom_meeting_charater_data);
		s_zoom_meeting_charater_data = NULL;
	}

	dpi_unregister_result_notify(DPI_ID_ZOOM_MEETING_STREAM_DATA, zoom_meeting_status_event);

	return;
}
