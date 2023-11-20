/***********************************************************
** Copyright (C), 2008-2023, oplus Mobile Comm Corp., Ltd.
** File: qq.c
** Description: add qq
**
** Version: 1.0
** Date : 2023/7/12
** Author: TanZhoumei
**
** ------------------ Revision History:------------------------
** <author> <data> <version > <desc>
** TanZhoumei 2023/7/12 1.0 build this module
****************************************************************/
#include <linux/file.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "dpi_core.h"
#include "qq.h"
#include "dpi_main.h"

#include "../include/netlink_api.h"
#include "../include/comm_def.h"
#include "../include/dpi_api.h"

#define LOG_TAG "QQ"

#define logt(fmt, args...) LOG(LOG_TAG, fmt, ##args)

u32 s_qq_uid = 0;
u64 s_qq_scene = 0;
u32 s_is_enter_qq = 0;

#define QQ_UID_SIZE 4

static int s_is_match_completed = 0;
static long s_qq_audio_call_pkgth = 0;
static long s_qq_video_call_pkgth = 0;

static void identify_qq_video_or_audio_stream(struct udphdr *udph, u16 port, dpi_match_data_t *data)
{
	struct timespec64 time;
	u64 cur_time = 0;

	ktime_get_raw_ts64(&time);
	cur_time = time.tv_sec * NS_PER_SEC + time.tv_nsec;
	if (data->qq_data.record_time == 0) {
		data->qq_data.record_time = cur_time;
	}
	if ((cur_time - data->qq_data.record_time) > 2 * NS_PER_SEC) {
		if (s_qq_scene == DPI_SCENE_VIDEO_CALL) {
			if (data->qq_data.packets_count >= s_qq_video_call_pkgth) {
				data->dpi_result |= DPI_ID_QQ_VIDEO_CALL_DATA;
				data->state = DPI_MATCH_STATE_COMPLETE;
				s_is_match_completed++;
			} else {
				data->dpi_result |= DPI_ID_QQ_APP;
				data->state = DPI_MATCH_STATE_COMPLETE;
			}
		} else if (s_qq_scene == DPI_SCENE_AUDIO_CALL) {
			if (data->qq_data.packets_count >= s_qq_audio_call_pkgth) {
				data->dpi_result |= DPI_ID_QQ_AUDIO_CALL_DATA;
				data->state = DPI_MATCH_STATE_COMPLETE;
				s_is_match_completed++;
			} else {
				data->dpi_result |= DPI_ID_QQ_APP;
				data->state = DPI_MATCH_STATE_COMPLETE;
			}
		}
		data->qq_data.packets_count = 1;
		data->qq_data.record_time = cur_time;
	} else {
		data->qq_data.packets_count++;
	}
}

static int qq_match(struct sk_buff *skb, int dir, dpi_match_data_t *data)
{
	struct udphdr *udph = NULL;
	u16 port = data->tuple.peer_port;


	if (s_is_enter_qq == 0 || s_is_match_completed == 1) {
		return 0;
	}

	udph = get_udp_header(skb);
	if ((!udph) || (port == DNS_SERVER_PORT)) {
		data->dpi_result |= DPI_ID_QQ_APP;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}

	identify_qq_video_or_audio_stream(udph, port, data);

	return 0;
}

static int set_qq_scene(u32 scene, u32 is_enter) {
	s_qq_scene = scene;
	s_is_enter_qq = is_enter;
	if (!s_is_enter_qq) {
		s_is_match_completed = 0;
	}
	logt("receive qq scene notify, scene = %u, is_enter = %u", scene, is_enter);
	return 0;
}

int set_qq_uid(u32 uid)
{
	int ret = 0;

	u32 old_uid = s_qq_uid;
	s_qq_uid = uid;
	if (s_qq_uid != old_uid) {
		if (old_uid == 0) {
			ret = dpi_register_app_match(s_qq_uid, qq_match);
			logt("dpi_register_app_match qq uid %u return %d", s_qq_uid, ret);
			ret = dpi_register_deepthinker_scene(s_qq_uid, set_qq_scene);
			logt("dpi_register_deepthinker_scene qq scene notify uid %u return %d", s_qq_uid, ret);
		} else if (s_qq_uid == 0) {
			ret = dpi_unregister_app_match(s_qq_uid);
			logt("dpi_unregister_app_match qq uid %u return %d", s_qq_uid, ret);
			ret = dpi_unregister_deepthinker_scene(old_uid);
			logt("dpi_unregister_deepthinker_scene qq scene notify uid %u return %d", s_qq_uid, ret);
		} else {
			ret |= dpi_unregister_app_match(old_uid);
			ret |= dpi_register_app_match(s_qq_uid, qq_match);
			logt("dpi app uid change! tmgp uid %u %u return %d", s_qq_uid, old_uid, ret);
			ret = dpi_unregister_deepthinker_scene(old_uid);
			ret = dpi_register_deepthinker_scene(s_qq_uid, set_qq_scene);
			logt("dpi_register_deepthinker_scene qq scene notify uid %u return %d", s_qq_uid, ret);
		}
	}

	return ret;
}

static int qq_video_call_event(u64 dpi_id, int startStop)
{
	logt("qq_video_call_event %llx, %d", dpi_id, startStop);
	return 0;
}

static int qq_audio_call_event(u64 dpi_id, int startStop)
{
	logt("qq_audio_call_event %llx, %d", dpi_id, startStop);
	return 0;
}

int set_qq_stream_character(dpi_stream_character_data *data) {
	int err = 0;

	if (data->stream_id == DPI_ID_QQ_AUDIO_CALL_DATA) {
		err = kstrtol(data->pkgth, 10, &s_qq_audio_call_pkgth);
		if (err) {
			logt("pkgth is not a number, err = %d", err);
		}
		logt("set qq audio call pkgth = %ld", s_qq_audio_call_pkgth);
	}
	if (data->stream_id == DPI_ID_QQ_VIDEO_CALL_DATA) {
		err = kstrtol(data->pkgth, 10, &s_qq_video_call_pkgth);
		if (err) {
			logt("pkgth is not a number, err = %d", err);
		} else {
			logt("set qq video call pkgth = %ld", s_qq_video_call_pkgth);
		}
	}
	return err;
}

int qq_init(void)
{
	int ret = 0;
	ret = dpi_register_result_notify(DPI_ID_QQ_VIDEO_CALL_DATA, qq_video_call_event);
	if (ret) {
		logt("dpi_video_register_result_notify return %d", ret);
		return -1;
	}
	ret = dpi_register_result_notify(DPI_ID_QQ_AUDIO_CALL_DATA, qq_audio_call_event);
	if (ret) {
		logt("dpi_audio_register_result_notify return %d", ret);
		goto dpi_qq_audio_failed;
	}

	return 0;

dpi_qq_audio_failed:
	dpi_unregister_result_notify(DPI_ID_QQ_VIDEO_CALL_DATA, qq_video_call_event);
	return -1;
}

void qq_fini(void)
{
	int ret = 0;

	if (s_qq_uid) {
		ret = dpi_unregister_app_match(s_qq_uid);
		logt("dpi_unregister_app_match qq uid %u return %d", s_qq_uid, ret);
		s_qq_uid = 0;
	}
	dpi_unregister_result_notify(DPI_ID_QQ_VIDEO_CALL_DATA, qq_video_call_event);
	dpi_unregister_result_notify(DPI_ID_QQ_AUDIO_CALL_DATA, qq_audio_call_event);

	return;
}

