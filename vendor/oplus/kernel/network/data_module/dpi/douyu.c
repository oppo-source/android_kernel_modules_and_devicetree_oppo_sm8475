/***********************************************************
** Copyright (C), 2008-2022, oplus Mobile Comm Corp., Ltd.
** File: douyu.h
** Description: add douyu stream identify
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
#include "douyu.h"

#include "../include/netlink_api.h"
#include "../include/comm_def.h"
#include "../include/dpi_api.h"

#define LOG_TAG "DOUYU"

#define logt(fmt, args...) LOG(LOG_TAG, fmt, ##args)

#define DOUYU_PACKAGE_MATCH_MATCH_COUNT 5


static dpi_stream_character_data *s_douyu_live_charater_data = NULL;
static dpi_stream_character_data *s_douyu_living_charater_data = NULL;
static separate_str_data *s_douyu_http_field_str_data = NULL;

static char s_douyu_http_type[MAX_HTTP_TYPE];
static long s_douyu_living_dst_port = 0;

static spinlock_t s_douyu_lock;

static u32 s_douyu_uid = 0;
static u32 s_douyu_flag = 0;
/* s_douyu_scene == 2 vedio */
static u32 s_douyu_scene = 0;
static u32 s_is_enter_douyu = 0;


static int douyu_stream_match(struct sk_buff *skb, int dir, dpi_match_data_t *data)
{
	struct tcphdr *tcph = NULL;

	tcph = get_tcp_header(skb);
	spin_lock_bh(&s_douyu_lock);
	if (dir == 1 && tcph && http_request_match(skb, tcph, s_douyu_http_type, s_douyu_http_field_str_data)) {
		logt("match douyu live stream success");
		data->dpi_result |= DPI_ID_DOUYU_LIVE_STREAM_DATA;
		data->state = DPI_MATCH_STATE_COMPLETE;
		spin_unlock_bh(&s_douyu_lock);
		return 0;
	}
	spin_unlock_bh(&s_douyu_lock);
	if(tcph && s_douyu_scene == 3 && s_is_enter_douyu == 1 && data->tuple.peer_port == s_douyu_living_dst_port) {
		logt("match douyu living stream success");
		data->dpi_result |= DPI_ID_DOUYU_LIVING_STREAM_DATA;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}
	data->package_count += 1;
	if(data->package_count >= DOUYU_PACKAGE_MATCH_MATCH_COUNT) {
		data->dpi_result |= DPI_ID_DOUYU_APP;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}
	return 0;
}

static int set_douyu_scene(u32 scene, u32 is_enter) {
	s_douyu_scene = scene;
	s_is_enter_douyu = is_enter;
	logt("receive douyu scene notify, scene = %u, is_enter = %u", scene, is_enter);
	return 0;
}

int set_douyu_stream_character(dpi_stream_character_data *data) {
	int err = 0;

	if(data->stream_id == DPI_ID_DOUYU_LIVE_STREAM_DATA) {
		if(s_douyu_live_charater_data == NULL) {
			s_douyu_live_charater_data = kmalloc(sizeof(dpi_stream_character_data), GFP_ATOMIC);
			if (!s_douyu_live_charater_data) {
				logt("malloc s_douyu_live_charater_data failed!");
				return -1;
			}
		}
		spin_lock_bh(&s_douyu_lock);
		memset(s_douyu_live_charater_data, 0, sizeof(dpi_stream_character_data));
		memcpy(s_douyu_live_charater_data, data, sizeof(dpi_stream_character_data));
		strncpy(s_douyu_http_type, s_douyu_live_charater_data->httptype, sizeof(s_douyu_http_type) - 1);
		if(s_douyu_http_field_str_data != NULL) {
			free_str_array(s_douyu_http_field_str_data);
			s_douyu_http_field_str_data = NULL;
		}
		s_douyu_http_field_str_data = split_str_by_symbol(s_douyu_live_charater_data->httpfield, ",");
		spin_unlock_bh(&s_douyu_lock);
		logt("receive stream vedio character, streamId = %llx", data->stream_id);
	}
	if(data->stream_id == DPI_ID_DOUYU_LIVING_STREAM_DATA) {
		if(s_douyu_living_charater_data == NULL) {
			s_douyu_living_charater_data = kmalloc(sizeof(dpi_stream_character_data), GFP_ATOMIC);
			if (!s_douyu_living_charater_data) {
				logt("malloc s_douyu_living_charater_data failed!");
				return -1;
			}
		}
		memset(s_douyu_living_charater_data, 0, sizeof(dpi_stream_character_data));
		memcpy(s_douyu_living_charater_data, data, sizeof(dpi_stream_character_data));
		err = kstrtol(s_douyu_living_charater_data->dstport, 10, &s_douyu_living_dst_port);
		if(err) {
			logt("dstport is not a number, err = %d", err);
		}
		logt("receive live stream character, streamId = %llx", data->stream_id);
	}
	return 0;
}

int set_douyu_uid(u32 uid)
{
	int ret = 0;
	u32 old_uid = s_douyu_uid;
	s_douyu_uid = uid;
	logt("s_douyu_uid == %u", uid);
	if (s_douyu_uid != old_uid) {
		if (old_uid == 0) {
			ret = dpi_register_app_match(s_douyu_uid, douyu_stream_match);
			logt("dpi_register_app_match douyu uid %u return %d", s_douyu_uid, ret);
			ret = dpi_register_deepthinker_scene(s_douyu_uid, set_douyu_scene);
			logt("dpi_register_deepthinker_scene douyu scene notify");
		} else if (uid == 0) {
			ret = dpi_unregister_app_match(old_uid);
			logt("dpi_unregister_app_match douyu uid %u return %d", s_douyu_uid, ret);
			ret = dpi_unregister_deepthinker_scene(old_uid);
		} else {
			ret |= dpi_unregister_app_match(old_uid);
			ret |= dpi_register_app_match(s_douyu_uid, douyu_stream_match);
			logt("dpi app uid change! douyu uid %u %u return %d", s_douyu_uid, old_uid, ret);
			ret = dpi_unregister_deepthinker_scene(old_uid);
			ret = dpi_register_deepthinker_scene(s_douyu_uid, set_douyu_scene);
			logt("dpi_register_deepthinker_scene douyu scene notify");
		}
	}
	return ret;
}

/* start 1, stop 0 */
static int douyu_status_event(u64 dpi_id, int startStop)
{
	if(startStop) {
		if(s_douyu_flag == 0) {
			s_douyu_flag = 1;
			logt("douyu_status_event start, streamId = %llx", dpi_id);
		}
	} else {
		s_douyu_flag = 0;
		logt("douyu_status_event stop, streamId = %llx", dpi_id);
	}
	return 0;
}

int douyu_init(void)
{
	int ret = 0;

	spin_lock_init(&s_douyu_lock);

	ret |= dpi_register_result_notify(DPI_ID_DOUYU_LIVE_STREAM_DATA, douyu_status_event);
	if(ret) {
		logt("douyu_init douyu_status_event register failed");
		return ret;
	}
	ret |= dpi_register_result_notify(DPI_ID_DOUYU_LIVING_STREAM_DATA, douyu_status_event);
	if(ret) {
		dpi_unregister_result_notify(DPI_ID_DOUYU_LIVE_STREAM_DATA, douyu_status_event);
		logt("douyu_init douyu_status_event register failed");
		return ret;
	}
	return 0;
}

void douyu_fini(void)
{
	int ret = 0;

	if (s_douyu_uid) {
		ret = dpi_unregister_app_match(s_douyu_uid);
		logt("dpi_unregister_app_match douyu uid %u return %d", s_douyu_uid, ret);
		s_douyu_uid = 0;
	}

	if(s_douyu_live_charater_data) {
		kfree(s_douyu_live_charater_data);
		s_douyu_live_charater_data = NULL;
	}
	if(s_douyu_living_charater_data) {
		kfree(s_douyu_living_charater_data);
		s_douyu_living_charater_data = NULL;
	}
	if(s_douyu_http_field_str_data) {
		free_str_array(s_douyu_http_field_str_data);
	}

	dpi_unregister_result_notify(DPI_ID_DOUYU_LIVE_STREAM_DATA, douyu_status_event);
	dpi_unregister_result_notify(DPI_ID_DOUYU_LIVING_STREAM_DATA, douyu_status_event);


	return;
}
