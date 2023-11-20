/***********************************************************
** Copyright (C), 2008-2022, oplus Mobile Comm Corp., Ltd.
** File: huya.h
** Description: add huya stream identify
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
#include "huya.h"

#include "../include/netlink_api.h"
#include "../include/comm_def.h"
#include "../include/dpi_api.h"

#define LOG_TAG "HUYA"

#define logt(fmt, args...) LOG(LOG_TAG, fmt, ##args)

#define HUYA_PACKAGE_MATCH_MATCH_COUNT 5

static dpi_stream_character_data *s_huya_live_charater_data = NULL;
static dpi_stream_character_data *s_huya_living_charater_data = NULL;
static separate_str_data *s_huya_http_field_str_data = NULL;


static char s_huya_http_type[MAX_HTTP_TYPE];

static spinlock_t s_huya_lock;

static u32 s_huya_uid = 0;
static u32 s_huya_flag = 0;
/* s_huya_scene == 2 live
 s_douyu_scene == 3 living
*/
static u32 s_huya_scene = 0;
static u32 s_is_enter_huya = 0;

static int huya_stream_match(struct sk_buff *skb, int dir, dpi_match_data_t *data)
{
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	if(data->tuple.peer_port == DNS_SERVER_PORT) {
		data->dpi_result |= DPI_ID_HUYA_APP;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}
	tcph = get_tcp_header(skb);
	spin_lock_bh(&s_huya_lock);
	if (tcph && dir == 1 && http_request_match(skb, tcph, s_huya_http_type, s_huya_http_field_str_data)) {
		logt("match huya live stream success");
		data->dpi_result |= DPI_ID_HUYA_LIVE_STREAM_DATA;
		data->state = DPI_MATCH_STATE_COMPLETE;
		spin_unlock_bh(&s_huya_lock);
		return 0;
	}
	spin_unlock_bh(&s_huya_lock);
	udph = get_udp_header(skb);
	if (udph && s_huya_scene == 3 && s_is_enter_huya == 1) {
		logt("match huya living stream success");
		data->dpi_result |= DPI_ID_HUYA_LIVING_STREAM_DATA;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}
	data->package_count += 1;
	if(data->package_count >= HUYA_PACKAGE_MATCH_MATCH_COUNT) {
		data->dpi_result |= DPI_ID_HUYA_APP;
		data->state = DPI_MATCH_STATE_COMPLETE;
		return 0;
	}
	return 0;
}

static int set_huya_scene(u32 scene, u32 is_enter) {
	s_huya_scene = scene;
	s_is_enter_huya = is_enter;
	logt("receive huya scene notify, scene = %u, is_enter = %u", scene, is_enter);
	return 0;
}

int set_huya_stream_character(dpi_stream_character_data *data) {
	if(data->stream_id == DPI_ID_HUYA_LIVE_STREAM_DATA) {
		if(s_huya_live_charater_data == NULL) {
			s_huya_live_charater_data = kmalloc(sizeof(dpi_stream_character_data), GFP_ATOMIC);
			if (!s_huya_live_charater_data) {
				logt("malloc s_huya_live_charater_data failed!");
				return -1;
			}
		}
		spin_lock_bh(&s_huya_lock);
		memset(s_huya_live_charater_data, 0, sizeof(dpi_stream_character_data));
		memcpy(s_huya_live_charater_data, data, sizeof(dpi_stream_character_data));
		memset(s_huya_http_type, 0, sizeof(s_huya_http_type));
		strncpy(s_huya_http_type, s_huya_live_charater_data->httptype, sizeof(s_huya_http_type) - 1);
		if(s_huya_http_field_str_data != NULL) {
			free_str_array(s_huya_http_field_str_data);
			s_huya_http_field_str_data = NULL;
		}
		s_huya_http_field_str_data = split_str_by_symbol(s_huya_live_charater_data->httpfield, ",");
		spin_unlock_bh(&s_huya_lock);
		logt("receive stream live character, streamId = %llx", data->stream_id);
	}
	if(data->stream_id == DPI_ID_HUYA_LIVING_STREAM_DATA) {
		if(s_huya_living_charater_data == NULL) {
			s_huya_living_charater_data = kmalloc(sizeof(dpi_stream_character_data), GFP_ATOMIC);
			if (!s_huya_living_charater_data) {
				logt("malloc s_huya_living_charater_data failed!");
				return -1;
			}
		}
		memset(s_huya_living_charater_data, 0, sizeof(dpi_stream_character_data));
		memcpy(s_huya_living_charater_data, data, sizeof(dpi_stream_character_data));
		logt("receive living stream character, streamId = %llx", data->stream_id);
	}
	return 0;
}

int set_huya_uid(u32 uid)
{
	int ret = 0;
	u32 old_uid = s_huya_uid;
	s_huya_uid = uid;
	logt("s_huya_uid == %u", uid);
	if (s_huya_uid != old_uid) {
		if (old_uid == 0) {
			ret = dpi_register_app_match(s_huya_uid, huya_stream_match);
			logt("dpi_register_app_match huya uid %u return %d", s_huya_uid, ret);
			ret = dpi_register_deepthinker_scene(s_huya_uid, set_huya_scene);
			logt("dpi_register_deepthinker_scene huya scene notify");
		} else if (uid == 0) {
			ret = dpi_unregister_app_match(old_uid);
			logt("dpi_unregister_app_match huya uid %u return %d", s_huya_uid, ret);
			ret = dpi_unregister_deepthinker_scene(old_uid);
		} else {
			ret |= dpi_unregister_app_match(old_uid);
			ret |= dpi_register_app_match(s_huya_uid, huya_stream_match);
			logt("dpi app uid change! huya uid %u %u return %d", s_huya_uid, old_uid, ret);
			ret = dpi_unregister_deepthinker_scene(old_uid);
			ret = dpi_register_deepthinker_scene(s_huya_uid, set_huya_scene);
			logt("dpi_register_deepthinker_scene huya scene notify");
		}
	}
	return ret;
}

/* start 1, stop 0 */
static int huya_status_event(u64 dpi_id, int startStop)
{
	if(startStop) {
		if(s_huya_flag == 0) {
			s_huya_flag = 1;
			logt("huya_status_event start, streamId = %llx", dpi_id & DPI_ID_STREAM_MASK);
		}
	} else {
		s_huya_flag = 0;
		logt("huya_status_event stop, streamId = %llx", dpi_id & DPI_ID_STREAM_MASK);
	}
	return 0;
}

int huya_init(void)
{
	int ret = 0;

	spin_lock_init(&s_huya_lock);

	ret |= dpi_register_result_notify(DPI_ID_HUYA_LIVE_STREAM_DATA, huya_status_event);
	if(ret) {
		logt("dpi_register_result_notify failed, return %d", ret);
		return ret;
	}
	ret |= dpi_register_result_notify(DPI_ID_HUYA_LIVING_STREAM_DATA, huya_status_event);
	if(ret) {
		dpi_unregister_result_notify(DPI_ID_HUYA_LIVE_STREAM_DATA, huya_status_event);
		logt("dpi_register_result_notify failed, return %d", ret);
		return ret;
	}

	return 0;
}

void huya_fini(void)
{
	int ret = 0;

	if (s_huya_uid) {
		ret = dpi_unregister_app_match(s_huya_uid);
		logt("dpi_unregister_app_match huya uid %u return %d", s_huya_uid, ret);
		s_huya_uid = 0;
	}

	if(s_huya_live_charater_data) {
		kfree(s_huya_live_charater_data);
		s_huya_live_charater_data = NULL;
	}
	if(s_huya_living_charater_data) {
		kfree(s_huya_living_charater_data);
		s_huya_living_charater_data = NULL;
	}

	if(s_huya_http_field_str_data) {
		free_str_array(s_huya_http_field_str_data);
	}

	dpi_unregister_result_notify(DPI_ID_HUYA_LIVE_STREAM_DATA, huya_status_event);
	dpi_unregister_result_notify(DPI_ID_HUYA_LIVING_STREAM_DATA, huya_status_event);


	return;
}
