/***********************************************************
** Copyright (C), 2008-2022, oplus Mobile Comm Corp., Ltd.
** File: dpi_api.h
** Description: Add dpi interface
**
** Version: 1.0
** Date : 2022/6/24
** Author: ShiQianhua
**
** ------------------ Revision History:------------------------
** <author> <data> <version > <desc>
** shiqianhua 2022/6/24 1.0 build this module
****************************************************************/

#ifndef __DPI_API_H__
#define __DPI_API_H__

#define DPI_ID_APP_MASK 0xFFFF0000
#define DPI_ID_FUNC_MASK 0xFFFFFF00
#define DPI_ID_STREAM_MASK 0xFFFFFFFF
#define DPI_ID_UID_MASK 0xFFFFFFFF00000000

#define DPI_ID_UID_BIT_OFFSET 32

#define DPI_ID_TMGP_SGAME_APP  0x10000
#define DPI_ID_TMGP_SGAME_FUNC_GAME  0x10100
#define DPI_ID_TMGP_SGAME_STREAM_GAME_DATA  0x10101

#define DPI_ID_HEYTAP_MARKET_APP	0x20000
#define DPI_ID_HEYTAP_MARKET_FUNC_DOWNLOAD	0x20100
#define DPI_ID_HEYTAP_MARKET_STREAM_DOWNLOAD_DATA	0x20101

#define DPI_ID_SYSTEM_APP 0x30000
#define DPI_ID_LOG_KIT_FUNC 0x30100
#define DPI_ID_LOG_KIT_STREAM_DATA 0x30101

#define DPI_ID_ZOOM_APP 0x40000
#define DPI_ID_ZOOM_FUNC 0x40100
#define DPI_ID_ZOOM_MEETING_STREAM_DATA 0x40101

#define DPI_ID_TENCENT_MEETING_APP 0x50000
#define DPI_ID_TENCENT_MEETING_FUNC 0x50100
#define DPI_ID_TENCENT_MEETING_STREAM_DATA 0x50101

#define DPI_ID_WECHAT_APP  0x60000
#define DPI_ID_WECHAT_FUNC  0x60100
#define DPI_ID_WECHAT_VIDEO_CALL_DATA  0x60101
#define DPI_ID_WECHAT_AUDIO_CALL_DATA  0x60102

#define DPI_ID_DOUYU_APP 0x70000
#define DPI_ID_DOUYU_FUNC 0x70100
#define DPI_ID_DOUYU_LIVE_STREAM_DATA 0x70101
#define DPI_ID_DOUYU_LIVING_STREAM_DATA 0x70102

#define DPI_ID_HUYA_APP 0x80000
#define DPI_ID_HUYA_FUNC 0x80100
#define DPI_ID_HUYA_LIVE_STREAM_DATA 0x80101
#define DPI_ID_HUYA_LIVING_STREAM_DATA 0x80102

#define DPI_ID_YOUKU_APP 0x90000
#define DPI_ID_YOUKU_FUNC 0x90100
#define DPI_ID_YOUKU_VIDEO_STREAM_DATA 0x90101

#define DPI_ID_IQIYI_APP 0xa0000
#define DPI_ID_IQIYI_FUNC 0xa0100
#define DPI_ID_IQIYI_VIDEO_STREAM_DATA 0xa0101

#define DPI_ID_BILIBILI_APP 0xb0000
#define DPI_ID_BILIBILI_FUNC 0xb0100
#define DPI_ID_BILIBILI_VIDEO_STREAM_DATA 0xb0101
#define DPI_ID_BILIBILI_LIVE_STREAM_DATA 0xb0102
#define DPI_ID_BILIBILI_LIVING_STREAM_DATA 0xb0103

#define DPI_ID_DOUYIN_APP  0xc0000
#define DPI_ID_DOUYIN_FUNC  0xc0100
#define DPI_ID_DOUYIN_SHORT_VIDEO_DATA  0xc0101
#define DPI_ID_DOUYIN_LIVE_PLAY_DATA  0xc0102
#define DPI_ID_DOUYIN_LIVE_BROADCAST_DATA  0xc0103

#define DPI_ID_KUAISHOU_APP  0xd0000
#define DPI_ID_KUAISHOU_FUNC  0xd0100
#define DPI_ID_KUAISHOU_SHORT_VIDEO_DATA  0xd0101
#define DPI_ID_KUAISHOU_LIVE_PLAY_DATA  0xd0102
#define DPI_ID_KUAISHOU_LIVE_BROADCAST_DATA  0xd0103

#define DPI_ID_QQ_APP  0xe0000
#define DPI_ID_QQ_FUNC  0xe0100
#define DPI_ID_QQ_VIDEO_CALL_DATA  0xe0101
#define DPI_ID_QQ_AUDIO_CALL_DATA  0xe0102

enum dpi_type_e {
	DPI_TYPE_UNSPEC,
	DPI_TYPE_UID,
	DPI_TYPE_APP,
	DPI_TYPE_FUNC,
	DPI_TYPE_STREAM,
	DPI_TYPE_MAX,
};

enum dpi_scene_e {
	DPI_SCENE_VIDEO_MEETING = 1,
	DPI_SCENE_VIDEO = 2,
	DPI_SCENE_VIDEO_LIVE = 3,
	DPI_SCENE_VIDEO_CALL = 4,
	DPI_SCENE_AUDIO_CALL = 5,
	DPI_SCENE_GAME_PLAYING = 6,
};

typedef int (*dpi_notify_fun)(u64 dpi_id, int startStop);


int dpi_register_result_notify(u64 dpi_id, dpi_notify_fun fun);
int dpi_unregister_result_notify(u64 dpi_id, dpi_notify_fun fun);

u64 get_skb_dpi_id(struct sk_buff *skb, int dir, int in_dev);

static inline int check_dpi_stream_result(u64 dpi_result, u64 dpi_stream_id) {
	if((dpi_result & DPI_ID_STREAM_MASK) == dpi_stream_id) {
		return 1;
	}
	return 0;
}

#endif /* __DPI_API_H__ */
