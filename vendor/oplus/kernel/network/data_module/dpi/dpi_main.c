/***********************************************************
** Copyright (C), 2008-2022, oplus Mobile Comm Corp., Ltd.
** File: dpi_main.h
** Description: add dpi_main stream identify
**
** Version: 1.0
** Date : 2023/08/31
** Author: Zhangpeng
**
** ------------------ Revision History:------------------------
** <author> <data> <version > <desc>
** Zhangpeng 2023/08/31 1.0 build this module
****************************************************************/

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/genetlink.h>
#include "../include/netlink_api.h"
#include "../include/comm_def.h"
#include "../include/dpi_api.h"

#include "../proto-src/netlink_msg.pb-c.h"
#include "dpi_main.h"
#include "dpi_core.h"
#include "log_stream.h"
#include "tmgp_sgame.h"
#include "heytap_market.h"
#include "zoom.h"
#include "tencent_meeting.h"
#include "wechat.h"
#include "douyu.h"
#include "huya.h"
#include "youku.h"
#include "iqiyi.h"
#include "bilibili.h"
#include "douyin.h"
#include "kuaishou.h"
#include "qq.h"

#define LOG_TAG "dpi_main"

extern int tmgp_sgame_init(void);
extern void tmgp_sgame_fini(void);

extern int wzry_stats_init(void);
extern void wzry_stats_fini(void);

extern int log_stream_init(void);
extern void log_stream_fini(void);

extern int game_main_stream_monitor_init(void);
extern void game_main_stream_monitor_fint(void);

extern int zoom_init(void);
extern void zoom_fini(void);

extern int tencent_meeting_init(void);
extern void tencent_meeting_fini(void);

extern int wechat_init(void);
extern void wechat_fini(void);

extern int douyu_init(void);
extern void douyu_fini(void);

extern int huya_init(void);
extern void huya_fini(void);

extern int youku_init(void);
extern void youku_fini(void);

extern int iqiyi_init(void);
extern void iqiyi_fini(void);

extern int bilibili_init(void);
extern void bilibili_fini(void);

extern int douyin_init(void);
extern void bilibili_fini(void);

extern int kuaishou_init(void);
extern void kuaishou_fini(void);

extern int qq_init(void);
extern void qq_fini(void);

static int s_debug = 0;

#define logt(fmt, args...) LOG(LOG_TAG, fmt, ##args)
#define logi(fmt, args...) do { \
	if (s_debug) { \
		LOG(LOG_TAG, fmt, ##args); \
	} \
} while (0)

static spinlock_t s_scene_lock;
static spinlock_t s_dpi_main_lock;

static struct hlist_head s_scene_notify_head;

static u32 s_scene_notify_count = 0;

typedef struct {
	struct hlist_node node;
	u32 uid;
	dpi_scene_notify_fun fun;
} dpi_scene_config;

typedef struct dpi_init_st
{
	int (*init)(void);
	void (*exit)(void);
}dpi_main_init_st;

static dpi_main_init_st s_data_init[] = {
	{.init = tmgp_sgame_init, .exit = tmgp_sgame_fini},
	/*
	{.init = wzry_stats_init, .exit = wzry_stats_fini},
	*/
	{.init = log_stream_init, .exit = log_stream_fini},
	{.init = game_main_stream_monitor_init, .exit = game_main_stream_monitor_fint},
	{.init = zoom_init, .exit = zoom_fini},
	{.init = tencent_meeting_init, .exit = tencent_meeting_fini},
	{.init = wechat_init, .exit = wechat_fini},
	{.init = douyu_init, .exit = douyu_fini},
	{.init = huya_init, .exit = huya_fini},
	{.init = youku_init, .exit = youku_fini},
	{.init = iqiyi_init, .exit = iqiyi_fini},
	{.init = bilibili_init, .exit = bilibili_fini},
	{.init = douyin_init, .exit = kuaishou_fini},
	{.init = kuaishou_init, .exit = kuaishou_fini},
	{.init = qq_init, .exit = qq_fini},
};

int dpi_register_deepthinker_scene(u32 uid, dpi_scene_notify_fun fun)
{
	dpi_scene_config *pos = NULL;

	spin_lock_bh(&s_scene_lock);
	hlist_for_each_entry(pos, &s_scene_notify_head, node) {
		if (pos->uid == uid) {
			spin_unlock_bh(&s_scene_lock);
			logt("already set!");
			return 0;
		}
	}
	pos = kmalloc(sizeof(dpi_scene_config), GFP_ATOMIC);
	if(!pos) {
		logt("malloc dpi_scene_config failed!");
		spin_unlock_bh(&s_scene_lock);
		return -1;
	}
	INIT_HLIST_NODE(&pos->node);
	pos->uid = uid;
	pos->fun = fun;
	hlist_add_head(&pos->node, &s_scene_notify_head);
	s_scene_notify_count++;
	spin_unlock_bh(&s_scene_lock);

	return 0;
}

int dpi_unregister_deepthinker_scene(u32 uid)
{
	dpi_scene_config *pos = NULL;
	struct hlist_node *n = NULL;

	spin_lock_bh(&s_scene_lock);
	hlist_for_each_entry_safe(pos, n, &s_scene_notify_head, node) {
		if (pos->uid == uid) {
			hlist_del_init(&pos->node);
			kfree(pos);
			s_scene_notify_count--;
			break;
		}
	}
	spin_unlock_bh(&s_scene_lock);
	return 0;
}

static void dpi_notify_scene_event(u32 uid, u32 scene, u32 is_enter)
{
	dpi_scene_config *pos = NULL;

	spin_lock_bh(&s_scene_lock);
	hlist_for_each_entry(pos, &s_scene_notify_head, node) {
		if (pos->uid == uid) {
			pos->fun(scene, is_enter);
		}
	}
	spin_unlock_bh(&s_scene_lock);
}

separate_str_data *split_str_by_symbol(char *input, const char *separator) {
	separate_str_data *field_result = NULL;
	char *token = NULL;
	int split_count = 0;
	int token_length = 0;

	field_result = kmalloc(sizeof(separate_str_data), GFP_ATOMIC);
	if (!field_result) {
		logt("Memory allocation failed");
		return NULL;
	}

	while ((token = strsep(&input, separator)) != NULL) {
		token_length = strlen(token);
		if(token_length >= MAX_TOKEN_LENGTH) {
			logt("Token length is too long");
			continue;
		}
		if (split_count >= MAX_FIELD_LENGTH) {
			logt("Filed length is too long");
			break;
		}
		strncpy(field_result->field[split_count], token, strlen(token));
		field_result->field[split_count][token_length] = '\0';
		split_count++;
	}
	field_result->field_length = split_count;
	return field_result;
}

void free_str_array(separate_str_data *field) {
	kfree(field);
	field = NULL;
}

int http_request_match(struct sk_buff *skb, struct tcphdr *tcp_header, char *http_request_type, separate_str_data *http_field_data) {
	int i = 0;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	int tcp_payload_length = 0;
	int http_data_offset = 0;
	int http_request_len = 0;
	char *http_request_end = NULL;
	char *payload_str = NULL;
	char *http_request_line = NULL;
	if(http_request_type == NULL || http_field_data == NULL) {
		return 0;
	}
	if(skb->protocol == htons(ETH_P_IP)) {
		iph = ip_hdr(skb);
		tcp_payload_length = ntohs(iph->tot_len) - (iph->ihl) * 4 - (tcp_header->doff) * 4;
	} else {
		ip6h = ipv6_hdr(skb);
		tcp_payload_length = ntohs(ip6h->payload_len) - (tcp_header->doff) * 4;
	}
	if(tcp_payload_length <= 0) {
		logi("tcp_payload_length <= 0");
		return 0;
	}
	http_data_offset = skb->len - skb->data_len;
	payload_str = kmalloc(skb->data_len + 1, GFP_ATOMIC);
	if(!payload_str) {
		logt("kmalloc payload_str failed");
		return 0;
	}
	memset(payload_str, 0, skb->data_len + 1);
	if (!skb_header_pointer(skb, http_data_offset, skb->data_len, payload_str)) {
		logi("skb_header_pointer null");
		kfree(payload_str);
		payload_str = NULL;
		return 0;
	}
	http_request_end = strstr(payload_str, "\r\n");
	if(!http_request_end) {
		kfree(payload_str);
		payload_str = NULL;
		logi("http_request_end null");
		return 0;
	}
	http_request_len = http_request_end - payload_str;
	if(http_request_len <= 0 || http_request_len > MAX_REQUEST_LINE_LENGTH) {
		logi("http_request_len illegal");
		kfree(payload_str);
		payload_str = NULL;
		return 0;
	}
	http_request_line = kmalloc(http_request_len + 1, GFP_ATOMIC);
	if(!http_request_line) {
		kfree(payload_str);
		payload_str = NULL;
		logt("kmalloc http_request_line failed");
		return 0;
	}
	memset(http_request_line, 0, http_request_len + 1);
	strncpy(http_request_line, payload_str, http_request_len);
	http_request_line[http_request_len] = '\0';
	logi("http_request_line : %s", http_request_line);
	if(strstr(http_request_line, http_request_type)) {
		for(;i < http_field_data->field_length; i++) {
			if(strlen(http_field_data->field[i]) > 0 && strstr(http_request_line, http_field_data->field[i])) {
				kfree(payload_str);
				kfree(http_request_line);
				payload_str = NULL;
				http_request_line = NULL;
				return 1;
			}
		}
	}
	kfree(http_request_line);
	kfree(payload_str);
	payload_str = NULL;
	http_request_line = NULL;
	return 0;
}

struct tcphdr *get_tcp_header(struct sk_buff *skb)
{
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;

	if (skb->protocol == htons(ETH_P_IP)) {
		iph = ip_hdr(skb);
		if (!iph || iph->protocol != IPPROTO_TCP) {
			return NULL;
		}
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		ip6h = ipv6_hdr(skb);
		if (!ip6h || ip6h->nexthdr != IPPROTO_TCP) {
			return NULL;
		}
	} else {
		return NULL;
	}

	return tcp_hdr(skb);
}

struct udphdr *get_udp_header(struct sk_buff *skb)
{
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;

	if (skb->protocol == htons(ETH_P_IP)) {
		iph = ip_hdr(skb);
		if (!iph || iph->protocol != IPPROTO_UDP) {
			return NULL;
		}
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		ip6h = ipv6_hdr(skb);
		if (!ip6h || ip6h->nexthdr != IPPROTO_UDP) {
			return NULL;
		}
	} else {
		return NULL;
	}

	return udp_hdr(skb);
}

static int request_set_dpi_uid(u32 eventid, Netlink__Proto__RequestMessage *requestMsg, char **rsp_data, u32 *rsp_len)
{
	if ((requestMsg->request_data_case != NETLINK__PROTO__REQUEST_MESSAGE__REQUEST_DATA_REQUSET_SET_DPI_UID)
		|| (!requestMsg->requsetsetdpiuid)) {
		return COMM_NETLINK_ERR_PARAM;
	}
	set_tmgp_sgame_uid(requestMsg->requsetsetdpiuid->tmgpsgameuid);
	set_heytap_market_uid(requestMsg->requsetsetdpiuid->haytapmarketuid);
	set_system_uid(requestMsg->requsetsetdpiuid->logkituid);
	if(requestMsg->requsetsetdpiuid->has_zoomuid) {
		set_zoom_uid(requestMsg->requsetsetdpiuid->zoomuid);
	}
	if(requestMsg->requsetsetdpiuid->has_tencentmeetinguid) {
		set_tencent_meeting_uid(requestMsg->requsetsetdpiuid->tencentmeetinguid);
	}
	if(requestMsg->requsetsetdpiuid->has_wechatuid) {
		set_wechat_uid(requestMsg->requsetsetdpiuid->wechatuid);
	}
	if(requestMsg->requsetsetdpiuid->has_douyuuid) {
		set_douyu_uid(requestMsg->requsetsetdpiuid->douyuuid);
	}
	if(requestMsg->requsetsetdpiuid->has_huyauid) {
		set_huya_uid(requestMsg->requsetsetdpiuid->huyauid);
	}
	if(requestMsg->requsetsetdpiuid->has_youkuuid) {
		set_youku_uid(requestMsg->requsetsetdpiuid->youkuuid);
	}
	if(requestMsg->requsetsetdpiuid->has_iqiyiuid) {
		set_iqiyi_uid(requestMsg->requsetsetdpiuid->iqiyiuid);
	}
	if(requestMsg->requsetsetdpiuid->has_bilibiliuid) {
		set_bilibili_uid(requestMsg->requsetsetdpiuid->bilibiliuid);
	}
	if(requestMsg->requsetsetdpiuid->has_douyinuid) {
		set_douyin_uid(requestMsg->requsetsetdpiuid->douyinuid);
	}
	if(requestMsg->requsetsetdpiuid->has_kuaishouuid) {
		set_kuaishou_uid(requestMsg->requsetsetdpiuid->kuaishouuid);
	}
	if(requestMsg->requsetsetdpiuid->has_qquid) {
		set_qq_uid(requestMsg->requsetsetdpiuid->qquid);
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
		logi("request_set_dpi_uid pack len %lu  buf len %lu", pack_len, len);
		*rsp_data = buf;
		*rsp_len = len;
	} while (0);

	return COMM_NETLINK_SUCC;
}

static int request_set_scene(u32 eventid, Netlink__Proto__RequestMessage *requestMsg, char **rsp_data, u32 *rsp_len)
{
	if ((requestMsg->request_data_case != NETLINK__PROTO__REQUEST_MESSAGE__REQUEST_DATA_REQUEST_SET_SCENE)
		|| (!requestMsg->requestsetscene)) {
		return COMM_NETLINK_ERR_PARAM;
	}

	dpi_notify_scene_event(requestMsg->requestsetscene->uid, requestMsg->requestsetscene->scene, requestMsg->requestsetscene->entertype);

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
		logi("request_set_scene pack len %lu  buf len %lu", pack_len, len);
		*rsp_data = buf;
		*rsp_len = len;
	} while (0);

	return COMM_NETLINK_SUCC;
}

static int request_set_stream_charater(u32 eventid, Netlink__Proto__RequestMessage *requestMsg, char **rsp_data, u32 *rsp_len)
{
	dpi_stream_character_data *stream_character_data = NULL;
	if ((requestMsg->request_data_case != NETLINK__PROTO__REQUEST_MESSAGE__REQUEST_DATA_REQUEST_SET_CHARATER)
		|| (!requestMsg->requestsetcharater)) {
		return COMM_NETLINK_ERR_PARAM;
	}

	stream_character_data = kmalloc(sizeof(dpi_stream_character_data), GFP_ATOMIC);
	if (!stream_character_data) {
		logt("malloc stream_character_data failed !");
		return COMM_NETLINK_ERR_MEMORY;
	}
	memset(stream_character_data, 0, sizeof(dpi_stream_character_data));
	stream_character_data->stream_id = requestMsg->requestsetcharater->streamid;
	if(requestMsg->requestsetcharater->transportprotocol != NULL) {
		if(strlen(requestMsg->requestsetcharater->transportprotocol) > DPI_STREAM_CHARACTER_LENGTH) {
			kfree(stream_character_data);
			return COMM_NETLINK_ERR_MEMORY;
		}
		strncpy(stream_character_data->transportprotocol, requestMsg->requestsetcharater->transportprotocol, (DPI_STREAM_CHARACTER_LENGTH - 1));
		logi("kernel receive stream config : %s", stream_character_data->transportprotocol);
	}
	if(requestMsg->requestsetcharater->dstport != NULL) {
		if(strlen(requestMsg->requestsetcharater->dstport) > DPI_STREAM_CHARACTER_LENGTH) {
			kfree(stream_character_data);
			return COMM_NETLINK_ERR_MEMORY;
		}
		strncpy(stream_character_data->dstport, requestMsg->requestsetcharater->dstport, (DPI_STREAM_CHARACTER_LENGTH - 1));
		logi("kernel receive stream config : %s", stream_character_data->dstport);
	}
	if(requestMsg->requestsetcharater->url != NULL) {
		if(strlen(requestMsg->requestsetcharater->url) > DPI_STREAM_CHARACTER_LENGTH) {
			kfree(stream_character_data);\
			return COMM_NETLINK_ERR_MEMORY;
		}
		strncpy(stream_character_data->url, requestMsg->requestsetcharater->url, (DPI_STREAM_CHARACTER_LENGTH - 1));
		logi("kernel receive stream config : %s", requestMsg->requestsetcharater->url);
	}
	if(requestMsg->requestsetcharater->httptype != NULL) {
		if(strlen(requestMsg->requestsetcharater->httptype) > DPI_STREAM_CHARACTER_LENGTH) {
			kfree(stream_character_data);
			return COMM_NETLINK_ERR_MEMORY;
		}
		strncpy(stream_character_data->httptype, requestMsg->requestsetcharater->httptype, (DPI_STREAM_CHARACTER_LENGTH - 1));
		logi("kernel receive stream config : %s", stream_character_data->httptype);
	}
	if(requestMsg->requestsetcharater->httpfield != NULL) {
		if(strlen(requestMsg->requestsetcharater->httpfield) > DPI_STREAM_CHARACTER_LENGTH) {
			kfree(stream_character_data);
			return COMM_NETLINK_ERR_MEMORY;
		}
		strncpy(stream_character_data->httpfield, requestMsg->requestsetcharater->httpfield, (DPI_STREAM_CHARACTER_LENGTH - 1));
		logi("kernel receive stream config : %s", stream_character_data->httpfield);
	}
	if(requestMsg->requestsetcharater->downpkgth != NULL) {
		if(strlen(requestMsg->requestsetcharater->downpkgth) > DPI_STREAM_CHARACTER_LENGTH) {
			kfree(stream_character_data);
			return COMM_NETLINK_ERR_MEMORY;
		}
		strncpy(stream_character_data->downpkgth, requestMsg->requestsetcharater->downpkgth, (DPI_STREAM_CHARACTER_LENGTH - 1));
		logi("kernel receive stream config : %s", stream_character_data->downpkgth);
	}
	if(requestMsg->requestsetcharater->uppkgth != NULL) {
		if(strlen(requestMsg->requestsetcharater->uppkgth) > (DPI_STREAM_CHARACTER_LENGTH - 1)) {
			kfree(stream_character_data);
			return COMM_NETLINK_ERR_MEMORY;
		}
		strncpy(stream_character_data->uppkgth, requestMsg->requestsetcharater->uppkgth, (DPI_STREAM_CHARACTER_LENGTH - 1));
		logi("kernel receive stream config : %s", stream_character_data->uppkgth);
	}
	if(requestMsg->requestsetcharater->pkgth != NULL) {
		if(strlen(requestMsg->requestsetcharater->pkgth) > (DPI_STREAM_CHARACTER_LENGTH - 1)) {
			kfree(stream_character_data);
			return COMM_NETLINK_ERR_MEMORY;
		}
		strncpy(stream_character_data->pkgth, requestMsg->requestsetcharater->pkgth, (DPI_STREAM_CHARACTER_LENGTH - 1));
		logi("kernel receive stream config : %s", stream_character_data->pkgth);
	}
	if(requestMsg->requestsetcharater->uppkgmagic != NULL) {
		if(strlen(requestMsg->requestsetcharater->uppkgmagic) > DPI_STREAM_CHARACTER_LENGTH) {
			kfree(stream_character_data);
			return COMM_NETLINK_ERR_MEMORY;
		}
		strncpy(stream_character_data->uppkgmagic, requestMsg->requestsetcharater->uppkgmagic, (DPI_STREAM_CHARACTER_LENGTH - 1));
		logi("kernel receive stream config : %s", stream_character_data->uppkgmagic);
	}
	switch (stream_character_data->stream_id & DPI_ID_APP_MASK) {
	case DPI_ID_ZOOM_APP :
		set_zoom_stream_character(stream_character_data);
		break;
	case DPI_ID_TENCENT_MEETING_APP :
		set_tencent_meeting_stream_character(stream_character_data);
		break;
	case DPI_ID_DOUYU_APP :
		set_douyu_stream_character(stream_character_data);
		break;
	case DPI_ID_HUYA_APP:
		set_huya_stream_character(stream_character_data);
		break;
	case DPI_ID_YOUKU_APP :
		set_youku_stream_character(stream_character_data);
		break;
	case DPI_ID_IQIYI_APP :
		set_iqiyi_stream_character(stream_character_data);
		break;
	case DPI_ID_BILIBILI_APP :
		set_bilibili_stream_character(stream_character_data);
		break;
	case DPI_ID_WECHAT_APP :
		set_wechat_stream_character(stream_character_data);
		break;
	case DPI_ID_DOUYIN_APP :
		set_douyin_stream_character(stream_character_data);
		break;
	case DPI_ID_KUAISHOU_APP :
		set_kuaishou_stream_character(stream_character_data);
		break;
	case DPI_ID_QQ_APP :
		set_qq_stream_character(stream_character_data);
		break;
	case DPI_ID_TMGP_SGAME_APP :
		set_wzry_stream_character(stream_character_data);
		break;
	default:
		break;
	}

	do {
		size_t len = 0, pack_len = 0;
		char *buf = NULL;
		NETLINK_RSP_DATA_DECLARE(rsp_name, requestMsg->header->requestid, requestMsg->header->eventid, COMM_NETLINK_SUCC);

		len = netlink__proto__response_message__get_packed_size(&rsp_name);
		buf = kmalloc(len, GFP_ATOMIC);
		if (!buf) {
			logt("malloc size %lu failed", len);
			kfree(stream_character_data);
			return COMM_NETLINK_ERR_MEMORY;
		}
		pack_len = netlink__proto__response_message__pack(&rsp_name, buf);
		logi("request_set_stream_character pack len %lu  buf len %lu", pack_len, len);
		*rsp_data = buf;
		*rsp_len = len;
	} while (0);
	kfree(stream_character_data);
	stream_character_data = NULL;

	return COMM_NETLINK_SUCC;
}

static void data_free(void *data)
{
	if (data) {
		kfree(data);
	}
}

int dpi_main_init(void) {
	int i = 0;
	int ret = 0;

	spin_lock_init(&s_scene_lock);
	spin_lock_init(&s_dpi_main_lock);

	INIT_HLIST_HEAD(&s_scene_notify_head);

	ret |= register_netlink_request(COMM_NETLINK_EVENT_SET_DPI_UID, request_set_dpi_uid, data_free);
	if(ret) {
		logt("register_netlink_request failed");
		return ret;
	}
	ret |= register_netlink_request(COMM_NETLINK_EVENT_SET_SCENE, request_set_scene, data_free);
	if(ret) {
		unregister_netlink_request(COMM_NETLINK_EVENT_SET_DPI_UID);
		logt("register_netlink_request failed");
		return ret;
	}
	ret |= register_netlink_request(COMM_NETLINK_EVENT_SET_STREAM_CHARACTER, request_set_stream_charater, data_free);

	if (ret) {
		unregister_netlink_request(COMM_NETLINK_EVENT_SET_DPI_UID);
		unregister_netlink_request(COMM_NETLINK_EVENT_SET_SCENE);
		logt("register_netlink_request failed");
		return ret;
	}

	for (i = 0; i < ARRAY_SIZE(s_data_init); i++) {
		ret = s_data_init[i].init();
		if (ret)
			goto dpi_main_init_failed;
	}

	return 0;

dpi_main_init_failed:
	for (i = i - 1; i >= 0; i--) {
		s_data_init[i].exit();
	}
	return ret;
}

void dpi_main_fini(void) {
	int i = ARRAY_SIZE(s_data_init) - 1;

	unregister_netlink_request(COMM_NETLINK_EVENT_SET_DPI_UID);
	unregister_netlink_request(COMM_NETLINK_EVENT_SET_SCENE);
	unregister_netlink_request(COMM_NETLINK_EVENT_SET_STREAM_CHARACTER);

	for(;i >= 0; i--) {
		s_data_init[i].exit();
	}
	return;
}
