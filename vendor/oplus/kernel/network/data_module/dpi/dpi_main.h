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

#ifndef OPLUS_KERNEL_NET_DPI_MAIN_H
#define OPLUS_KERNEL_NET_DPI_MAIN_H

#define DNS_SERVER_PORT 53
#define MAX_FIELD_LENGTH 10
#define MAX_TOKEN_LENGTH 10
#define MAX_HTTP_TYPE 2
#define MAX_STRING_LENGTH 10
#define MAX_REQUEST_LINE_LENGTH 1024
#define DPI_STREAM_CHARACTER_LENGTH 128

typedef struct {
	u64 stream_id;
	char transportprotocol[DPI_STREAM_CHARACTER_LENGTH];
	char dstport[DPI_STREAM_CHARACTER_LENGTH];
	char url[DPI_STREAM_CHARACTER_LENGTH];
	char httptype[DPI_STREAM_CHARACTER_LENGTH];
	char httpfield[DPI_STREAM_CHARACTER_LENGTH];
	char downpkgth[DPI_STREAM_CHARACTER_LENGTH];
	char uppkgth[DPI_STREAM_CHARACTER_LENGTH];
	char pkgth[DPI_STREAM_CHARACTER_LENGTH];
	char uppkgmagic[DPI_STREAM_CHARACTER_LENGTH];
} dpi_stream_character_data;

typedef struct {
	char field[MAX_FIELD_LENGTH][MAX_TOKEN_LENGTH];
	u32 field_length;
} separate_str_data;

typedef int (*dpi_scene_notify_fun)(u32 scene, u32 is_enter);

int dpi_register_deepthinker_scene(u32 uid, dpi_scene_notify_fun fun);
int dpi_unregister_deepthinker_scene(u32 uid);

separate_str_data *split_str_by_symbol(char *input, const char *separator);
void free_str_array(separate_str_data *field);
int http_request_match(struct sk_buff *skb, struct tcphdr *tcp_header, char *http_request_type, separate_str_data *field);
struct tcphdr *get_tcp_header(struct sk_buff *skb);
struct udphdr *get_udp_header(struct sk_buff *skb);

int dpi_main_init(void);
void dpi_main_fini(void);

#endif  /* OPLUS_KERNEL_NET_DPI_MAIN_H */
