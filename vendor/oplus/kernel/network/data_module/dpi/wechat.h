/***********************************************************
** Copyright (C), 2008-2022, oplus Mobile Comm Corp., Ltd.
** File: wechat.h
** Description: add wechat
**
** Version: 1.0
** Date : 2023/7/12
** Author: TanZhoumei
**
** ------------------ Revision History:------------------------
** <author> <data> <version > <desc>
** TanZhoumei 2023/7/121.0 build this module
****************************************************************/


#ifndef __WECHAT_H__
#define __WECHAT_H__


int set_wechat_uid(u32 uid);
int set_wechat_stream_character(dpi_stream_character_data *data);

int wechat_init(void);
void wechat_fini(void);


#endif  /* __WECHAT_H__ */
