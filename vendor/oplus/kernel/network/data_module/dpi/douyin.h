/***********************************************************
** Copyright (C), 2008-2022, oplus Mobile Comm Corp., Ltd.
** File: douyin.h
** Description: add douyin stream identify
**
** Version: 1.0
** Date : 2023/07/30
** Author: tanzhoumei
**
** ------------------ Revision History:------------------------
** <author> <data> <version > <desc>
** tanzhoumei 2023/07/30 1.0 build this module
****************************************************************/
#ifndef __DOUYIN_H__
#define __DOUYIN_H__
#include "dpi_main.h"

int set_douyin_uid(u32 uid);
int set_douyin_stream_character(dpi_stream_character_data *data);

int douyin_init(void);
void douyin_fini(void);

#endif  /* __DOUYIN_H__ */
