/***********************************************************
** Copyright (C), 2008-2022, oplus Mobile Comm Corp., Ltd.
** File: bilibili.h
** Description: add bilibili stream identify
**
** Version: 1.0
** Date : 2023/06/27
** Author: Zhangpeng
**
** ------------------ Revision History:------------------------
** <author> <data> <version > <desc>
** Zhangpeng 2023/06/27 1.0 build this module
****************************************************************/

#ifndef OPLUS_KERNEL_NET_BILIBILI_H
#define OPLUS_KERNEL_NET_BILIBILI_H

#include "dpi_main.h"

int set_bilibili_uid(u32 uid);
int set_bilibili_stream_character(dpi_stream_character_data *data);

int bilibili_init(void);
void bilibili_fini(void);

#endif  /* OPLUS_KERNEL_NET_BILIBILI_H */
