/***********************************************************
** Copyright (C), 2008-2022, oplus Mobile Comm Corp., Ltd.
** File: iqiyi.h
** Description: add iqiyi stream identify
**
** Version: 1.0
** Date : 2023/06/27
** Author: Zhangpeng
**
** ------------------ Revision History:------------------------
** <author> <data> <version > <desc>
** Zhangpeng 2023/06/27 1.0 build this module
****************************************************************/

#ifndef OPLUS_KERNEL_NET_IQIYI_H
#define OPLUS_KERNEL_NET_IQIYI_H

#include "dpi_main.h"

int set_iqiyi_uid(u32 uid);
int set_iqiyi_stream_character(dpi_stream_character_data *data);

int iqiyi_init(void);
void iqiyi_fini(void);

#endif  /* OPLUS_KERNEL_NET_IQIYI_H */
