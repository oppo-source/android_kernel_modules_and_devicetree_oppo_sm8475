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

#ifndef OPLUS_KERNEL_NET_DOUYU_H
#define OPLUS_KERNEL_NET_DOUYU_H

#include "dpi_main.h"


int set_douyu_uid(u32 uid);
int set_douyu_stream_character(dpi_stream_character_data *data);

int douyu_init(void);
void douyu_fini(void);

#endif  /* OPLUS_KERNEL_NET_DOUYU_H */
