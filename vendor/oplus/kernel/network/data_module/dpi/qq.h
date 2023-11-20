/***********************************************************
** Copyright (C), 2008-2022, oplus Mobile Comm Corp., Ltd.
** File: qq.h
** Description: add qq stream identify
**
** Version: 1.0
** Date : 2023/07/30
** Author: tanzhoumei
**
** ------------------ Revision History:------------------------
** <author> <data> <version > <desc>
** tanzhoumei 2023/07/30 1.0 build this module
****************************************************************/

#ifndef __QQ_H__
#define __QQ_H__

#include "dpi_main.h"

int set_qq_uid(u32 uid);
int set_qq_stream_character(dpi_stream_character_data *data);

int qq_init(void);
void qq_fini(void);

#endif  /* __QQ_H__ */
