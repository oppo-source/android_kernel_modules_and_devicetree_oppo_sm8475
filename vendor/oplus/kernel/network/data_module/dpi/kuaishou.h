/***********************************************************
** Copyright (C), 2008-2022, oplus Mobile Comm Corp., Ltd.
** File: kuaishou.h
** Description: add kuaishou stream identify
**
** Version: 1.0
** Date : 2023/07/30
** Author: tanzhoumei
**
** ------------------ Revision History:------------------------
** <author> <data> <version > <desc>
** tanzhoumei 2023/07/30 1.0 build this module
****************************************************************/

#ifndef __KUAISHOU_H__
#define __KUAISHOU_H__

int set_kuaishou_uid(u32 uid);
int set_kuaishou_stream_character(dpi_stream_character_data *data);

int kuaishou_init(void);
void kuaishou_fini(void);

#endif  /* __KUAISHOU_H__ */
