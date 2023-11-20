/***********************************************************
** Copyright (C), 2008-2022, oplus Mobile Comm Corp., Ltd.
** File: zoom.h
** Description: add zoom stream identify
**
** Version: 1.0
** Date : 2023/06/27
** Author: Zhangpeng
**
** ------------------ Revision History:------------------------
** <author> <data> <version > <desc>
** Zhangpeng 2023/06/27 1.0 build this module
****************************************************************/

#ifndef OPLUS_KERNEL_NET_ZOOM_H
#define OPLUS_KERNEL_NET_ZOOM_H

int set_zoom_uid(u32 uid);
int set_zoom_stream_character(dpi_stream_character_data *data);

int zoom_init(void);
void zoom_fini(void);

#endif  /* OPLUS_KERNEL_NET_ZOOM_H */
