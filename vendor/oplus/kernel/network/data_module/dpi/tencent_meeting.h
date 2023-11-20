/***********************************************************
** Copyright (C), 2008-2022, oplus Mobile Comm Corp., Ltd.
** File: tencent_meeting.h
** Description: add tencent meeting stream identify
**
** Version: 1.0
** Date : 2023/06/27
** Author: Zhangpeng
**
** ------------------ Revision History:------------------------
** <author> <data> <version > <desc>
** Zhangpeng 2023/06/27 1.0 build this module
****************************************************************/

#ifndef OPLUS_KERNEL_NET_TENCENT_MEETING_APP_H
#define OPLUS_KERNEL_NET_TENCENT_MEETING_APP_H

int set_tencent_meeting_uid(u32 uid);
int set_tencent_meeting_stream_character(dpi_stream_character_data *data);

int tencent_meeting_init(void);
void tencent_meeting_fini(void);

#endif  /* OPLUS_KERNEL_NET_TENCENT_MEETING_APP_H */
