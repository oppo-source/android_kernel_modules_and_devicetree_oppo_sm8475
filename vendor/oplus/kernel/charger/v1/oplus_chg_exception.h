/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2018-2020 Oplus. All rights reserved.
 */

#ifndef __OPLUS_CHG_EXCEPTION_H__
#define __OPLUS_CHG_EXCEPTION_H__

#define EXCEP_SOC_ERROR_DEFAULT		(0x000)
#define EXCEP_GENERAL_RECORD_DEFAULT	(0x100)
#define EXCEP_NO_CHARGING_DEFAULT	(0x200)
#define EXCEP_CHARGING_SLOW_DEFAULT	(0x300)
#define EXCEP_CHARGING_BREAK_DEFAULT	(0x400)
#define EXCEP_DEVICE_ABNORMAL_DEFAULT	(0x500)
#define EXCEP_SOFTWARE_ABNORMAL_DEFAULT (0x600)
#define EXCEP_TYPE_MAX_DEFAULT		(0xFFF)

#define OLC_CONFIG_NUM_MAX 7

enum olc_notify_type {
	OLC_NOTIFY_TYPE_SOC_JUMP,
	OLC_NOTIFY_TYPE_GENERAL_RECORD,
	OLC_NOTIFY_TYPE_NO_CHARGING,
	OLC_NOTIFY_TYPE_CHARGING_SLOW,
	OLC_NOTIFY_TYPE_CHARGING_BREAK,
	OLC_NOTIFY_TYPE_DEVICE_ABNORMAL,
	OLC_NOTIFY_TYPE_SOFTWARE_ABNORMAL,
};

struct exception_data {
	u64 olc_config[OLC_CONFIG_NUM_MAX];
};

struct chg_exception_table {
	int type_reason;
	int olc_type;
};

int chg_exception_report(void *chg_exception_data, int type_reason, int flag_reason,
				void *summary, unsigned int summary_size);
#endif /*__OPLUS_CHG_EXCEPTION_H__*/
