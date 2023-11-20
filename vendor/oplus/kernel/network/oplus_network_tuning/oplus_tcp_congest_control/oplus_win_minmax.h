#ifndef OPLUS_WIN_MINMAX_H
#define OPLUS_WIN_MINMAX_H

#include <linux/types.h>
#include <linux/win_minmax.h>

u32 oplus_minmax_running_max(struct minmax *m, u32 win, u32 t, u32 meas);
u32 oplus_minmax_running_min(struct minmax *m, u32 win, u32 t, u32 meas);

#endif