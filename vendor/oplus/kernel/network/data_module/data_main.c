#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/types.h>
#include <linux/version.h>

extern int comm_netlink_module_init(void);
extern void comm_netlink_module_exit(void);

extern int oplus_dpi_module_init(void);
extern void oplus_dpi_module_fini(void);

extern int cls_dpi_mod_init(void);
extern void cls_dpi_mod_exit(void);

extern int dpi_main_init(void);
extern void dpi_main_finit(void);

typedef struct data_init_st
{
	int (*init)(void);
	void (*exit)(void);
}module_init_st;

static module_init_st data_init[] = {
	{.init = comm_netlink_module_init, .exit = comm_netlink_module_exit},
	{.init = oplus_dpi_module_init, .exit = oplus_dpi_module_fini},
	{.init = cls_dpi_mod_init, .exit = cls_dpi_mod_exit},
	{.init = dpi_main_init, .exit = oplus_dpi_module_fini},
};

static int __init data_modules_init(void)
{
	int ret = 0;
	int i = 0;

	for (i = 0; i < ARRAY_SIZE(data_init); i++) {
		ret = data_init[i].init();
		if (ret)
			goto init_failed;
	}

	printk("data_modules_init succ \n");
	return 0;

init_failed:
	for (i = i - 1; i >= 0; i--) {
		data_init[i].exit();
	}
	printk("data_modules_init failed!\n");
	return -1;
}

static void __exit data_modules_exit(void)
{
	int i = ARRAY_SIZE(data_init) - 1;
	for(;i >= 0; i--) {
		data_init[i].exit();
	}
	printk("data_modules_exit\n");
	return;
}

module_init(data_modules_init);
module_exit(data_modules_exit);
MODULE_LICENSE("GPL");
