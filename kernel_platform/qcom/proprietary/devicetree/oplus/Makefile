ifeq ($(CONFIG_BUILD_ARM64_DT_OVERLAY),y)
dtbo-$(CONFIG_ARCH_CAPE) +=  \
	whiteswan-22001-cape-overlay.dtbo \
	lvzhou-22015-cape-overlay.dtbo \
	monroe-22091-cape-overlay.dtbo \
	monroe-22091-cape-overlay-t0.dtbo \
	daoxiang-23023-cape-overlay.dtbo \
        daoxiang-23023-cape-overlay-V2.dtbo

whiteswan-22001-cape-overlay.dtbo-base := cape.dtb cape-v2.dtb
lvzhou-22015-cape-overlay.dtbo-base := cape.dtb cape-v2.dtb
monroe-22091-cape-overlay.dtbo-base := cape.dtb cape-v2.dtb
monroe-22091-cape-overlay-t0.dtbo-base := cape.dtb cape-v2.dtb
daoxiang-23023-cape-overlay.dtbo-base := cape.dtb cape-v2.dtb
daoxiang-23023-cape-overlay-V2.dtbo-base := cape.dtb cape-v2.dtb
endif

always-y	:= $(dtb-y)
subdir-y	:= $(dts-dirs)
clean-files	:= *.dtb *.dtbo
