#ifndef __OPLUS_KERNEL_COMMON_H__
#define __OPLUS_KERNEL_COMMON_H__

#define NLA_DATA(na) ((char *)((char*)(na) + NLA_HDRLEN))


#define LOG(tag, fmt, args...) \
	do { \
		printk("[%-10s][%-5u] " fmt "\n", tag, __LINE__, ##args); \
	} while (0)



#define ENABLE_DEBUG 0

#define LOG_TAG "[##KERN_TUNING##]:"
#define logt(fmt, args...) LOG(LOG_TAG, fmt, ##args)
#define debug(fmt, args...) do { if (ENABLE_DEBUG) LOG(LOG_TAG, fmt, ##args); } while (0)


#define	OPLUS_TRUE	1
#define	OPLUS_FALSE	0

enum tuning_msg_type_et {
	OPLUS_TUNING_MSG_UNSPEC,
	OPLUS_TUNING_MSG_TCPSYN_ENABLE,
	OPLUS_TUNING_MSG_FOREGROUND_ANDROID_UID,
	OPLUS_TUNING_MSG_REQUEST_TCPSYN_REPORT,
	OPLUS_TUNING_MSG_TCPSYN_INFO_REPORT,
	OPLUS_TUNING_MSG_TCP_CONTROL_ENABLE,
	OPLUS_TUNING_MSG_SET_TCP_BBR_UID,
	OPLUS_TUNING_MSG_REQUEST_TCP_BBR_INFO,
	OPLUS_TUNING_MSG_TCP_BBR_INFO_REPORT,
	OPLUS_TUNING_MSG_SET_TCP_BBR_STAT_UID,
	__OPLUS_TUNING_MSG_MAX,
};

static inline uid_t get_uid_from_sock(const struct sock *sk)
{
	uid_t sk_uid;
	#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0))
	const struct file *filp = NULL;
	#endif
	if (NULL == sk || !sk_fullsock(sk) || NULL == sk->sk_socket) {
		return 0;
	}
	#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0))
	filp = sk->sk_socket->file;
	if (NULL == filp) {
		return 0;
	}
	sk_uid = __kuid_val(filp->f_cred->fsuid);
	#else
	sk_uid = __kuid_val(sk->sk_uid);
	#endif
	return sk_uid;
}

int oplus_network_tuning_send_netlink_msg(int msg_type, char *payload, int payload_len);

#endif // __OPLUS_KERNEL_COMMON_H__