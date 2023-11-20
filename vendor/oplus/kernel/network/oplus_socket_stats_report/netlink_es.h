#include <linux/netlink.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include <asm/uaccess.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/notifier.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/sched.h>

#define NETLINK_ESTABLISH_REPORT 31

#define NLMSG_SET_FILTER 0x11
#define NLMSG_GET_FILTER 0x12
#define NLMSG_DISABLE_FILTER 0x13
#define NLMSG_ENABLE_FILTER 0x14
#define NLMSG_TEST_START 0x15
#define NLMSG_TEST_STOP 0x16




#define ES_NL_GRP_NONE		0x00000000
#define ES_NL_GRP_ESTABLISH		0x00000001	/* establish notifications */
#define ES_NL_GRP_ALL		0xffffffff

#define IPV4_TYPE 0x1
#define IPV6_TYPE 0x2

#define ESREPORT_FAMILY_NAME "esreport"
#define ESREPORT_FAMILY_VERSION 1

typedef struct {
  int flag;
  unsigned int  addr;
  unsigned short port;
  unsigned int  mask;

  unsigned char  addr6[16];
  unsigned short port6;
  unsigned char  mask6[16];
}st_es_filter;


enum esreport_msg_type_et{
	ES_NL_MSG_UNSPEC,
	ES_NL_MSG_ENABLE,
    ES_NL_MSG_TCP_ESTABLISH,
    ES_NL_MSG_UDP_ESTABLISH,
    ES_NL_MSG_TCP_CLOSE,
    ES_NL_MSG_UDP_CLOSE,
    ES_NL_MSG_CONFIG_IP_TRIPLE,
    __ES_NL_MSG_MAX,
};

#define ES_NL_MSG_MAX ES_NL_MSG_UDP6_CLOSE

#define TCP_ESTABLISH_EVENT ES_NL_MSG_TCP_ESTABLISH
#define UDP_ESTABLISH_EVENT ES_NL_MSG_UDP_ESTABLISH
#define TCP_CLOSE_EVENT ES_NL_MSG_TCP_CLOSE
#define UDP_CLOSE_EVENT ES_NL_MSG_UDP_CLOSE

#define IPV6_FLAG  0x10


#if IS_ENABLED(CONFIG_IPV6)
//ipv6
#define ES_NL_MSG_TCP6_ESTABLISH 0x12
#define ES_NL_MSG_UDP6_ESTABLISH 0x13
#define ES_NL_MSG_TCP6_CLOSE 0x14
#define ES_NL_MSG_UDP6_CLOSE 0x15

#define TCP6_ESTABLISH_EVENT ES_NL_MSG_TCP6_ESTABLISH
#define UDP6_ESTABLISH_EVENT ES_NL_MSG_UDP6_ESTABLISH
#define TCP6_CLOSE_EVENT ES_NL_MSG_TCP6_CLOSE
#define UDP6_CLOSE_EVENT ES_NL_MSG_UDP6_CLOSE

#endif

#define NLA_DATA(na)		((char *)((char*)(na) + NLA_HDRLEN))

enum esreport_cmd_type_et {
	ESREPORT_CMD_UNSPEC,
	ESREPORT_CMD_DOWN,
	ESREPORT_CMD_UP,
	__ESREPORT_CMD_MAX,
};

typedef struct {
    uint8_t         event;
    union {
        uint32_t    s_addr;
        uint8_t     s_addr6[16];
    };
    union {
        uint32_t    d_addr;
        uint8_t     d_addr6[16];
    };
    uint16_t        s_port;
    uint16_t        d_port;
    uint32_t        uid;
    uint32_t        protocol;
    char            list_name[64];
} es_nl_msg_establish;

typedef struct{
  unsigned int  addr;
  unsigned short port;
  unsigned int uid;
}es_nl_msg_tcp_establish;

typedef struct{
  unsigned int  addr;
  unsigned short port;
  unsigned int uid;
}es_nl_msg_udp_establish;

typedef struct{
    uint32_t port;
    uint32_t start_port;
    uint32_t end_port;
    uint32_t proto;
    uint32_t addr;
    uint8_t addr6[16];
}ip_triple;

