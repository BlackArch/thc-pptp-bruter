/*
 * $Id:$
 *
 * Some defines stolen from linux pptp client. These guys did some good
 * reverse engineering work.
 */

#ifndef __PPTP_BRUTER_PPTP_H__
#define __PPTP_BRUTER_PPTP_H__ 1

#include <unistd.h>

typedef struct _pptp
{
	int sox;
	int state;
	size_t rlen;
	char rbuf[4096];
	size_t wlen;
	char wbuf[4096];
} PPTP;

#define PPTP_STATE_ESTABLISHED		(1)

struct _pptp_header
{
	unsigned short length;		/* length in octets, including header */
	unsigned short pptp_type;	/* message type. 1 for ctrl msg       */
	unsigned int magic;		/* this should be PPTP_MAGIC          */
	unsigned short ctrl_type;	/* Control msg type (0-15)            */
	unsigned short reserved0;       /* reserved, but must be zero!        */
};

struct _pptp_start_ctrl_conn
{
	struct _pptp_header header;
	unsigned short version;
	unsigned char result_code;
	unsigned char error_code;
	unsigned int framing_cap;
	unsigned int bearer_cap;
	unsigned short max_channels;
	unsigned short firmware_rev;
	unsigned char hostname[64];
	unsigned char vendor[64];
};

struct _pptp_stop_ctrl_conn
{
	struct _pptp_header header;
	unsigned char reason_result;
	unsigned char error_code;
	unsigned short reserved1;
};

struct _pptp_echo_rqst
{
	struct _pptp_header header;
	unsigned int identifier;
};

struct _pptp_echo_rply
{
	struct _pptp_header header;
	unsigned int identifier;
	unsigned char result_code;
	unsigned char error_code;
	unsigned short reserved1;
};

struct _pptp_out_call_rqst
{
	struct _pptp_header header;
	unsigned short call_id;
	unsigned short call_sernum;
	unsigned int bps_min;
	unsigned int bps_max;
	unsigned int bearer;
	unsigned int framing;
	unsigned short recv_size;
	unsigned short delay;
	unsigned short phone_len;
	unsigned short reserved1;
	unsigned char phone_num[64];
	unsigned char subaddress[64];
};

struct _pptp_out_call_rply
{
	struct _pptp_header header;
	unsigned short call_id;
	unsigned short call_id_peer;
	unsigned char result_code;
	unsigned char error_code;
	unsigned short cause_code;
	unsigned int speed;
	unsigned short recv_size;
	unsigned short delay;
	unsigned int channel;
};

struct _pptp_in_call_rqst
{
	struct _pptp_header header;
	unsigned short call_id;
	unsigned short call_sernum;
	unsigned int bearer;
	unsigned int channel;
	unsigned short dialed_len;
	unsigned short dialing_len;
	unsigned char dialed_num[64];
	unsigned char dialing_num[64];
	unsigned char subaddress[64];
};

struct _pptp_in_call_rply
{
	struct _pptp_header header;
	unsigned short call_id;
	unsigned short call_id_peer;
	unsigned char result_code;
	unsigned char error_code;
	unsigned short recv_size;
	unsigned short delay;
	unsigned short reserverd1;
};

struct _pptp_in_call_connect
{
	struct _pptp_header header;
	unsigned short call_id_peer;
	unsigned short reserved1;
	unsigned int speed;
	unsigned short recv_size;
	unsigned short delay;
	unsigned int framing;
};

struct _pptp_call_clear_rqst
{
	struct _pptp_header header;
	unsigned short call_id;
	unsigned short reserved1;
};

struct _pptp_call_clear_ntfy
{
	struct _pptp_header header;
	unsigned short call_id;
	unsigned char result_code;
	unsigned char error_code;
	unsigned short cause_code;
	unsigned short reserved1;
	unsigned char call_state[128];
};

struct _pptp_wan_err_ntfy
{
	struct _pptp_header header;
	unsigned short call_id_peer;
	unsigned short reserved1;
	unsigned int crc_errors;
	unsigned int frame_errors;
	unsigned int hard_errors;
	unsigned int buff_errors;
	unsigned int time_errors;
	unsigned int align_errors;
};

struct _pptp_set_link_info
{
	struct _pptp_header header;
	unsigned short call_id_peer;
	unsigned short reserved1;
	unsigned int send_accm;
	unsigned int recv_accm;
};



/* (Control Connection Management) */
#define PPTP_START_CTRL_CONN_RQST       1
#define PPTP_START_CTRL_CONN_RPLY       2
#define PPTP_STOP_CTRL_CONN_RQST        3
#define PPTP_STOP_CTRL_CONN_RPLY        4
#define PPTP_ECHO_RQST                  5
#define PPTP_ECHO_RPLY                  6

/* (Call Management) */
#define PPTP_OUT_CALL_RQST              7
#define PPTP_OUT_CALL_RPLY              8
#define PPTP_IN_CALL_RQST               9
#define PPTP_IN_CALL_RPLY               10
#define PPTP_IN_CALL_CONNECT            11
#define PPTP_CALL_CLEAR_RQST            12
#define PPTP_CALL_CLEAR_NTFY            13

/* (Error Reporting) */
#define PPTP_WAN_ERR_NTFY               14

/* (PPP Session Control) */
#define PPTP_SET_LINK_INFO              15

/* Control Connection Message Types: --------------------------- */

#define PPTP_MESSAGE_CONTROL		1
#define PPTP_MESSAGE_MANAGE		2


#define PPTP_MAX_CHANNELS		4096
#define PPTP_FIRMWARE_STRING "0.01"
#define PPTP_FIRMWARE_VERSION		1
#define PPTP_HOSTNAME {'l','o','c','a','l',0}
//#define PPTP_VENDOR			{'c', 'a', 'n', 'a', 'n', 'i', 'a', 'n', 0}
#define PPTP_VENDOR			{'N','T',0}
#define PPTP_FRAME_CAP  2
#define PPTP_BEARER_CAP 1

#define PPTP_VERSION         0x100

#define PPTP_MAGIC		 0x1A2B3C4D /* Magic cookie, PPTP datagrams */
#define PPTP_BPS_MIN		2400
#define PPTP_BPS_MAX		10000000
#define PPTP_WINDOW		3
#define PPTP_CONNECT_SPEED	10000000
#define PPTP_DELAY		0


#define PPTP_HEADER_CTRL(type)  \
{ htons(PPTP_CTRL_SIZE(type)), \
  htons(PPTP_MESSAGE_CONTROL), \
  htonl(PPTP_MAGIC),           \
  htons(type), 0 }             

#define PPTP_CTRL_SIZE(type) ( \
(type==PPTP_START_CTRL_CONN_RQST)?sizeof(struct _pptp_start_ctrl_conn):  \
(type==PPTP_START_CTRL_CONN_RPLY)?sizeof(struct _pptp_start_ctrl_conn):  \
(type==PPTP_STOP_CTRL_CONN_RQST )?sizeof(struct _pptp_stop_ctrl_conn):   \
(type==PPTP_STOP_CTRL_CONN_RPLY )?sizeof(struct _pptp_stop_ctrl_conn):   \
(type==PPTP_ECHO_RQST           )?sizeof(struct _pptp_echo_rqst):        \
(type==PPTP_ECHO_RPLY           )?sizeof(struct _pptp_echo_rply):        \
(type==PPTP_OUT_CALL_RQST       )?sizeof(struct _pptp_out_call_rqst):    \
(type==PPTP_OUT_CALL_RPLY       )?sizeof(struct _pptp_out_call_rply):    \
(type==PPTP_IN_CALL_RQST        )?sizeof(struct _pptp_in_call_rqst):     \
(type==PPTP_IN_CALL_RPLY        )?sizeof(struct _pptp_in_call_rply):     \
(type==PPTP_IN_CALL_CONNECT     )?sizeof(struct _pptp_in_call_connect):  \
(type==PPTP_CALL_CLEAR_RQST     )?sizeof(struct _pptp_call_clear_rqst):  \
(type==PPTP_CALL_CLEAR_NTFY     )?sizeof(struct _pptp_call_clear_ntfy):  \
(type==PPTP_WAN_ERR_NTFY        )?sizeof(struct _pptp_wan_err_ntfy):     \
(type==PPTP_SET_LINK_INFO       )?sizeof(struct _pptp_set_link_info):    \
0)
#define max(a,b) (((a)>(b))?(a):(b))
#define PPTP_CTRL_SIZE_MAX (                    \
max(sizeof(struct _pptp_start_ctrl_conn),        \
max(sizeof(struct _pptp_echo_rqst),              \
max(sizeof(struct _pptp_echo_rply),              \
max(sizeof(struct _pptp_out_call_rqst),          \
max(sizeof(struct _pptp_out_call_rply),          \
max(sizeof(struct _pptp_in_call_rqst),           \
max(sizeof(struct _pptp_in_call_rply),           \
max(sizeof(struct _pptp_in_call_connect),        \
max(sizeof(struct _pptp_call_clear_rqst),        \
max(sizeof(struct _pptp_call_clear_ntfy),        \
max(sizeof(struct _pptp_wan_err_ntfy),           \
max(sizeof(struct _pptp_set_link_info), 0)))))))))))))

#define PPTP_GENERAL_ERROR_NONE			0
#define PPTP_GENERAL_ERROR_NOT_CONNECTED	1

#define PPTP_WANTWRITE(pptp)	(pptp)->wlen

int pptp_open(struct _pptp *pptp, int ip, unsigned short port);
ssize_t pptp_read(struct _pptp *pptp, void *buf, size_t count);
ssize_t pptp_write(struct _pptp *pptp, void *buf, size_t count);
int pptp_flush(struct _pptp *pptp);

#endif
