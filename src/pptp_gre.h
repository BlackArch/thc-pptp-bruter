/*
 * $Id:$
 */

#ifndef __PPTP_BRUTER_PPTP_GRE_H__
#define __PPTP_BRUTER_PPTP_GRE_H__ 1

#include <sys/time.h>

#define PPTP_PROTO	47	/* PPTP IP protocol number */

#define HDLC_FLAG         0x7E
#define HDLC_ESCAPE       0x7D
#define HDLC_TRANSPARENCY 0x20

#define PPTP_GRE_PROTO  0x880B
#define PPTP_GRE_VER    0x1

#define PROTO_PPP_LCP		0xc021	/* protocol number */
#define PROTO_PPP_CHL		0xc223  /* Challenge/Response payload */

#define PPTP_GRE_FLAG_C 0x80
#define PPTP_GRE_FLAG_R 0x40
#define PPTP_GRE_FLAG_K 0x20
#define PPTP_GRE_FLAG_S 0x10
#define PPTP_GRE_FLAG_A 0x80
#define PPTP_GRE_FLAG_SET_A(header)	(header)->ver | 0x80

#define PPTP_GRE_IS_C(f) ((f)&PPTP_GRE_FLAG_C)
#define PPTP_GRE_IS_R(f) ((f)&PPTP_GRE_FLAG_R)
#define PPTP_GRE_IS_K(f) ((f)&PPTP_GRE_FLAG_K)
#define PPTP_GRE_IS_S(f) ((f)&PPTP_GRE_FLAG_S)
#define PPTP_GRE_IS_A(f) ((f)&PPTP_GRE_FLAG_A)

/*
 * It appears that there are teo different types of ppp headers.
 * A long one, containing address and ctrl, and a short one,just
 * containing the protocol.
 */
struct _ppp_header_addr
{
	unsigned char address;
	unsigned char ctrl;
	unsigned short protocol;
	unsigned char payload[0];
};

struct _ppp_header
{
	unsigned short protocol;
	unsigned char payload[0];
};

struct _ppp_lcp_header
{
	unsigned char code;
	unsigned char id;
	unsigned short length; /* payload + ppp_lcp_header */
	unsigned char payload[0];
};

struct _pptp_gre_header
{
	unsigned char flags;
	unsigned char ver;
	unsigned short protocol;
	unsigned short payload_len;
	unsigned short call_id;
	unsigned int seq;	/* can be ACK as well if no SEQ present */
	unsigned int ack;
};

typedef struct _gre
{
	/* Timeout retransmission buffer as well. We dont want
	 * to retransmit empty ACK's. This works for us because we only
	 * send out empty GRE ACK packets right before we reuse the slot.
	 */
	union
	{
		struct _pptp_gre_header header;
		unsigned char wbuf[8196 + sizeof(struct _pptp_gre_header)];
	} u;
	int wlen;
	unsigned short call_id;
	unsigned short peer_call_id;
	int ack_sent;
	int seq_recv;
	int seq_sent;
	struct timeval last_sent;
} GRE;

int pptp_gre_bind(unsigned int ip);
int gre_write(int fd, GRE *gre, void *data, unsigned int len);
int gre_read(int fd, unsigned char *buf, unsigned int len, unsigned short *call_id);
int gre_process(GRE *gre, unsigned char *buf, unsigned int len);
int GRE_init(GRE *gre);

#endif /* !__PPTP_BRUTER_PPTP_GRE_H__ */
