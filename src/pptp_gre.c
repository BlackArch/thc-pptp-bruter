/*
 * $Id:$
 */


#include "common.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include "pptp_bruter.h"
#include "pptp_gre.h"

extern struct _opt opt;

int
GRE_init(GRE *gre)
{
	memset(gre, 0, sizeof *gre);
	//gre->seq_sent = 0;
	gre->seq_recv = -1;

	return 0;
}

/*
 * Read GRE data from socket.
 * This function also reorders GRE packets on its own.
 *
 * FIXME: first check buffer if there are GRE packets in the queue.
 * FIXME: should we handle out of order GRE packets or just assume
 * them as discarded?
 *
 * Yes, for receiving packets we must check ack number and free
 * gre slot with tha tbuffered packet.
 *
 * We dont really need send buffer. we just retransmit anyway
 * if we dont get a proper answer to a packet.
 */
int
gre_read(int fd, unsigned char *buf, unsigned int len, unsigned short *call_id)
{
	struct _pptp_gre_header *header;
	int ip_len = 0;
	int ret;
	int hdrsize;

	ret = read(fd, buf, len);
	//DEBUGF("read(,,%d) returned %d\n", len, ret);
	if (ret <= 0)
		return -1;

	/* Strip of IP header if present */
	if ((buf[0] & 0xf0) == 0x40)
	{
		ip_len = (buf[0] & 0x0f) * 4;
		if (ip_len >= ret)
			return 0;
		ret -= ip_len;
		memmove(buf, buf + ip_len, ret);
	}

	/* UNFINSIHED READ. Kernel should not return before full packet recv. */
	/* Packet can be without SEQ or without ACK number */
	if (ret < sizeof *header - 4)
	{
		DEBUGF("FATAL: short GRE packet read (%d). CANT HAPPEN.\n", ret);
		return 0;
	}

	hdrsize = sizeof *header;
	header = (struct _pptp_gre_header *)(buf);
	if (!PPTP_GRE_IS_A(header->ver))
		hdrsize -= sizeof header->ack;
	if (!PPTP_GRE_IS_S(header->flags))
		hdrsize -= sizeof header->ack;

	if (ret - hdrsize < ntohs(header->payload_len))
	{
		DEBUGF("Discarding truncated packet. (is %d, should %d)\n", ret - hdrsize, ntohs(header->payload_len));
		return 0;
	}

	*call_id = ntohs(header->call_id);

	return ret;
}

int
gre_process(GRE *gre, unsigned char *buf, unsigned int len)
{
	struct _pptp_gre_header *header = (struct _pptp_gre_header *)(buf);
	unsigned int seq = 0;

	/* Either ACK or SEQ must be set */
	if ((!PPTP_GRE_IS_A(header->ver)) && (!PPTP_GRE_IS_S(header->flags)))
		return -8;

	/* RFC says seq must start with 1. Windows anyway starts with 0 */
	/* Accept packet with _smaller_ or equal + 1 seq number of what
	 * we already received. Smaller because the peer might sent in
	 * parallel a lot of packets out and all ACK's might have get
	 * lost. Retransmit answer then. Peer ignores packet if already
	 * received (hopefully!).
	 */
#if 0
	if (PPTP_GRE_IS_A(header->ver))
	{
		if (PPTP_GRE_IS_S(header->flags))
			ack = ntohl(header->ack);
		else
			ack = ntohl(header->seq);
	}
#endif
	if ((gre) && (PPTP_GRE_IS_S(header->flags)))
	{
		seq = ntohl(header->seq);

		if (((gre->seq_recv == -1) && (seq > 1)) || ((gre->seq_recv > 0) && ((seq > gre->seq_recv + 1))))
		{
			DEBUGF("Discarding out of order packet (seq = %d, expect %d)\n", seq, gre->seq_recv + 1);
			return -7;
		}
		gre->seq_recv = seq;
	}

	/* Sanity checking if this is our packet */
	if ((header->ver & 0x7f) != PPTP_GRE_VER)
		return -1;
	if (ntohs(header->protocol) != PPTP_GRE_PROTO)
		return -2;
	if (PPTP_GRE_IS_C(header->flags))
		return -3;
	if (PPTP_GRE_IS_R(header->flags))
		return -4;
	if (!(PPTP_GRE_IS_K(header->flags)))
		return -5;
	if ((header->flags & 0x0f) != 0)
		return -6;

	/* Ack without payload */
	if ((!PPTP_GRE_IS_S(header->flags)) && (PPTP_GRE_IS_A(header->ver)))
		return 0;	/* ack without payload */

	return len;
}

/*
 */
int
gre_write(int fd, GRE *gre, void *data, unsigned int len)
{
	int header_len;
	int ret;

	if (data == NULL)
		len = 0;

	gre->u.header.flags = PPTP_GRE_FLAG_K;
	gre->u.header.ver = PPTP_GRE_VER;
	gre->u.header.protocol = htons(PPTP_GRE_PROTO);
	gre->u.header.payload_len = htons(len);
	gre->u.header.call_id = htons(gre->peer_call_id);

	if (data)
	{
		gre->u.header.flags |= PPTP_GRE_FLAG_S;
		gre->u.header.seq = htonl(++gre->seq_sent);
	}
		

	header_len = sizeof gre->u.header;
	/* Look at this windows crap shit. Sequence number
	 * field is used for ack number if no data is send and this
	 * is an empty ack package.
	 */
	if (data == NULL)
	{
		gre->u.header.ver |= PPTP_GRE_FLAG_A;
		gre->u.header.seq = htonl(gre->seq_recv);
		header_len -= sizeof gre->u.header.ack;
	} else {
		if ((gre->seq_recv >= 0) && (gre->ack_sent != gre->seq_recv))
		{
			gre->u.header.ver |= PPTP_GRE_FLAG_A;
			gre->u.header.ack = htonl(gre->seq_recv);
			gre->ack_sent = gre->seq_recv;
		} else {
			header_len -= sizeof gre->u.header.ack;
		}
	}

	if (header_len + len > sizeof gre->u.wbuf)
		return 0;

	/* We sometimes send the same buffer just with differen SEQ again */
	if (data != gre->u.wbuf + header_len)
		memcpy(gre->u.wbuf + header_len, data, len);

	DEBUGF("passed len: %d, header_len: %d, SEQ %d\n", len, header_len, gre->seq_sent);

	gre->wlen = header_len + len;
	ret = write(fd, gre->u.wbuf, gre->wlen);
	if (ret < 0)
		return -1;
#if 0
	gettimeofday(&gre->last_sent, NULL);
#endif
	if (ret != header_len + len)
	{
		/* when can this happen on a blocking fd?\ */
		DEBUGF("FATAL: write could write everything to GRE\n");
		return -1;
		return 0;
	}

	return ret;
}


/*
 * Open a GRE socket to peer. IP is NBO.
 */
int
pptp_gre_bind(unsigned int ip)
{
	struct sockaddr_in addr;
	int s;
	
	s = socket(AF_INET, SOCK_RAW, PPTP_PROTO);
	if (s < 0)
		return -1;

	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = ip;
	addr.sin_port = 0;

	if (connect(s, (struct sockaddr *)&addr, sizeof addr) < 0)
	{
		close(s);
		return -1;
	}

	return s;
}


