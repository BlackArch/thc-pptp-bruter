/*
 * $Id:$
 */

#include "common.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/in.h>
#include "pptp_bruter.h"
#include "pptp.h"
#include "net.h"

extern struct _opt opt;

int
pptp_open(struct _pptp *pptp, int ip, unsigned short port)
{
	struct _pptp_start_ctrl_conn packet = {
	PPTP_HEADER_CTRL(PPTP_START_CTRL_CONN_RQST),
	htons(PPTP_VERSION), 0, 0,
	htonl(PPTP_FRAME_CAP), htonl(PPTP_BEARER_CAP),
	htons(PPTP_MAX_CHANNELS), htons(PPTP_FIRMWARE_VERSION),
	PPTP_HOSTNAME, PPTP_VENDOR};

	memset(pptp, 0, sizeof *pptp);
	pptp->sox = tcp_open(ip, port);
	if (pptp->sox < 0)
		return -1;

	if (pptp_write(pptp, &packet, sizeof packet) < 0)
		return -1;

	return 0;
}

/*
 * Flush data in PPTP write buffer.
 */
int
pptp_flush(struct _pptp *pptp)
{
	ssize_t ret;

	ret = pptp_write(pptp, pptp->wbuf, pptp->wlen);

	return ret;
}

/*
 * Return number of bytes written to pptp.
 */
ssize_t
pptp_write(struct _pptp *pptp, void *buf, size_t count)
{
	ssize_t ret;

	ret = write(pptp->sox, buf, count);
	DEBUGF("write returned %d of %d to write\n", ret, count);
	if (ret < 0)
	{
		if (errno == EAGAIN || errno == EINTR)
		{
			ret = 0;
		} else {
			return -1;
		}
	}

	pptp->wlen = count - ret;

	if (pptp->wlen > 0)
	{
		if (pptp->wlen > sizeof pptp->wbuf)
			return -1;
		/* wbuf and buf might be the same buffer */
		memmove(pptp->wbuf, buf + ret, pptp->wlen);
	}

	return ret;
}

/*
 * Read next pptp packet. Return -1 on error, 0 if complete packet
 * has not been read yet.
 */
ssize_t
pptp_read(struct _pptp *pptp, void *buf, size_t count)
{
	ssize_t ret;
	struct _pptp_header *header;
	unsigned short len;

	/* Read buffer to small */
	if (pptp->rlen >= sizeof pptp->rbuf)
		return -1;

	ret = read(pptp->sox, pptp->rbuf + pptp->rlen, sizeof pptp->rbuf - pptp->rlen);
	DEBUGF("read() returned %d\n", ret);

	if (ret <= 0)
		return -1;

	pptp->rlen += ret;

	if (pptp->rlen < sizeof(struct _pptp_header))
		return 0;
	header = (struct _pptp_header *)(pptp->rbuf);
	if (ntohl(header->magic) != PPTP_MAGIC)
		return -1;
	len = ntohs(header->length);

	if (len > PPTP_CTRL_SIZE_MAX)
		return -1;
	/* Need more bytes */
	if (len > pptp->rlen)
		return 0;
	/* Buffer to small */
	if (len > count)
		return -1;
	memcpy(buf, pptp->rbuf, len);
	if (pptp->rlen > len)
		memmove(pptp->rbuf, pptp->rbuf + len, pptp->rlen - len);
	pptp->rlen -= len;

	return len;
}

