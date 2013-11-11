/*
 * $Id:$
 */

#ifndef __PPTP_BRUTER_H__
#define __PPTP_BRUTER_H__ 1

#include <sys/time.h>
#include "pptp_gre.h"

#define PPTP_BRUTER_MAX_SLOTS	(1024)
#define PPTP_BRUTER_DFL_LIMIT	(100)

struct _opt
{
	int n_slots;
	FILE *wordlistfp;
	unsigned char *user;
	unsigned char *host;
	unsigned short int port;
	unsigned int limit;
	unsigned int tries;
	struct timeval start;
	struct timeval status_due;
	struct timeval pwd_due;		/* when next pwd should be taken */
	struct timeval pwd_delta;	/* take pwd ever pwd_delta sec.  */
	struct timeval tv_now;
	unsigned char flags;
};

#define OPT_FLAGS_WINDOWSHACK		(0x01)
#define OPT_FLAGS_VERBOSE		(0x02)


struct _slot
{
	GRE gre;
	int state;
	struct timeval due;
	struct timeval due_global;
	struct timeval start;
	char password[32];
	unsigned char retrans_timeout;
	unsigned char challenge[16];
	unsigned short lcp_id;
};

#define SLOT_STATE_NONE			(0)
#define SLOT_STATE_WAIT_TERM_ACK	(1)
/* All down here means restart them */
#define SLOT_STATE_RESTARTABLE		(2)
#define SLOT_STATE_WAIT_CID		(2) /* Waiting for caller id on 1723 */
#define SLOT_STATE_PPTP_CFGREQ_SENT	(3) /* Sent gre packet with cfg-req */
#define SLOT_STATE_RESPONSE_SENT	(4)
#define SLOT_STATE_FAILURE_RECV		(5)
#define SLOT_STATE_CHL_RECV		(6)
#define SLOT_STATE_CONF_RECV		(7)
//#define SLOT_STATE_FINISHED		(3) /* no passwords anymore ?! */

void hexdump(unsigned char *ptr, int len);

#endif /* !__PPTP_BRUTER_H__ */
