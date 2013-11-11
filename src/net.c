/*
 * $Id:$
 */

#include "common.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

/*
 * Return socket
 * ip and port are NBO.
 */
int
tcp_open(int ip, unsigned short port)
{
	struct sockaddr_in addr;
	int sox;

	memset(&addr, 0, sizeof addr);
	addr.sin_family = PF_INET;
	addr.sin_addr.s_addr = ip;
	addr.sin_port = port;

	sox = socket(AF_INET, SOCK_STREAM, 0);
	if (connect(sox, (struct sockaddr *)&addr, sizeof addr) == 0)
		return sox;

	close(sox);
	return -1;
}

