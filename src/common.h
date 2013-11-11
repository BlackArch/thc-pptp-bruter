/* 
 * $Id:$
 */

#ifndef __PPTP_BRUTER_COMMON_H__
#define __PPTP_BRUTER_COMMON_H__ 1

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#define LOG(a...)	do { \
	fprintf(stderr, a); \
} while (0)

#define LOGVRET(a...)	do { \
	LOG(a); \
	return; \
} while (0)

#define LOGRET(v, a...)	do { \
	LOG(a); \
	return v; \
} while (0)

#define ERREXIT(a...)	do { \
	fprintf(stderr, "ERROR: "); \
	fprintf(stderr, a); \
	exit(-1); \
} while (0)

#define PERREXIT(a...)	do { \
	fprintf(stderr, a); \
	fprintf(stderr, ": %s\n", strerror(errno)); \
	exit(-1); \
} while (0)

#define DEBUGF(a...)    do { \
	if (opt.flags & OPT_FLAGS_VERBOSE) \
	{ \
		fprintf(stderr, "DEBUG %s:%d: ", __func__, __LINE__); \
		fprintf(stderr, a); \
	} \
} while (0)

#define MIN(a,b)	((a)<(b)?(a):(b))
#define MAX(a,b)	((a)<(b)?(b):(a))
#endif /* !__PPTP_BRUTER_COMMON_H__ */
