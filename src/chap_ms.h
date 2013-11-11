/*
 * $Id:$
 */

#ifndef __PPTP_BRUTER_CHAP_MS_H__
#define __PPTP_BRUTER_CHAP_MS_H__ 1

#define MAX_NT_PASSWORD			(256)

int ChapMS(unsigned char *resp, unsigned char *chl, unsigned char *secret, int secret_len);
int ChapMS_v2(unsigned char *resp, unsigned char *chl, unsigned char *secret, int secret_len, char *username);

#endif /* !__PPTP_BRUTER_CHAP_MS_H__ */

