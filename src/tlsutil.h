/*
 * sslutil.h
 */

#ifndef SSLUTIL_H_
#define SSLUTIL_H_

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

#endif /* SSLUTIL_H_ */
