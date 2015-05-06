/*
 * netcat.h -- main header project file
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <giovanni@giacobbi.net>
 * Copyright (C) 2002 - 2004  Giovanni Giacobbi
 *
 * $Id: netcat.h,v 1.35 2004/01/03 16:42:07 themnemonic Exp $
 */

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 ***************************************************************************/

#ifndef NETCAT_H
#define NETCAT_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>		/* basic types definition */
#include <sys/time.h>		/* timeval, time_t */
#include <sys/socket.h>
#include <sys/uio.h>		/* needed for reading/writing vectors */
#include <sys/param.h>		/* defines MAXHOSTNAMELEN and other stuff */
#include <netinet/in.h>
#include <arpa/inet.h>		/* inet_ntop(), inet_pton() */

/* other misc unchecked includes */
#if 0
#include <netinet/in_systm.h>	/* misc crud that netinet/ip.h references */
#include <netinet/ip.h>		/* IPOPT_LSRR, header stuff */
#endif

/* These are useful to keep the source readable */
#ifndef STDIN_FILENO
# define STDIN_FILENO 0
#endif
#ifndef STDOUT_FILENO
# define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
# define STDERR_FILENO 2
#endif
#ifndef SHUT_RDWR
# define SHUT_RDWR 2
#endif

/* find a random routine */
#if defined(HAVE_RANDOM) && defined(HAVE_SRANDOM)
# define USE_RANDOM		/* try with most modern random routines */
# define SRAND srandom
# define RAND random
#elif defined(HAVE_RAND) && defined(HAVE_SRAND)
# define USE_RANDOM		/* otherwise fallback to the older rand() */
# define SRAND srand
# define RAND rand
#endif				/* if none of them are here, CHANGE OS! */

/* This must be defined to the longest possible internet address length in
   string notation.
   Bugfix: Looks like Solaris 7 doesn't define this standard. It's ok to use
   the following workaround since this is going to change to introduce IPv6
   support. */
#ifdef INET_ADDRSTRLEN
# define NETCAT_ADDRSTRLEN INET_ADDRSTRLEN
#else
# define NETCAT_ADDRSTRLEN 16
#endif

/* FIXME: I should search more about this portnames standards.  At the moment
   i'll fix my own size for this */
#define NETCAT_MAXPORTNAMELEN 64

/* Find out whether we can use the RFC 2292 extensions on this machine
   (I've found out only linux supporting this feature so far) */
#ifdef HAVE_STRUCT_IN_PKTINFO
# if defined(SOL_IP) && defined(IP_PKTINFO)
#  define USE_PKTINFO
# endif
#endif

/* MAXINETADDR defines the maximum number of host aliases that are saved after
   a successfully hostname lookup. Please not that this value will also take
   a significant role in the memory usage. Approximately one struct takes:
   MAXINETADDRS * (NETCAT_ADDRSTRLEN + sizeof(struct in_addr)) */
#define MAXINETADDRS 6

#ifndef INADDR_NONE
# define INADDR_NONE 0xffffffff
#endif

/* FIXME: shall we really change this define? probably not. */
#ifdef MAXHOSTNAMELEN
# undef MAXHOSTNAMELEN		/* might be too small on aix, so fix it */
#endif
#define MAXHOSTNAMELEN 256

/* TRUE and FALSE values for logical type `bool' */
#ifndef TRUE
# define TRUE 1
#endif
#ifndef FALSE
# define FALSE 0
#endif

/* this is just a logical type, but helps a lot */
#ifndef __cplusplus
# ifndef bool
#  define bool unsigned char
# endif
#endif
#define BOOL_TO_STR(__var__) (__var__ ? "TRUE" : "FALSE")
#define NULL_STR(__var__) (__var__ ? __var__ : "(null)")

/* there are some OS that still doesn't support POSIX standards */
#ifndef HAVE_IN_PORT_T
typedef unsigned short in_port_t;
#endif

/* Netcat basic operating modes */

typedef enum {
  NETCAT_UNSPEC,
  NETCAT_CONNECT,
  NETCAT_LISTEN,
  NETCAT_TUNNEL
} nc_mode_t;

/* Recognized protocols */

typedef enum {
  NETCAT_PROTO_UNSPEC,
  NETCAT_PROTO_TCP,
  NETCAT_PROTO_UDP
} nc_proto_t;

/* used for queues buffering and data tracking purposes.  The `head' field is
   a pointer to the begin of the buffer segment, while `pos' indicates the
   actual position of the data stream.  If `head' is NULL, it means that there
   is no dynamically-allocated data in this buffer, *BUT* it MAY still contain
   some local data segment (for example allocated inside the stack).
   `len' indicates the length of the buffer starting from `pos'. */

typedef struct {
  unsigned char *head;
  unsigned char *pos;
  int len;
} nc_buffer_t;

/* this is the standard netcat hosts record.  It contains an "authoritative"
   `name' field, which may be empty, and a list of IP addresses in the network
   notation and in the dotted string notation. */

typedef struct {
  char name[MAXHOSTNAMELEN];			/* dns name */
  char addrs[MAXINETADDRS][NETCAT_ADDRSTRLEN];	/* ascii-format IP addresses */
  struct in_addr iaddrs[MAXINETADDRS];		/* real addresses */
} nc_host_t;

/* standard netcat port record.  It contains the port `name', which may be
   empty, and the port number both as number and as string. */

typedef struct {
  char name[NETCAT_MAXPORTNAMELEN];	/* canonical port name */
  char ascnum[8];			/* ascii port number */
  unsigned short num;			/* port number */
  /* FIXME: this is just a test! */
  in_port_t netnum;			/* port number in network byte order */
} nc_port_t;

/* This is a more complex struct that holds socket records. [...] */

typedef struct {
  int fd, domain, timeout;
  nc_proto_t proto;
  nc_host_t local_host, host;
  nc_port_t local_port, port;
  nc_buffer_t sendq, recvq;
} nc_sock_t;

/* Netcat includes */

#include "proto.h"
#include "intl.h"
#include "misc.h"

#endif	/* !NETCAT_H */
