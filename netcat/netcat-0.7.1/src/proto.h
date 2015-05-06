/*
 * proto.h -- contains all global variables and functions prototypes
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <giovanni@giacobbi.net>
 * Copyright (C) 2002 - 2004  Giovanni Giacobbi
 *
 * $Id: proto.h,v 1.41 2004/01/03 16:42:07 themnemonic Exp $
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

/* core.c */
extern unsigned long bytes_sent, bytes_recv;
int core_connect(nc_sock_t *ncsock);
int core_listen(nc_sock_t *ncsock);
int core_readwrite(nc_sock_t *nc_main, nc_sock_t *nc_slave);

/* flagset.c */
bool netcat_flag_init(unsigned int len);
void netcat_flag_set(unsigned short port, bool flag);
bool netcat_flag_get(unsigned short port);
unsigned short netcat_flag_next(unsigned short port);
int netcat_flag_count(void);
unsigned short netcat_flag_rand(void);

/* misc.c */
int netcat_fhexdump(FILE *stream, char c, const void *data, size_t datalen);
int netcat_snprintnum(char *str, size_t size, unsigned long number);
void ncprint(int type, const char *fmt, ...);
void netcat_printstats(bool force);
char *netcat_string_split(char **buf);
void netcat_commandline_read(int *argc, char ***argv);
void netcat_printhelp(char *argv0);
void netcat_printversion(void);
#ifdef DEBUG
const char *debug_fmt(const char *fmt, ...);
#endif
#ifndef USE_LINUX_SELECT
void update_timeval(struct timeval *target);
#endif

/* netcat.c */
extern nc_mode_t netcat_mode;
extern bool opt_eofclose, opt_debug, opt_numeric, opt_random, opt_hexdump,
	opt_telnet, opt_zero;
extern int opt_interval, opt_verbose, opt_wait;
extern char *opt_outputfile;
extern nc_proto_t opt_proto;
extern FILE *output_fp;
extern bool use_stdin, signal_handler, got_sigterm, got_sigint, got_sigusr1,
	commandline_need_newline;

/* network.c */
bool netcat_resolvehost(nc_host_t *dst, const char *name);
bool netcat_getport(nc_port_t *dst, const char *port_string,
		    unsigned short port_num);
const char *netcat_strid(const nc_host_t *host, const nc_port_t *port);
int netcat_inet_pton(const char *src, void *dst);
const char *netcat_inet_ntop(const void *src);
int netcat_socket_new(int domain, int type);
int netcat_socket_new_connect(int domain, int type, const struct in_addr *addr,
		in_port_t port, const struct in_addr *local_addr,
		in_port_t local_port);
int netcat_socket_new_listen(int domain, const struct in_addr *addr,
			     in_port_t port);
int netcat_socket_accept(int fd, int timeout);

/* telnet.c */
void netcat_telnet_parse(nc_sock_t *ncsock);

/* udphelper.c */
#ifdef USE_PKTINFO
int udphelper_ancillary_read(struct msghdr *my_hdr,
			     struct sockaddr_in *get_addr);
#else
int udphelper_sockets_open(int **sockbuf, in_port_t nport);
#endif
void udphelper_sockets_close(int *sockbuf);
