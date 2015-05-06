/*
 * netcat.c -- main project file
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <giovanni@giacobbi.net>
 * Copyright (C) 2002 - 2003  Giovanni Giacobbi
 *
 * $Id: netcat.c,v 1.63 2003/08/21 15:27:18 themnemonic Exp $
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "netcat.h"
#include <signal.h>
#include <getopt.h>
#include <time.h>		/* time(2) used as random seed */

/* int gatesidx = 0; */		/* LSRR hop count */
/* int gatesptr = 4; */		/* initial LSRR pointer, settable */
/* nc_host_t **gates = NULL; */	/* LSRR hop hostpoop */
/* char *optbuf = NULL; */	/* LSRR or sockopts */
FILE *output_fp = NULL;		/* output fd (FIXME: i don't like this) */
bool use_stdin = TRUE;		/* tells wether stdin was closed or not */
bool signal_handler = TRUE;	/* handle the signals externally */
bool got_sigterm = FALSE;	/* when this TRUE the application must exit */
bool got_sigint = FALSE;	/* when this TRUE the application should exit */
bool got_sigusr1 = FALSE;	/* when set, the application should print stats */
bool commandline_need_newline = FALSE;	/* fancy output handling */

/* global options flags */
nc_mode_t netcat_mode = 0;	/* Netcat working modality */
bool opt_eofclose = FALSE;	/* close connection on EOF from stdin */
bool opt_debug = FALSE;		/* debugging output */
bool opt_numeric = FALSE;	/* don't resolve hostnames */
bool opt_random = FALSE;	/* use random ports */
bool opt_udpmode = FALSE;	/* use udp protocol instead of tcp */
bool opt_telnet = FALSE;	/* answer in telnet mode */
bool opt_hexdump = FALSE;	/* hexdump traffic */
bool opt_zero = FALSE;		/* zero I/O mode (don't expect anything) */
int opt_interval = 0;		/* delay (in seconds) between lines/ports */
int opt_verbose = 0;		/* be verbose (> 1 to be MORE verbose) */
int opt_wait = 0;		/* wait time */
char *opt_outputfile = NULL;	/* hexdump output file */
char *opt_exec = NULL;		/* program to exec after connecting */
nc_proto_t opt_proto = NETCAT_PROTO_TCP; /* protocol to use for connections */


/* signal handling */

static void got_term(int z)
{
  if (!got_sigterm)
    ncprint(NCPRINT_VERB1, _("Terminated."));
  debug_v(("_____ RECEIVED SIGTERM _____ [signal_handler=%s]",
	  BOOL_TO_STR(signal_handler)));
  got_sigterm = TRUE;
  if (signal_handler)			/* default action */
    exit(EXIT_FAILURE);
}

static void got_int(int z)
{
  if (!got_sigint)
    ncprint(NCPRINT_VERB1, _("Exiting."));
  debug_v(("_____ RECEIVED SIGINT _____ [signal_handler=%s]",
	  BOOL_TO_STR(signal_handler)));
  got_sigint = TRUE;
  if (signal_handler) {			/* default action */
    if (commandline_need_newline)	/* if we were waiting for input */
      printf("\n");
    netcat_printstats(FALSE);
    exit(EXIT_FAILURE);
  }
}

static void got_usr1(int z)
{
  debug_dv(("_____ RECEIVED SIGUSR1 _____ [signal_handler=%s]",
	   BOOL_TO_STR(signal_handler)));
  if (signal_handler)			/* default action */
    netcat_printstats(TRUE);
  else
    got_sigusr1 = TRUE;
}

/* Execute an external file making its stdin/stdout/stderr the actual socket */

static void ncexec(nc_sock_t *ncsock)
{
  int saved_stderr;
  char *p;
  assert(ncsock && (ncsock->fd >= 0));

  /* save the stderr fd because we may need it later */
  saved_stderr = dup(STDERR_FILENO);

  /* duplicate the socket for the child program */
  dup2(ncsock->fd, STDIN_FILENO);	/* the precise order of fiddlage */
  close(ncsock->fd);			/* is apparently crucial; this is */
  dup2(STDIN_FILENO, STDOUT_FILENO);	/* swiped directly out of "inetd". */
  dup2(STDIN_FILENO, STDERR_FILENO);	/* also duplicate the stderr channel */

  /* change the label for the executed program */
  if ((p = strrchr(opt_exec, '/')))
    p++;			/* shorter argv[0] */
  else
    p = opt_exec;

  /* replace this process with the new one */
#ifndef USE_OLD_COMPAT
  execl("/bin/sh", p, "-c", opt_exec, NULL);
#else
  execl(opt_exec, p, NULL);
#endif
  dup2(saved_stderr, STDERR_FILENO);
  ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Couldn't execute %s: %s"),
	  opt_exec, strerror(errno));
}				/* end of ncexec() */

/* main: handle command line arguments and listening status */

int main(int argc, char *argv[])
{
  int c, glob_ret = EXIT_FAILURE;
  int total_ports, left_ports, accept_ret = -1, connect_ret = -1;
  struct sigaction sv;
  nc_port_t local_port;		/* local port specified with -p option */
  nc_host_t local_host;		/* local host for bind()ing operations */
  nc_host_t remote_host;
  nc_sock_t listen_sock;
  nc_sock_t connect_sock;
  nc_sock_t stdio_sock;

  memset(&local_port, 0, sizeof(local_port));
  memset(&local_host, 0, sizeof(local_host));
  memset(&remote_host, 0, sizeof(remote_host));
  memset(&listen_sock, 0, sizeof(listen_sock));
  memset(&connect_sock, 0, sizeof(listen_sock));
  memset(&stdio_sock, 0, sizeof(stdio_sock));
  listen_sock.domain = PF_INET;
  connect_sock.domain = PF_INET;

#ifdef ENABLE_NLS
  setlocale(LC_MESSAGES, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  /* set up the signal handling system */
  sigemptyset(&sv.sa_mask);
  sv.sa_flags = 0;
  sv.sa_handler = got_int;
  sigaction(SIGINT, &sv, NULL);
  sv.sa_handler = got_term;
  sigaction(SIGTERM, &sv, NULL);
  sv.sa_handler = got_usr1;
  sigaction(SIGUSR1, &sv, NULL);
  /* ignore some boring signals */
  sv.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sv, NULL);
  sigaction(SIGURG, &sv, NULL);

  /* if no args given at all, take them from stdin and generate argv */
  if (argc == 1)
    netcat_commandline_read(&argc, &argv);

  /* check for command line switches */
  while (TRUE) {
    int option_index = 0;
    static const struct option long_options[] = {
	{ "close",	no_argument,		NULL, 'c' },
	{ "debug",	no_argument,		NULL, 'd' },
	{ "exec",	required_argument,	NULL, 'e' },
	{ "gateway",	required_argument,	NULL, 'g' },
	{ "pointer",	required_argument,	NULL, 'G' },
	{ "help",	no_argument,		NULL, 'h' },
	{ "interval",	required_argument,	NULL, 'i' },
	{ "listen",	no_argument,		NULL, 'l' },
	{ "tunnel",	required_argument,	NULL, 'L' },
	{ "dont-resolve", no_argument,		NULL, 'n' },
	{ "output",	required_argument,	NULL, 'o' },
	{ "local-port",	required_argument,	NULL, 'p' },
	{ "tunnel-port", required_argument,	NULL, 'P' },
	{ "randomize",	no_argument,		NULL, 'r' },
	{ "source",	required_argument,	NULL, 's' },
	{ "tunnel-source", required_argument,	NULL, 'S' },
#ifndef USE_OLD_COMPAT
	{ "tcp",	no_argument,		NULL, 't' },
	{ "telnet",	no_argument,		NULL, 'T' },
#else
	{ "tcp",	no_argument,		NULL, 1 },
	{ "telnet",	no_argument,		NULL, 't' },
#endif
	{ "udp",	no_argument,		NULL, 'u' },
	{ "verbose",	no_argument,		NULL, 'v' },
	{ "version",	no_argument,		NULL, 'V' },
	{ "hexdump",	no_argument,		NULL, 'x' },
	{ "wait",	required_argument,	NULL, 'w' },
	{ "zero",	no_argument,		NULL, 'z' },
	{ 0, 0, 0, 0 }
    };

    c = getopt_long(argc, argv, "cde:g:G:hi:lL:no:p:P:rs:S:tTuvVxw:z",
		    long_options, &option_index);
    if (c == -1)
      break;

    switch (c) {
    case 'c':			/* close connection on EOF from stdin */
      opt_eofclose = TRUE;
      break;
    case 'd':			/* enable debugging */
      opt_debug = TRUE;
      break;
    case 'e':			/* prog to exec */
      if (opt_exec)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Cannot specify `-e' option double"));
      opt_exec = strdup(optarg);
      break;
    case 'G':			/* srcrt gateways pointer val */
      break;
    case 'g':			/* srcroute hop[s] */
      break;
    case 'h':			/* display help and exit */
      netcat_printhelp(argv[0]);
      exit(EXIT_SUCCESS);
    case 'i':			/* line/ports interval time (seconds) */
      opt_interval = atoi(optarg);
      if (opt_interval <= 0)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Invalid interval time \"%s\""), optarg);
      break;
    case 'l':			/* mode flag: listen mode */
      if (netcat_mode != NETCAT_UNSPEC)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("You can specify mode flags (`-l' and `-L') only once"));
      netcat_mode = NETCAT_LISTEN;
      break;
    case 'L':			/* mode flag: tunnel mode */
      if (netcat_mode != NETCAT_UNSPEC)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("You can specify mode flags (`-l' and `-L') only once"));
      if (opt_zero)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("`-L' and `-z' options are incompatible"));
      do {
	char *div = strchr(optarg, ':');

	if (div && *(div + 1))
	  *div++ = '\0';
	else
	  ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Invalid target string for `-L' option"));

	/* lookup the remote address and the remote port for tunneling */
	if (!netcat_resolvehost(&connect_sock.host, optarg))
	  ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
	  	  _("Couldn't resolve tunnel target host: %s"), optarg);
	if (!netcat_getport(&connect_sock.port, div, 0))
	  ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
	  	  _("Invalid tunnel target port: %s"), div);

	connect_sock.proto = opt_proto;
	connect_sock.timeout = opt_wait;
	netcat_mode = NETCAT_TUNNEL;
      } while (FALSE);
      break;
    case 'n':			/* numeric-only, no DNS lookups */
      opt_numeric = TRUE;
      break;
    case 'o':			/* output hexdump log to file */
      opt_outputfile = strdup(optarg);
      opt_hexdump = TRUE;	/* implied */
      break;
    case 'p':			/* local source port */
      if (!netcat_getport(&local_port, optarg, 0))
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Invalid local port: %s"),
		optarg);
      break;
    case 'P':			/* used only in tunnel mode (source port) */
      if (!netcat_getport(&connect_sock.local_port, optarg, 0))
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Invalid tunnel connect port: %s"), optarg);
      break;
    case 'r':			/* randomize various things */
      opt_random = TRUE;
      break;
    case 's':			/* local source address */
      /* lookup the source address and assign it to the connection address */
      if (!netcat_resolvehost(&local_host, optarg))
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Couldn't resolve local host: %s"), optarg);
      break;
    case 'S':			/* used only in tunnel mode (source ip) */
      if (!netcat_resolvehost(&connect_sock.local_host, optarg))
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("Couldn't resolve tunnel local host: %s"), optarg);
      break;
    case 1:			/* use TCP protocol (default) */
#ifndef USE_OLD_COMPAT
    case 't':
#endif
      opt_proto = NETCAT_PROTO_TCP;
      break;
#ifdef USE_OLD_COMPAT
    case 't':
#endif
    case 'T':			/* answer telnet codes */
      opt_telnet = TRUE;
      break;
    case 'u':			/* use UDP protocol */
      opt_proto = NETCAT_PROTO_UDP;
      break;
    case 'v':			/* be verbose (twice=more verbose) */
      opt_verbose++;
      break;
    case 'V':			/* display version and exit */
      netcat_printversion();
      exit(EXIT_SUCCESS);
    case 'w':			/* wait time (in seconds) */
      opt_wait = atoi(optarg);
      if (opt_wait <= 0)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Invalid wait-time: %s"),
		optarg);
      break;
    case 'x':			/* hexdump traffic */
      opt_hexdump = TRUE;
      break;
    case 'z':			/* little or no data xfer */
      if (netcat_mode == NETCAT_TUNNEL)
	ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("`-L' and `-z' options are incompatible"));
      opt_zero = TRUE;
      break;
    default:
      ncprint(NCPRINT_EXIT, _("Try `%s --help' for more information."), argv[0]);
    }
  }

  if (opt_zero && opt_exec)
    ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
		_("`-e' and `-z' options are incompatible"));

  /* initialize the flag buffer to keep track of the specified ports */
  netcat_flag_init(65535);

#ifndef DEBUG
  /* check for debugging support */
  if (opt_debug)
    ncprint(NCPRINT_WARNING,
	    _("Debugging support not compiled, option `-d' discarded. Using maximum verbosity."));
#endif

  /* randomize only if needed */
  if (opt_random)
#ifdef USE_RANDOM
    SRAND(time(0));
#else
    ncprint(NCPRINT_WARNING,
	    _("Randomization support not compiled, option `-r' discarded."));
#endif

  /* handle the -o option. exit on failure */
  if (opt_outputfile) {
    output_fp = fopen(opt_outputfile, "w");
    if (!output_fp)
      ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Failed to open output file: %s"),
	      strerror(errno));
  }
  else
    output_fp = stderr;

  debug_v(("Trying to parse non-args parameters (argc=%d, optind=%d)", argc,
	  optind));

  /* try to get an hostname parameter */
  if (optind < argc) {
    char *myhost = argv[optind++];
    if (!netcat_resolvehost(&remote_host, myhost))
      ncprint(NCPRINT_ERROR | NCPRINT_EXIT, _("Couldn't resolve host \"%s\""),
	      myhost);
  }

  /* now loop all the other (maybe optional) parameters for port-ranges */
  while (optind < argc) {
    const char *get_argv = argv[optind++];
    char *q, *parse = strdup(get_argv);
    int port_lo = 0, port_hi = 65535;
    nc_port_t port_tmp;

    if (!(q = strchr(parse, '-')))	/* simple number? */
      q = strchr(parse, ':');		/* try with the other separator */

    if (!q) {
      if (netcat_getport(&port_tmp, parse, 0))
	netcat_flag_set(port_tmp.num, TRUE);
      else
	goto got_err;
    }
    else {		/* could be in the forms: N1-N2, -N2, N1- */
      *q++ = 0;
      if (*parse) {
	if (netcat_getport(&port_tmp, parse, 0))
	  port_lo = port_tmp.num;
	else
	  goto got_err;
      }
      if (*q) {
	if (netcat_getport(&port_tmp, q, 0))
	  port_hi = port_tmp.num;
	else
	  goto got_err;
      }
      if (!*parse && !*q)		/* don't accept the form '-' */
	goto got_err;

      /* now update the flagset (this is int, so it's ok even if hi == 65535) */
      while (port_lo <= port_hi)
	netcat_flag_set(port_lo++, TRUE);
    }

    free(parse);
    continue;

 got_err:
    free(parse);
    ncprint(NCPRINT_ERROR, _("Invalid port specification: %s"), get_argv);
    exit(EXIT_FAILURE);
  }

  debug_dv(("Arguments parsing complete! Total ports=%d", netcat_flag_count()));
#if 0
  /* pure debugging code */
  c = 0;
  while ((c = netcat_flag_next(c))) {
    printf("Got port=%d\n", c);
  }
  exit(0);
#endif

  /* Handle listen mode and tunnel mode (whose index number is higher) */
  if (netcat_mode > NETCAT_CONNECT) {
    /* in tunnel mode the opt_zero flag is illegal, while on listen mode it
       means that no connections should be accepted.  For UDP it means that
       no remote addresses should be used as default endpoint, which means
       that we can't send anything.  In both situations, stdin is no longer
       useful, so close it. */
    if (opt_zero) {
      close(STDIN_FILENO);
      use_stdin = FALSE;
    }

    /* prepare the socket var and start listening */
    listen_sock.proto = opt_proto;
    listen_sock.timeout = opt_wait;
    memcpy(&listen_sock.local_host, &local_host, sizeof(listen_sock.local_host));
    memcpy(&listen_sock.local_port, &local_port, sizeof(listen_sock.local_port));
    memcpy(&listen_sock.host, &remote_host, sizeof(listen_sock.host));
    accept_ret = core_listen(&listen_sock);

    /* in zero I/O mode the core_tcp_listen() call will always return -1
       (ETIMEDOUT) since no connections are accepted, because of this our job
       is completed now. */
    if (accept_ret < 0) {
      /* since i'm planning to make `-z' compatible with `-L' I need to check
         the exact error that caused this failure. */
      if (opt_zero && (errno == ETIMEDOUT))
	exit(0);

      ncprint(NCPRINT_VERB1 | NCPRINT_EXIT, _("Listen mode failed: %s"),
	      strerror(errno));
    }

    /* if we are in listen mode, run the core loop and exit when it returns.
       otherwise now it's the time to connect to the target host and tunnel
       them together (which means passing to the next section. */
    if (netcat_mode == NETCAT_LISTEN) {
      if (opt_exec) {
	ncprint(NCPRINT_VERB2, _("Passing control to the specified program"));
	ncexec(&listen_sock);		/* this won't return */
      }
      core_readwrite(&listen_sock, &stdio_sock);
      debug_dv(("Listen: EXIT"));
    }
    else {
      /* otherwise we are in tunnel mode.  The connect_sock var was already
         initialized by the command line arguments. */
      assert(netcat_mode == NETCAT_TUNNEL);
      connect_ret = core_connect(&connect_sock);

      /* connection failure? (we cannot get this in UDP mode) */
      if (connect_ret < 0) {
	assert(opt_proto != NETCAT_PROTO_UDP);
	ncprint(NCPRINT_VERB1, "%s: %s",
		netcat_strid(&connect_sock.host, &connect_sock.port),
		strerror(errno));
      }
      else {
	glob_ret = EXIT_SUCCESS;
	core_readwrite(&listen_sock, &connect_sock);
	debug_dv(("Tunnel: EXIT (ret=%d)", glob_ret));
      }
    }

    /* all jobs should be ok, go to the cleanup */
    goto main_exit;
  }				/* end of listen and tunnel mode handling */

  /* we need to connect outside, this is the connect mode */
  netcat_mode = NETCAT_CONNECT;

  /* first check that a host parameter was given */
  if (!remote_host.iaddrs[0].s_addr) {
    /* FIXME: The Networking specifications state that host address "0" is a
       valid host to connect to but this broken check will assume as not
       specified. */
    ncprint(NCPRINT_NORMAL, _("%s: missing hostname argument"), argv[0]);
    ncprint(NCPRINT_EXIT, _("Try `%s --help' for more information."), argv[0]);
  }

  /* since ports are the second argument, checking ports might be enough */
  total_ports = netcat_flag_count();
  if (total_ports == 0)
    ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
	    _("No ports specified for connection"));

  c = 0;			/* must be set to 0 for netcat_flag_next() */
  left_ports = total_ports;
  while (left_ports > 0) {
    /* `c' is the port number independently of the sorting method (linear
       or random).  While in linear mode it is also used to fetch the next
       port number */
    if (opt_random)
      c = netcat_flag_rand();
    else
      c = netcat_flag_next(c);
    left_ports--;		/* decrease the total ports number to try */

    /* since we are nonblocking now, we can start as many connections as we want
       but it's not a great idea connecting more than one host at time */
    connect_sock.proto = opt_proto;
    connect_sock.timeout = opt_wait;
    memcpy(&connect_sock.local_host, &local_host,
	   sizeof(connect_sock.local_host));
    memcpy(&connect_sock.local_port, &local_port,
	   sizeof(connect_sock.local_port));
    memcpy(&connect_sock.host, &remote_host, sizeof(connect_sock.host));
    netcat_getport(&connect_sock.port, NULL, c);

    /* FIXME: in udp mode and NETCAT_CONNECT, opt_zero is senseless */
    connect_ret = core_connect(&connect_sock);

    /* connection failure? (we cannot get this in UDP mode) */
    if (connect_ret < 0) {
      int ncprint_flags = NCPRINT_VERB1;
      assert(connect_sock.proto != NETCAT_PROTO_UDP);

      /* if we are portscanning or multiple connecting show only open
         ports with verbosity level 1. */
      if (total_ports > 1)
	ncprint_flags = NCPRINT_VERB2;

      ncprint(ncprint_flags, "%s: %s",
	      netcat_strid(&connect_sock.host, &connect_sock.port),
	      strerror(errno));
      continue;			/* go with next port */
    }

    /* when portscanning (or checking a single port) we are happy if AT LEAST
       ONE port is available. */
    glob_ret = EXIT_SUCCESS;

    if (opt_zero) {
      shutdown(connect_ret, 2);
      close(connect_ret);
    }
    else {
      if (opt_exec) {
	ncprint(NCPRINT_VERB2, _("Passing control to the specified program"));
	ncexec(&connect_sock);		/* this won't return */
      }
      core_readwrite(&connect_sock, &stdio_sock);
      /* FIXME: add a small delay */
      debug_v(("Connect: EXIT"));

      /* both signals are handled inside core_readwrite(), but while the
         SIGINT signal is fully handled, the SIGTERM requires some action
         from outside that function, because of this that flag is not
         cleared. */
      if (got_sigterm)
	break;
    }
  }			/* end of while (left_ports > 0) */

  /* all basic modes should return here for the final cleanup */
 main_exit:
  debug_v(("Main: EXIT (cleaning up)"));

  netcat_printstats(FALSE);
  return glob_ret;
}				/* end of main() */
