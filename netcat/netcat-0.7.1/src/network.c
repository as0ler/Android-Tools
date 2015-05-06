/*
 * network.c -- all network related functions and helpers
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <giovanni@giacobbi.net>
 * Copyright (C) 2002 - 2004  Giovanni Giacobbi
 *
 * $Id: network.c,v 1.38 2004/01/03 16:42:07 themnemonic Exp $
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
#include <netdb.h>		/* hostent, gethostby*, getservby* */
#include <fcntl.h>		/* fcntl() */

/* Fills the structure pointed to by `dst' with the valid DNS information
   for the target identified by `name', which can be an hostname or a valid IP
   address in the dotted notation.
   The hostname field is stored in the results structure only if it is actually
   authoritative for that machine.
   Returns TRUE on success or FALSE otherwise.  On success, at least one IP
   address will be in the results, while there could be an empty hostname. */

bool netcat_resolvehost(nc_host_t *dst, const char *name)
{
  int i, ret;
  struct hostent *hostent;
  struct in_addr res_addr;

  assert(name && name[0]);
  debug_v(("netcat_resolvehost(dst=%p, name=\"%s\")", (void *)dst, name));

  /* reset all fields of the dst struct */
  memset(dst, 0, sizeof(*dst));

  ret = netcat_inet_pton(name, &res_addr);
  if (!ret) {			/* couldn't translate: it must be a name! */
    bool host_auth_taken = FALSE;

    /* if the opt_numeric option is set, we must not use DNS in any way */
    if (opt_numeric)
      return FALSE;

    /* failures to look up a name are reported to the calling function */
    if (!(hostent = gethostbyname(name)))
      return FALSE;

    /* now I need to handle the host aliases (CNAME).  If we lookup host
       www.bighost.foo, which is an alias for www.bighost.mux.foo, the hostent
       struct will contain the real name in h_name, which is not what we want
       for the output purpose (the user doesn't want to see something he didn't
       type.  So assume the lookup name as the "official" name and fetch the
       ips for the reverse lookup. */
    debug(("(lookup) lookup=\"%s\" official=\"%s\" (should match)\n", name,
	  hostent->h_name));
    strncpy(dst->name, name, MAXHOSTNAMELEN - 1);

    /* now save all the available ip addresses (no more than MAXINETADDRS) */
    for (i = 0; hostent->h_addr_list[i] && (i < MAXINETADDRS); i++) {
      memcpy(&dst->iaddrs[i], hostent->h_addr_list[i], sizeof(dst->iaddrs[0]));
      strncpy(dst->addrs[i], netcat_inet_ntop(&dst->iaddrs[i]),
	      sizeof(dst->addrs[0]));
    }				/* end of foreach addr, part A */

    /* for speed purposes, skip the authoritative checking if we haven't got
       any verbosity level set.  note that this will cause invalid results
       in the dst struct, but we don't care at this point. */
    if (!opt_debug && (opt_verbose < 1))
      return TRUE;

    /* do inverse lookups in a separated loop for each collected addresses */
    for (i = 0; dst->iaddrs[i].s_addr && (i < MAXINETADDRS); i++) {
      hostent = gethostbyaddr((char *)&dst->iaddrs[i], sizeof(dst->iaddrs[0]),
			      AF_INET);

      if (!hostent || !hostent->h_name) {
	ncprint(NCPRINT_VERB1 | NCPRINT_WARNING,
		_("Inverse name lookup failed for `%s'"), dst->addrs[i]);
	continue;
      }

      /* now the case.  hostnames aren't case sensitive because of this we may
         find a different case for the authoritative hostname.  For the same
         previous reason we may want to keep the user typed case, but this time
         we are going to override it because this tool is a "network exploration
         tool", thus it's good to see the case they chose for this host. */
      if (strcasecmp(dst->name, hostent->h_name)) {
	int xcmp;
	char savedhost[MAXHOSTNAMELEN];

	/* refering to the flowchart (see the drafts directory contained in
	   this package), try to guess the real hostname */
	strncpy(savedhost, hostent->h_name, sizeof(savedhost));
	savedhost[sizeof(savedhost) - 1] = 0;

	/* ok actually the given host and the reverse-resolved address doesn't
	   match, so try to see if we can find the real machine name.  In order to
	   this to happen the originally found address must match with the newly
	   found hostname directly resolved.  If this doesn't, or if this resolve
	   fails, then fall back to the original warning message: they have a DNS
	   misconfigured! */
	hostent = gethostbyname(savedhost);
	if (!hostent)
	  continue;		/* FIXME: missing information analysis */

	for (xcmp = 0; hostent->h_addr_list[xcmp] &&
		(xcmp < MAXINETADDRS); xcmp++) {
	  if (!memcmp(&dst->iaddrs[i], hostent->h_addr_list[xcmp],
		     sizeof(dst->iaddrs[0])))
	    goto found_real_host;
	}

	ncprint(NCPRINT_WARNING | NCPRINT_VERB1,
		_("This host's reverse DNS doesn't match! %s -- %s"),
		hostent->h_name, dst->name);
	continue;

 found_real_host:
	ncprint(NCPRINT_NOTICE | NCPRINT_VERB2,
		_("Real hostname for %s [%s] is %s"),
		dst->name, dst->addrs[i], savedhost);
	continue;
      }
      else if (!host_auth_taken) {	/* case: take only the first one as auth */
	strncpy(dst->name, hostent->h_name, sizeof(dst->name));
	host_auth_taken = TRUE;
      }
    }				/* end of foreach addr, part B */
  }
  else {		/* `name' is a numeric address, try reverse lookup */
    memcpy(&dst->iaddrs[0], &res_addr, sizeof(dst->iaddrs[0]));
    strncpy(dst->addrs[0], netcat_inet_ntop(&res_addr), sizeof(dst->addrs[0]));

    /* if opt_numeric is set or we don't require verbosity, we are done */
    if (opt_numeric)
      return TRUE;

    /* numeric or not, failure to look up a PTR is *not* considered fatal */
    hostent = gethostbyaddr((char *)&res_addr, sizeof(res_addr), AF_INET);
    if (!hostent)
      ncprint(NCPRINT_VERB2 | NCPRINT_WARNING,
	      _("Inverse name lookup failed for `%s'"), name);
    else {
      strncpy(dst->name, hostent->h_name, MAXHOSTNAMELEN - 2);
      /* now do the direct lookup to see if the PTR was authoritative */
      hostent = gethostbyname(dst->name);

      /* Any kind of failure in this section results in a host not auth
         warning, and the dst->name field cleaned (I don't care if there is a
         PTR, if it's unauthoritative). */
      if (!hostent || !hostent->h_addr_list[0]) {
	ncprint(NCPRINT_VERB1 | NCPRINT_WARNING,
		_("Host %s isn't authoritative! (direct lookup failed)"),
		dst->addrs[0]);
	goto check_failed;
      }
      for (i = 0; hostent->h_addr_list[i] && (i < MAXINETADDRS); i++)
	if (!memcmp(&dst->iaddrs[0], hostent->h_addr_list[i],
		    sizeof(dst->iaddrs[0])))
	  return TRUE;

      ncprint(NCPRINT_VERB1 | NCPRINT_WARNING,
	      _("Host %s isn't authoritative! (direct lookup mismatch)"),
	      dst->addrs[0]);
      ncprint(NCPRINT_VERB1, _("  %s -> %s  BUT  %s -> %s"),
	      dst->addrs[0], dst->name, dst->name,
	      netcat_inet_ntop(hostent->h_addr_list[0]));

 check_failed:
      memset(dst->name, 0, sizeof(dst->name));
    }				/* if hostent */
  }

  return TRUE;
}

/* Identifies a port and fills in the netcat_port structure pointed to by
   `dst'.  If `port_string' is not NULL, it is used to identify the port
   (either by port name, listed in /etc/services, or by a string number).  In
   this case `port_num' is discarded.
   If `port_string' is NULL then `port_num' is used to identify the port and
   if opt_numeric is not TRUE, the port name is looked up reversely. */

bool netcat_getport(nc_port_t *dst, const char *port_string,
		    unsigned short port_num)
{
  const char *get_proto = (opt_proto == NETCAT_PROTO_UDP ? "udp" : "tcp");
  struct servent *servent;

  debug_v(("netcat_getport(dst=%p, port_string=\"%s\", port_num=%hu)",
	  (void *)dst, NULL_STR(port_string), port_num));

/* Obligatory netdb.h-inspired rant: servent.s_port is supposed to be an int.
   Despite this, we still have to treat it as a short when copying it around.
   Not only that, but we have to convert it *back* into net order for
   getservbyport to work.  Manpages generally aren't clear on all this, but
   there are plenty of examples in which it is just quietly done. -hobbit */

  /* reset all fields of the dst struct */
  memset(dst, 0, sizeof(*dst));

  if (!port_string) {
    if (port_num == 0)
      return FALSE;
    dst->num = port_num;
    dst->netnum = htons(port_num);
    servent = getservbyport((int)dst->netnum, get_proto);
    if (servent) {
      assert(dst->netnum == servent->s_port);
      strncpy(dst->name, servent->s_name, sizeof(dst->name));
    }
    goto end;
  }
  else {
    long port;
    char *endptr;

    /* empty string? refuse it */
    if (!port_string[0])
      return FALSE;

    /* try to convert the string into a valid port number.  If an error occurs
       but it doesn't occur at the first char, throw an error */
    port = strtol(port_string, &endptr, 10);
    if (!endptr[0]) {
      /* pure numeric value, check it out */
      if ((port > 0) && (port < 65536))
        return netcat_getport(dst, NULL, (in_port_t)port);
      else
        return FALSE;
    }
    else if (endptr != port_string)	/* mixed numeric and string value */
      return FALSE;

    /* this is a port name, try to lookup it */
    servent = getservbyname(port_string, get_proto);
    if (servent) {
      strncpy(dst->name, servent->s_name, sizeof(dst->name));
      dst->netnum = servent->s_port;
      dst->num = ntohs(dst->netnum);
      goto end;
    }
    return FALSE;
  }

 end:
  snprintf(dst->ascnum, sizeof(dst->ascnum), "%hu", dst->num);
  return TRUE;
}			/* end of netcat_getport() */

/* returns a pointer to a static buffer containing a description of the remote
   host in the best form available (using hostnames and portnames) */

/*    MAXHOSTNAMELEN     _ [ ADDRSTRLEN ]   _ 5 _    ( MAXPORTNAMELEN ) */
/* "my.very.long.hostname [255.255.255.255] 65535 (my_very_long_port_name)" */

const char *netcat_strid(const nc_host_t *host, const nc_port_t *port)
{
  static char buf[MAXHOSTNAMELEN + NETCAT_ADDRSTRLEN +
		  NETCAT_MAXPORTNAMELEN + 15];
  char *p = buf;
  assert(host && port);

  if (host->iaddrs[0].s_addr) {
    if (host->name[0])
      p += snprintf(p, sizeof(buf) + buf - p, "%s [%s]", host->name,
		    host->addrs[0]);
    else
      p += snprintf(p, sizeof(buf) + buf - p, "%s", host->addrs[0]);
  }
  else
    p += snprintf(p, sizeof(buf) + buf - p, _("any address"));

  p += snprintf(p, sizeof(buf) + buf - p, " %s", port->ascnum);
  if (port->name[0])
    p += snprintf(p, sizeof(buf) + buf - p, " (%s)", port->name);

  return buf;
}

/* Create a network address structure.  This function is a compatibility
   replacement for the standard POSIX inet_pton() function. */

int netcat_inet_pton(const char *src, void *dst)
{
  int ret;

#ifdef HAVE_INET_PTON
  ret = inet_pton(AF_INET, src, dst);
#else
# ifdef __GNUC__
#  warning Using broken network address conversion function for pton
# endif
  ret = inet_aton(src, (struct in_addr *)dst);
#endif

  return ret;
}			/* end of netcat_inet_pton() */

/* Parse a network address structure.  This function is a compatibility
   replacement for the standard POSIX inet_ntop() function. */

const char *netcat_inet_ntop(const void *src)
{
#ifdef HAVE_INET_NTOP
  static char my_buf[127];
#endif
  const char *ret;

  debug_v(("netcat_inet_ntop(src=%p)", src));

#ifdef HAVE_INET_NTOP
  /* FIXME: Since inet_ntop breaks on IPv6-mapped IPv4 addresses i'll need to
   * sort it out by myself. */
  ret = inet_ntop(AF_INET, src, my_buf, sizeof(my_buf));
#else
# ifdef __GNUC__
#  warning Using broken network address conversion function for ntop
# endif
  ret = inet_ntoa(*(struct in_addr *)src);
#endif

  return ret;
}			/* end of netcat_inet_ntop() */

/* Backend for the socket(2) system call.  This function wraps the creation of
   new sockets and sets the common SO_REUSEADDR socket option, and the useful
   SO_LINGER option (if system available) handling eventual errors.
   Returns -1 if the socket(2) call failed, -2 if the setsockopt() call failed;
   otherwise the return value is a descriptor referencing the new socket. */

int netcat_socket_new(int domain, int type)
{
  int sock, ret, sockopt;
  struct linger fix_ling;

  sock = socket(domain, type, 0);
  if (sock < 0)
    return -1;

  /* don't leave the socket in a TIME_WAIT state if we close the connection */
  fix_ling.l_onoff = 1;
  fix_ling.l_linger = 0;
  ret = setsockopt(sock, SOL_SOCKET, SO_LINGER, &fix_ling, sizeof(fix_ling));
  if (ret < 0) {
    close(sock);		/* anyway the socket was created */
    return -2;
  }

  /* fix the socket options */
  sockopt = 1;
  ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt));
  if (ret < 0) {
    close(sock);		/* anyway the socket was created */
    return -2;
  }

  return sock;
}

/* Creates a full outgoing async socket connection in the specified `domain'
   and `type' to the specified `addr' and `port'.  The connection is
   originated using the optionally specified `local_addr' and `local_port'.
   If `local_addr' is NULL and `local_port' is 0 the bind(2) call is skipped.
   Returns the descriptor referencing the new socket on success, otherwise
   returns -1 or -2 if socket creation failed (see netcat_socket_new()),
   or -3 if the bind(2) call failed, -4 if the fcntl(2) call failed, or -5
   if the connect(2) call failed. */

int netcat_socket_new_connect(int domain, int type, const struct in_addr *addr,
		in_port_t port, const struct in_addr *local_addr,
		in_port_t local_port)
{
  int sock, ret, my_family = AF_UNSPEC;
  struct sockaddr_in rem_addr;
  assert(addr);

  debug_dv(("netcat_socket_new_connect(addr=%p, port=%hu, local_addr=%p, local_"
	   "port=%hu)", (void *)addr, ntohs(port), (void *)local_addr,
	   ntohs(local_port)));

  /* selects the currently supported domains */
  if (domain == PF_INET)
    my_family = AF_INET;
  else
    return -1;		/* assumes as the socket(2) call failed */

  memset(&rem_addr, 0, sizeof(rem_addr));
  rem_addr.sin_family = my_family;
  rem_addr.sin_port = port;
  memcpy(&rem_addr.sin_addr, addr, sizeof(rem_addr.sin_addr));

  /* create the socket and fix the options */
  sock = netcat_socket_new(domain, type);
  if (sock < 0)
    return sock;		/* just forward the error code */

  /* only if needed, bind it to a local address */
  if (local_addr || local_port) {
    struct sockaddr_in my_addr;

    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = my_family;
    my_addr.sin_port = local_port;

    /* local_addr may not be specified because the user may want to only
       enforce the local source port */
    if (local_addr)
      memcpy(&my_addr.sin_addr, local_addr, sizeof(my_addr.sin_addr));

    ret = bind(sock, (struct sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) {
      ret = -3;
      goto err;
    }
  }

  /* add the non-blocking flag to this socket */
  if ((ret = fcntl(sock, F_GETFL, 0)) >= 0)
    ret = fcntl(sock, F_SETFL, ret | O_NONBLOCK);
  if (ret < 0) {
    ret = -4;
    goto err;
  }

  /* now launch the real connection.  Since we are in non-blocking mode, this
     call will return -1 in MOST cases (on some systems, a connect() to a local
     address may immediately return successfully) */
  ret = connect(sock, (struct sockaddr *)&rem_addr, sizeof(rem_addr));
  if ((ret < 0) && (errno != EINPROGRESS)) {
    ret = -5;
    goto err;
  }

  /* everything went fine, return the (connected or connecting) socket */
  return sock;

 err:
  /* the if () statement is unuseful, but I need to for declaring vars */
  if (ret < 0) {
    int tmpret, saved_errno = errno;

    /* the close() calls MUST NOT fail */
    tmpret = close(sock);
    assert(tmpret >= 0);

    /* restore the original errno */
    errno = saved_errno;
  }
  return ret;
}

/* Creates a listening TCP (stream) socket already bound and in listening
   state in the specified `domain', ready for accept(2) or select(2).  The
   `addr' parameter is optional and specifies the local interface at which
   socket should be bound to.  If `addr' is NULL, it defaults to INADDR_ANY,
   which is a valid value as well.
   Returns the descriptor referencing the listening socket on success,
   otherwise returns -1 or -2 if socket creation failed (see
   netcat_socket_new()), -3 if the bind(2) call failed, or -4 if the listen(2)
   call failed. */

int netcat_socket_new_listen(int domain, const struct in_addr *addr,
			     in_port_t port)
{
  int sock, ret, my_family;
  struct sockaddr_in my_addr;

  debug_dv(("netcat_socket_new_listen(addr=%p, port=%hu)", (void *)addr, port));

  /* selects the currently supported domains */
  if (domain == PF_INET)
    my_family = AF_INET;
  else
    return -1;		/* assumes as the socket(2) call failed */

  /* Reset the sockaddr structure */
  memset(&my_addr, 0, sizeof(my_addr));
  my_addr.sin_family = my_family;
  my_addr.sin_port = port;

  /* this parameter is not mandatory.  if it's not present, it's assumed as
     INADDR_ANY, and the behaviour is the same */
  if (addr)
    memcpy(&my_addr.sin_addr, addr, sizeof(my_addr.sin_addr));

  /* create the socket and fix the options */
  sock = netcat_socket_new(domain, SOCK_STREAM);
  if (sock < 0)
    return sock;		/* forward the error code */

  /* bind it to the specified address (can be INADDY_ANY) */
  ret = bind(sock, (struct sockaddr *)&my_addr, sizeof(my_addr));
  if (ret < 0) {
    ret = -3;
    goto err;
  }

  /* now make it listening, with a reasonable backlog value */
  ret = listen(sock, 4);
  if (ret < 0) {
    ret = -4;
    goto err;
  }

  return sock;

 err:
  /* the if () statement is unuseful, but I need to for declaring vars */
  if (ret < 0) {
    int tmpret, saved_errno = errno;

    /* the close() calls MUST NOT fail */
    tmpret = close(sock);
    assert(tmpret >= 0);

    /* restore the original errno */
    errno = saved_errno;
  }
  return ret;
}

/* This function is much like the accept(2) call, but implements also the
   parameter `timeout', which specifies the time (in seconds) after which the
   function returns.  If `timeout' is negative, the remaining of the last
   valid timeout specified is used.  If it reached zero, or if the timeout
   hasn't been initialized already, this function waits forever.
   Returns -1 on error, setting the errno variable.  If it succeeds, it
   returns a non-negative integer that is the file descriptor for the accepted
   socket. */

int netcat_socket_accept(int s, int timeout)
{
  fd_set in;
  int ret;
  static bool timeout_init = FALSE;
  static struct timeval timest;

  debug_v(("netcat_socket_accept(s=%d, timeout=%d)", s, timeout));

  /* initialize the select() variables */
  FD_ZERO(&in);
  FD_SET(s, &in);
  if (timeout > 0) {
    timest.tv_sec = timeout;
    timest.tv_usec = 0;
    timeout_init = TRUE;
  }
  else if (timeout && !timeout_init) {
    /* means that timeout is < 0 and timest hasn't been initialized */
    timeout = 0;
  }

  /* now call select(2).  use timest only if we won't wait forever */
 call_select:
  ret = select(s + 1, &in, NULL, NULL, (timeout ? &timest : NULL));
  if (ret < 0) {
    /* if the call was interrupted by a signal nothing happens. signal at this
       stage ought to be handled externally. */
    if (errno == EINTR)
      goto call_select;
    perror("select(sock_accept)");
    exit(EXIT_FAILURE);
  }

  /* have we got this connection? */
  if (FD_ISSET(s, &in)) {
    int new_sock;

    new_sock = accept(s, NULL, NULL);
    debug_v(("Connection received (new fd=%d)", new_sock));

    /* NOTE: as accept() could fail, new_sock might also be a negative value.
       It's application's work to handle the right errno. */
    return new_sock;
  }

  /* since we've got a timeout, the timest is now zero and thus it is like
     uninitialized.  Next time assume wait forever. */
  timeout_init = FALSE;

  /* no connections arrived during the given time. nothing happens */
  errno = ETIMEDOUT;
  return -1;
}
