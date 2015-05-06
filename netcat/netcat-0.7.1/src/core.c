/*
 * core.c -- core loops and most critical routines
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <giovanni@giacobbi.net>
 * Copyright (C) 2002 - 2004  Giovanni Giacobbi
 *
 * $Id: core.c,v 1.38 2004/01/03 16:42:07 themnemonic Exp $
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

/* Global variables */

unsigned long bytes_sent = 0;		/* total bytes received */
unsigned long bytes_recv = 0;		/* total bytes sent */

/* Creates a UDP socket with a default destination address.  It also calls
   bind(2) if it is needed in order to specify the source address.
   Returns the new socket number. */

static int core_udp_connect(nc_sock_t *ncsock)
{
  int ret, sock;
  struct sockaddr_in myaddr;
  debug_v(("core_udp_connect(ncsock=%p)", (void *)ncsock));

  sock = netcat_socket_new(PF_INET, SOCK_DGRAM);
  if (sock < 0)
    return -1;

  /* prepare myaddr for the bind() call */
  myaddr.sin_family = AF_INET;
  myaddr.sin_port = ncsock->local_port.netnum;
  memcpy(&myaddr.sin_addr, &ncsock->local_host.iaddrs[0],
	 sizeof(myaddr.sin_addr));
  /* only call bind if it is really needed */
  if (myaddr.sin_port || myaddr.sin_addr.s_addr) {
    ret = bind(sock, (struct sockaddr *)&myaddr, sizeof(myaddr));
    if (ret < 0)
      goto err;
  }

  /* now prepare myaddr for the connect() call */
  myaddr.sin_family = AF_INET;
  myaddr.sin_port = ncsock->port.netnum;
  memcpy(&myaddr.sin_addr, &ncsock->host.iaddrs[0], sizeof(myaddr.sin_addr));
  ret = connect(sock, (struct sockaddr *)&myaddr, sizeof(myaddr));
  if (ret < 0)
    goto err;

  return sock;

 err:
  close(sock);
  return -1;
}				/* end of core_udp_connect() */

/* Emulates a TCP connection but using the UDP protocol.  There is a listening
   socket that catches the first valid packet and assumes the packet endpoints
   as the endpoints for the final connection. */

static int core_udp_listen(nc_sock_t *ncsock)
{
  int ret, *sockbuf, sock, sock_max, timeout = ncsock->timeout;
  bool need_udphelper = TRUE;
#ifdef USE_PKTINFO
  int sockopt = 1;
#endif
  struct sockaddr_in myaddr;
  struct timeval tt;		/* needed by the select() call */
  debug_v(("core_udp_listen(ncsock=%p)", (void *)ncsock));

#ifdef USE_PKTINFO
  need_udphelper = FALSE;
#else
  /* if we need a specified source address then go straight to it */
  if (ncsock->local_host.iaddrs[0].s_addr)
    need_udphelper = FALSE;
#endif

  if (!need_udphelper) {
    /* simulates a udphelper_sockets_open() call */
    sockbuf = calloc(2, sizeof(int));
    sockbuf[0] = 1;
    sockbuf[1] = sock = netcat_socket_new(PF_INET, SOCK_DGRAM);
  }
#ifndef USE_PKTINFO
  else
    sock = udphelper_sockets_open(&sockbuf, ncsock->local_port.netnum);
#endif
  if (sock < 0)
    goto err;

  /* we know that udphelper_sockets_open() returns the highest socket, and
     if we didn't call it we have just one socket */
  sock_max = sock + 1;

  if (!need_udphelper) {
    /* prepare myaddr for the bind() call */
    myaddr.sin_family = AF_INET;
    myaddr.sin_port = ncsock->local_port.netnum;
    memcpy(&myaddr.sin_addr, &ncsock->local_host.iaddrs[0],
	   sizeof(myaddr.sin_addr));
    /* bind() MUST be called in this function, since it's the final call for
       this type of socket. FIXME: I heard that UDP port 0 is illegal. true? */
    ret = bind(sock, (struct sockaddr *)&myaddr, sizeof(myaddr));
    if (ret < 0)
      goto err;
  }

#ifdef USE_PKTINFO
  /* set the right flag in order to obtain the ancillary data */
  ret = setsockopt(sock, SOL_IP, IP_PKTINFO, &sockopt, sizeof(sockopt));
  if (ret < 0)
    goto err;
#endif

  /* if the port was set to 0 this means that it is assigned randomly by the
     OS.  Find out which port they assigned to us. */
  if (ncsock->local_port.num == 0) {
    struct sockaddr_in get_myaddr;
    unsigned int get_myaddr_len = sizeof(get_myaddr);

    ret = getsockname(sock, (struct sockaddr *)&get_myaddr, &get_myaddr_len);
    if (ret < 0)
      goto err;
    netcat_getport(&ncsock->local_port, NULL, ntohs(get_myaddr.sin_port));
    assert(ncsock->local_port.num != 0);
  }

  if (!need_udphelper)
    ncprint(NCPRINT_VERB2, _("Listening on %s"),
	    netcat_strid(&ncsock->local_host, &ncsock->local_port));
  else
    ncprint(NCPRINT_VERB2, _("Listening on %s (using %d sockets)"),
	    netcat_strid(&ncsock->local_host, &ncsock->local_port), sockbuf[0]);

  /* since this protocol is connectionless, we need a special handling here.
     We want to simulate a two-ends connection but in order to do this we need
     a remote address and a local address (in case we bound to INADDR_ANY).
     Wait here until a packet is received, and use its source and destination
     addresses as default endpoints.  If we have the zero-I/O option set, we
     just eat the packet and return when timeout is elapsed (maybe never). */
  tt.tv_sec = timeout;
  tt.tv_usec = 0;

  while (TRUE) {
    int socks_loop;
    fd_set ins;

    FD_ZERO(&ins);
    for (socks_loop = 1; socks_loop <= sockbuf[0]; socks_loop++) {
      debug_v(("Setting sock %d on ins", sockbuf[socks_loop]));
      FD_SET(sockbuf[socks_loop], &ins);
    }

    /* automatically use remaining timeout time if in zero-I/O mode */
    ret = select(sock_max, &ins, NULL, NULL, (timeout > 0 ? &tt : NULL));
    if (ret == 0)
      break;

    /* loop all the open sockets to find the active one */
    for (socks_loop = 1; socks_loop <= sockbuf[0]; socks_loop++) {
      int recv_ret, write_ret;
      struct msghdr my_hdr;
      unsigned char buf[1024];
      struct iovec my_hdr_vec;
      struct sockaddr_in rem_addr;
      struct sockaddr_in local_addr;
#ifdef USE_PKTINFO
      unsigned char anc_buf[512];
#endif

      sock = sockbuf[socks_loop];

      if (!FD_ISSET(sock, &ins))
	continue;

      /* I've looked for this code for a lot of hours, and finally found the
         RFC 2292 which provides a socket API for fetching the destination
         interface of the incoming packet. */
      memset(&my_hdr, 0, sizeof(my_hdr));
      memset(&rem_addr, 0, sizeof(rem_addr));
      memset(&local_addr, 0, sizeof(local_addr));
      my_hdr.msg_name = (void *)&rem_addr;
      my_hdr.msg_namelen = sizeof(rem_addr);
      /* initialize the vector struct and then the vectory member of the header */
      my_hdr_vec.iov_base = buf;
      my_hdr_vec.iov_len = sizeof(buf);
      my_hdr.msg_iov = &my_hdr_vec;
      my_hdr.msg_iovlen = 1;
#ifdef USE_PKTINFO
      /* now the core part for the IP_PKTINFO support: the ancillary data */
      my_hdr.msg_control = anc_buf;
      my_hdr.msg_controllen = sizeof(anc_buf);
#endif

      /* now check the remote address.  If we are simulating a routing then
         use the MSG_PEEK flag, which leaves the received packet untouched */
      recv_ret = recvmsg(sock, &my_hdr, (opt_zero ? 0 : MSG_PEEK));

      debug_v(("received packet from %s:%d%s", netcat_inet_ntop(&rem_addr.sin_addr),
		ntohs(rem_addr.sin_port), (opt_zero ? "" : ", using as default dest")));

#ifdef USE_PKTINFO
      ret = udphelper_ancillary_read(&my_hdr, &local_addr);
      local_addr.sin_port = myaddr.sin_port;
      local_addr.sin_family = myaddr.sin_family;
#else
      ret = sizeof(local_addr);
      ret = getsockname(sock, (struct sockaddr *)&local_addr, &ret);
#endif

      if (ret == 0) {
	char tmpbuf[127];

	strncpy(tmpbuf, netcat_inet_ntop(&rem_addr.sin_addr), sizeof(tmpbuf));
	ncprint(NCPRINT_VERB1, _("Received packet from %s:%d -> %s:%d (local)"),
		tmpbuf, ntohs(rem_addr.sin_port),
		netcat_inet_ntop(&local_addr.sin_addr),
		ntohs(local_addr.sin_port));
      }
      else
	ncprint(NCPRINT_VERB1, _("Received packet from %s:%d"),
		netcat_inet_ntop(&rem_addr.sin_addr), ntohs(rem_addr.sin_port));

      if (opt_zero) {		/* output the packet right here right now */
	write_ret = write(STDOUT_FILENO, buf, recv_ret);
	bytes_recv += write_ret;
	debug_dv(("write_u(stdout) = %d", write_ret));

	if (write_ret < 0) {
	  perror("write_u(stdout)");
	  exit(EXIT_FAILURE);
	}

	/* FIXME: unhandled exception */
	assert(write_ret == recv_ret);

	/* if the hexdump option is set, hexdump the received data */
	if (opt_hexdump) {
#ifndef USE_OLD_HEXDUMP
	  fprintf(output_fp, "Received %d bytes from %s:%d\n", recv_ret,
		netcat_inet_ntop(&rem_addr.sin_addr), ntohs(rem_addr.sin_port));
#endif
	  netcat_fhexdump(output_fp, '<', buf, write_ret);
	}
      }
      else {
#ifdef USE_PKTINFO
	nc_sock_t dup_socket;

	memset(&dup_socket, 0, sizeof(dup_socket));
	dup_socket.domain = ncsock->domain;
	dup_socket.proto = ncsock->proto;
	memcpy(&dup_socket.local_host.iaddrs[0], &local_addr.sin_addr,
	       sizeof(local_addr));
	memcpy(&dup_socket.host.iaddrs[0], &rem_addr.sin_addr,
	       sizeof(local_addr));
	dup_socket.local_port.netnum = local_addr.sin_port;
	dup_socket.local_port.num = ntohs(local_addr.sin_port);
	dup_socket.port.netnum = rem_addr.sin_port;
	dup_socket.port.num = ntohs(rem_addr.sin_port);
	/* copy the received data in the socket's queue */
	ncsock->recvq.len = recv_ret;
	ncsock->recvq.head = ncsock->recvq.pos = malloc(recv_ret);
	memcpy(ncsock->recvq.head, my_hdr_vec.iov_base, recv_ret);
	/* FIXME: this ONLY saves the first 1024 bytes! and the others? */
#else
	ret = connect(sock, (struct sockaddr *)&rem_addr, sizeof(rem_addr));
	if (ret < 0)
	  goto err;

	/* remove this socket from the array in order not to get it closed */
	sockbuf[socks_loop] = -1;
#endif
	udphelper_sockets_close(sockbuf);

#ifdef USE_PKTINFO
	/* this is all we want from this function */
	debug_dv(("calling the udp_connect() function..."));
	return core_udp_connect(&dup_socket);
#else
	return sock;
#endif
      }
    }				/* end of foreach (sock, sockbuf) */
  }				/* end of packet receiving loop */

  /* no packets until timeout, set errno and proceed to general error handling */
  errno = ETIMEDOUT;

 err:
  udphelper_sockets_close(sockbuf);
  return -1;
}				/* end of core_udp_listen() */

/* Creates an outgoing tcp connection to the remote host.  If a local address
   or port is also specified in the socket object, it calls bind(2).
   Returns the new socket descriptor or -1 on error. */

static int core_tcp_connect(nc_sock_t *ncsock)
{
  int ret, sock, timeout = ncsock->timeout;
  struct timeval timest;
  fd_set outs;
  debug_v(("core_tcp_connect(ncsock=%p)", (void *)ncsock));

  /* since we are nonblocking now, we could start as many connections as we
     want but it's not a great idea connecting more than one host at time.
     Also don't specify the local address if it's not really needed, so we can
     avoid one bind(2) call. */
  sock = netcat_socket_new_connect(PF_INET, SOCK_STREAM,
	&ncsock->host.iaddrs[0], ncsock->port.netnum,
	(ncsock->local_host.iaddrs[0].s_addr ? &ncsock->local_host.iaddrs[0] :
	NULL), ncsock->local_port.netnum);

  if (sock < 0)
    ncprint(NCPRINT_ERROR | NCPRINT_EXIT, "Couldn't create connection (err=%d): %s",
	    sock, strerror(errno));

  /* initialize select()'s variables */
  FD_ZERO(&outs);
  FD_SET(sock, &outs);
  timest.tv_sec = timeout;
  timest.tv_usec = 0;

  ret = select(sock + 1, NULL, &outs, NULL, (timeout > 0 ? &timest : NULL));
  if (ret > 0) {
    int ret, get_ret;
    unsigned int get_len = sizeof(get_ret);	/* socklen_t */

    /* ok, select([single]), so sock must have triggered this */
    assert(FD_ISSET(sock, &outs));

    /* fetch the errors of the socket and handle system request errors */
    ret = getsockopt(sock, SOL_SOCKET, SO_ERROR, &get_ret, &get_len);
    if (ret < 0)
      ncprint(NCPRINT_ERROR | NCPRINT_EXIT, "Critical system request failed: %s",
	      strerror(errno));

    /* POSIX says that SO_ERROR expects an int, so my_len must be untouched */
    assert(get_len == sizeof(get_ret));

    /* FIXME: the error Broken Pipe should probably not stop here */
    debug_v(("Connection returned errcode=%d (%s)", get_ret, strerror(get_ret)));
    if (get_ret > 0) {
      char tmp;

      /* Ok, select() returned a write event for this socket AND getsockopt()
         said that some error happened.  This mean that EOF is expected. */
      ret = read(sock, &tmp, 1);
      assert(ret == 0);
      /* FIXME: see the TODO entry about false error detection */

      shutdown(sock, 2);
      close(sock);
      ncsock->fd = -1;
      errno = get_ret;		/* value returned by getsockopt(SO_ERROR) */
      return -1;
    }

    /* everything went fine, we have the socket */
    ncprint(NCPRINT_VERB1, _("%s open"), netcat_strid(&ncsock->host,
						      &ncsock->port));
    return sock;
  }
  else if (ret) {
    /* Terminated by a signal. Silently exit */
    if (errno == EINTR)
      exit(EXIT_FAILURE);
    /* The error seems to be a little worse */
    ncprint(NCPRINT_ERROR | NCPRINT_EXIT, "Critical system request failed: %s",
	    strerror(errno));
  }

  /* select returned 0, this means connection timed out for our timing
     directives (in fact the socket has a longer timeout usually, so we need
     to abort the connection try, set the proper errno and return */
  shutdown(sock, 2);
  close(sock);
  errno = ETIMEDOUT;
  return -1;
}				/* end of core_tcp_connect() */

/* This function loops inside the accept() loop until a *VALID* connection is
   fetched.  If an unwanted connection arrives, it is shutdown() and close()d.
   If zero I/O mode is enabled, ALL connections are refused and it stays
   unconditionally in listen mode until timeout elapses, if given, otherwise
   forever.
   Returns: The new socket descriptor for the fetched connection */

static int core_tcp_listen(nc_sock_t *ncsock)
{
  int sock_listen, sock_accept, timeout = ncsock->timeout;
  debug_v(("core_tcp_listen(ncsock=%p)", (void *)ncsock));

  sock_listen = netcat_socket_new_listen(PF_INET, &ncsock->local_host.iaddrs[0],
			ncsock->local_port.netnum);
  if (sock_listen < 0)
    ncprint(NCPRINT_ERROR | NCPRINT_EXIT,
	    _("Couldn't setup listening socket (err=%d)"), sock_listen);

  /* if the port was set to 0 this means that it is assigned randomly by the
     OS.  Find out which port they assigned to us. */
  if (ncsock->local_port.num == 0) {
    int ret;
    struct sockaddr_in myaddr;
    unsigned int myaddr_len = sizeof(myaddr);

    ret = getsockname(sock_listen, (struct sockaddr *)&myaddr, &myaddr_len);
    if (ret < 0) {
      close(sock_listen);
      return -1;
    }
    netcat_getport(&ncsock->local_port, NULL, ntohs(myaddr.sin_port));
  }

  ncprint(NCPRINT_VERB2, _("Listening on %s"),
	netcat_strid(&ncsock->local_host, &ncsock->local_port));
  while (TRUE) {
    struct sockaddr_in my_addr;
    unsigned int my_len = sizeof(my_addr);	/* this *IS* socklen_t */

    sock_accept = netcat_socket_accept(sock_listen, timeout);
    /* reset the timeout to the "use remaining time" value (see network.c file)
       if it exited with timeout we also return this function, so losing the
       original value is not a bad thing. */
    timeout = -1;

    /* failures in netcat_socket_accept() cause this function to return */
    if (sock_accept < 0)
      return -1;

    /* FIXME: i want a library function like netcat_peername() that fetches it
       and resolves with netcat_resolvehost(). */
    getpeername(sock_accept, (struct sockaddr *)&my_addr, &my_len);

    /* if a remote address (and optionally some ports) have been specified we
       assume it as the only ip and port that it is allowed to connect to
       this socket */

    if ((ncsock->host.iaddrs[0].s_addr && memcmp(&ncsock->host.iaddrs[0],
	 &my_addr.sin_addr, sizeof(ncsock->host.iaddrs[0]))) ||
	(netcat_flag_count() && !netcat_flag_get(ntohs(my_addr.sin_port)))) {
      ncprint(NCPRINT_VERB2, _("Unwanted connection from %s:%hu (refused)"),
	      netcat_inet_ntop(&my_addr.sin_addr), ntohs(my_addr.sin_port));
      goto refuse;
    }
    ncprint(NCPRINT_VERB1, _("Connection from %s:%hu"),
	    netcat_inet_ntop(&my_addr.sin_addr), ntohs(my_addr.sin_port));

    /* with zero I/O mode we don't really accept any connection */
    if (opt_zero)
      goto refuse;

    /* we have got our socket, now exit the loop */
    break;

 refuse:
    shutdown(sock_accept, 2);
    close(sock_accept);
    continue;
  }			/* end of infinite accepting loop */

  /* we don't need a listening socket anymore */
  close(sock_listen);
  return sock_accept;
}				/* end of core_tcp_listen() */

/* ... */

int core_connect(nc_sock_t *ncsock)
{
  assert(ncsock);

  if (ncsock->proto == NETCAT_PROTO_TCP)
    return ncsock->fd = core_tcp_connect(ncsock);
  else if (ncsock->proto == NETCAT_PROTO_UDP)
    return ncsock->fd = core_udp_connect(ncsock);
  else
    abort();

  return -1;
}

/* ... */

int core_listen(nc_sock_t *ncsock)
{
  assert(ncsock);

  if (ncsock->proto == NETCAT_PROTO_TCP)
    return ncsock->fd = core_tcp_listen(ncsock);
  else if (ncsock->proto == NETCAT_PROTO_UDP)
    return ncsock->fd = core_udp_listen(ncsock);
  else
    abort();

  return -1;
}

/* handle stdin/stdout/network I/O. */

int core_readwrite(nc_sock_t *nc_main, nc_sock_t *nc_slave)
{
  int fd_stdin, fd_stdout, fd_sock, fd_max;
  int read_ret, write_ret;
  unsigned char buf[1024];
  bool inloop = TRUE;
  fd_set ins, outs;
  struct timeval delayer;
  assert(nc_main && nc_slave);

  debug_v(("core_readwrite(nc_main=%p, nc_slave=%p)", (void *)nc_main,
	  (void *)nc_slave));

  /* set the actual input and output fds and find out the max fd + 1 */
  fd_sock = nc_main->fd;
  assert(fd_sock >= 0);

  /* if the domain is unspecified, it means that this is the standard I/O */
  if (nc_slave->domain == PF_UNSPEC) {
    fd_stdin = STDIN_FILENO;
    fd_stdout = STDOUT_FILENO;
  }
  else {
    fd_stdin = fd_stdout = nc_slave->fd;
    assert(fd_stdin >= 0);
  }
  fd_max = 1 + (fd_stdin > fd_sock ? fd_stdin : fd_sock);
  delayer.tv_sec = 0;
  delayer.tv_usec = 0;

  /* use the internal signal handler */
  signal_handler = FALSE;

  while (inloop) {
    bool call_select = TRUE;
    struct sockaddr_in recv_addr;	/* only used by UDP proto */
    unsigned int recv_len = sizeof(recv_addr);

    /* if we received an interrupt signal break this function */
    if (got_sigint) {
      got_sigint = FALSE;
      break;
    }
    /* if we received a terminating signal we must terminate */
    if (got_sigterm)
      break;

    /* reset the ins and outs events watch because some changes could happen */
    FD_ZERO(&ins);
    FD_ZERO(&outs);

    /* if the receiving queue is not empty it means that something bad is
       happening (for example the target sending queue is delaying the output
       and so requires some more time to free up. */
    if (nc_main->recvq.len == 0) {
      debug_v(("watching main sock for incoming data (recvq is empty)"));
      FD_SET(fd_sock, &ins);
    }
    else
      call_select = FALSE;

    /* same thing for the other socket */
    if (nc_slave->recvq.len == 0) { /* FIXME: call_select = false but could call it
	anyway and one of them could be set.. so what happens? */
      debug_v(("watching slave sock for incoming data (recvq is empty)"));
      if (use_stdin || (netcat_mode == NETCAT_TUNNEL))
        FD_SET(fd_stdin, &ins);
    }
    else
      call_select = FALSE;

    /* now the send queue. There are two cases in which the main sendq is not
       empty.  The first one is when we have a delayed output (-i), in which
       case the delayer is not null, and the socket is writable.  The second
       case is when the socket buffer is full, so the socket is not writable
       and the delayer is either null or set, depending on the opt_interval
       variable. */
    if (nc_main->sendq.len > 0) {
      if ((delayer.tv_sec == 0) && (delayer.tv_usec == 0)) {
	debug_v(("watching main sock for outgoing availability (there is pending data)"));
	FD_SET(fd_sock, &outs);
	call_select = TRUE;
      }
    }

    if (call_select || delayer.tv_sec || delayer.tv_usec) {
      int ret;
#ifndef USE_LINUX_SELECT
      struct timeval dd_saved;

      dd_saved.tv_sec = delayer.tv_sec;
      dd_saved.tv_usec = delayer.tv_usec;
      update_timeval(NULL);
#endif

      debug(("[select] entering with timeout=%d:%d ...", delayer.tv_sec, delayer.tv_usec));
      ret = select(fd_max, &ins, &outs, NULL,
		   (delayer.tv_sec || delayer.tv_usec ? &delayer : NULL));

#ifndef USE_LINUX_SELECT
      delayer.tv_sec = dd_saved.tv_sec;
      delayer.tv_usec = dd_saved.tv_usec;
      update_timeval(&delayer);
#endif

      if (ret < 0) {			/* something went wrong (maybe a legal signal) */
	if (errno == EINTR)
	  goto handle_signal;
	perror("select(core_readwrite)");
	exit(EXIT_FAILURE);
      }
      else if (ret == 0) {		/* timeout expired */
	delayer.tv_sec = 0;
	delayer.tv_usec = 0;
      }

      call_select = TRUE;
      debug(("ret=%d\n", ret));
    }

    /* reading from stdin the incoming data.  The data is currently in the
       kernel's receiving queue, and in this session we move that data to our
       own receiving queue, located in the socket object.  We can be sure that
       this queue is empty now because otherwise this fd wouldn't have been
       watched. */
    if (call_select && FD_ISSET(fd_stdin, &ins)) {
      read_ret = read(fd_stdin, buf, sizeof(buf));
      debug_dv(("read(stdin) = %d", read_ret));

      if (read_ret < 0) {
	perror("read(stdin)");
	exit(EXIT_FAILURE);
      }
      else if (read_ret == 0) {
	/* when we receive EOF and this is a tunnel say goodbye, otherwise
	   it means that stdin has finished its input. */
	if ((netcat_mode == NETCAT_TUNNEL) || opt_eofclose) {
	  debug_v(("EOF Received from stdin! (exiting from loop..)"));
	  inloop = FALSE;
	}
	else {
	  debug_v(("EOF Received from stdin! (removing from lookups..)"));
	  use_stdin = FALSE;
	}
      }
      else {
	/* we can overwrite safely since if the receive queue is busy this fd
	   is not watched at all. */
        nc_slave->recvq.len = read_ret;
        nc_slave->recvq.head = NULL;
        nc_slave->recvq.pos = buf;
      }
    }

    /* for optimization reasons we have a common buffer for both receiving
       queues, because of this, handle the data now so the buffer is available
       for the other socket events. */
    if (nc_slave->recvq.len > 0) {
      nc_buffer_t *my_recvq = &nc_slave->recvq;
      nc_buffer_t *rem_sendq = &nc_main->sendq;
      debug_v(("there are %d data bytes in slave->recvq", my_recvq->len));

      /* if the remote send queue is empty, move there the entire data block */
      if (rem_sendq->len == 0) {
	debug_v(("  moved %d data bytes from slave->recvq to main->sendq", my_recvq->len));
	memcpy(rem_sendq, my_recvq, sizeof(*rem_sendq));
	memset(my_recvq, 0, sizeof(*my_recvq));
      }
      else if (!my_recvq->head) {
	/* move the data block in a dedicated allocated space */
	debug_v(("  reallocating %d data bytes in slave->recvq", my_recvq->len));
	my_recvq->head = malloc(my_recvq->len);
	memcpy(my_recvq->head, my_recvq->pos, my_recvq->len);
	my_recvq->pos = my_recvq->head;
      }
    }

    /* now handle the nc_slave sendq because of the same reason as above. There
       could be a common buffer that moves around the queues, so if this is the case
       handle it so that it can be reused. If we must delay it some more, copy it
       in a dynamically allocated space. */
    if (nc_main->sendq.len > 0) {
      unsigned char *data = nc_main->sendq.pos;
      int data_len = nc_main->sendq.len;
      nc_buffer_t *my_sendq = &nc_main->sendq;

      debug_v(("there are %d data bytes in main->sendq", my_sendq->len));

      /* we have a delayed output, but at this point we might have the
         send queue pointing to a stack buffer.  In this case, allocate a
         new buffer and copy the data there for the buffered output. */
      if (opt_interval) {
	int i = 0;

	if (delayer.tv_sec || delayer.tv_usec)
	  goto skip_sect;		/* the delay is not yet over! */

	/* find the newline character.  We are going to output the first line
	   immediately while we allocate and safe the rest of the data for a
	   later output. */
	while (i < data_len)
	  if (data[i++] == '\n')
	    break;

	data_len = i;
	delayer.tv_sec = opt_interval;
      }

      write_ret = write(fd_sock, data, data_len);
      if (write_ret < 0) {
	if (errno == EAGAIN)
	  write_ret = 0;	/* write would block, append it to select */
	else {
	  perror("write(net)");
	  exit(EXIT_FAILURE);
	}
      }

      /* FIXME: fix the below unhandled exception, and find a way to delay the
       * tries to call write(2) in case of EAGAIN, i think 100ms would be fine
       * for most systems. A too high value would not use all the bandwidth on
       * bigger installations, while a too small value would eat cpu with
       * kernel overhead. */

      bytes_sent += write_ret;		/* update statistics */
      debug_dv(("write(net) = %d (buf=%p)", write_ret, (void *)data));

      if (write_ret < data_len) {
	debug_v(("Damn! I wanted to send to sock %d bytes but it only sent %d",
		data_len, write_ret));
	data_len = write_ret;
      }

      /* if the option is set, hexdump the sent data */
      if (opt_hexdump) {
#ifndef USE_OLD_HEXDUMP
	fprintf(output_fp, "Sent %u bytes to the socket\n", write_ret);
#endif
	netcat_fhexdump(output_fp, '>', data, data_len);
      }

      /* update the queue */
      my_sendq->len -= data_len;
      my_sendq->pos += data_len;

 skip_sect:
      debug_v(("there are %d data bytes left in the queue", my_sendq->len));
      if (my_sendq->len == 0) {
	free(my_sendq->head);
	memset(my_sendq, 0, sizeof(*my_sendq));
      }
      else if (!my_sendq->head) {
	my_sendq->head = malloc(my_sendq->len);
	memcpy(my_sendq->head, my_sendq->pos, my_sendq->len);
	my_sendq->pos = my_sendq->head;
      }

    }				/* end of reading from stdin section */

    /* reading from the socket (net). */
    if (call_select && FD_ISSET(fd_sock, &ins)) {
      if ((nc_main->proto == NETCAT_PROTO_UDP) && opt_zero) {
	memset(&recv_addr, 0, sizeof(recv_addr));
	/* this allows us to fetch packets from different addresses */
	read_ret = recvfrom(fd_sock, buf, sizeof(buf), 0,
			    (struct sockaddr *)&recv_addr, &recv_len);
	/* when recvfrom() call fails, recv_addr remains untouched */
	debug_dv(("recvfrom(net) = %d (address=%s:%d)", read_ret,
		netcat_inet_ntop(&recv_addr.sin_addr), ntohs(recv_addr.sin_port)));
      }
      else {
	/* common file read fallback */
	read_ret = read(fd_sock, buf, sizeof(buf));
	debug_dv(("read(net) = %d", read_ret));
      }

      if (read_ret < 0) {
	perror("read(net)");
	exit(EXIT_FAILURE);
      }
      else if (read_ret == 0) {
	debug_v(("EOF Received from the net"));
	inloop = FALSE;
      }
      else {
	nc_main->recvq.len = read_ret;
	nc_main->recvq.head = NULL;
	nc_main->recvq.pos = buf;
      }
    }

    /* handle net receiving queue */
    if (nc_main->recvq.len > 0) {
      nc_buffer_t *my_recvq = &nc_main->recvq;
      nc_buffer_t *rem_sendq = &nc_slave->sendq;

      /* check for telnet codes (if enabled).  Note that the buffered output
         interval does NOT apply to telnet code answers */
      if (opt_telnet)
	netcat_telnet_parse(nc_main);

      /* the telnet parsing could have returned 0 chars! */
      if (my_recvq->len > 0) {
	/* if the remote send queue is empty, move there the entire data block */
	if (rem_sendq->len == 0) {
	  memcpy(rem_sendq, my_recvq, sizeof(*rem_sendq));
	  memset(my_recvq, 0, sizeof(*my_recvq));
	}
	else if (!my_recvq->head) {
	  /* move the data block in a dedicated allocated space */
	  my_recvq->head = malloc(my_recvq->len);
	  memcpy(my_recvq->head, my_recvq->pos, my_recvq->len);
	  my_recvq->pos = my_recvq->head;
	}
      }
    }

    if (nc_slave->sendq.len > 0) {
      unsigned char *data = nc_slave->sendq.pos;
      int data_len = nc_slave->sendq.len;
      nc_buffer_t *my_sendq = &nc_slave->sendq;

      write_ret = write(fd_stdout, data, data_len);
      bytes_recv += write_ret;		/* update statistics */
      debug_dv(("write(stdout) = %d", write_ret));

      if (write_ret < 0) {
	perror("write(stdout)");
	exit(EXIT_FAILURE);
      }

      /* FIXME: unhandled exception */
      assert((write_ret > 0) && (write_ret <= data_len));

      if (write_ret < data_len) {
	debug_v(("Damn! I wanted to send to stdout %d bytes but it only sent %d",
		data_len, write_ret));
	data_len = write_ret;
      }

      /* if option is set, hexdump the received data */
      if (opt_hexdump) {
#ifndef USE_OLD_HEXDUMP
	if ((nc_main->proto == NETCAT_PROTO_UDP) && opt_zero)
	  fprintf(output_fp, "Received %d bytes from %s:%d\n", write_ret,
		  netcat_inet_ntop(&recv_addr.sin_addr), ntohs(recv_addr.sin_port));
	else
	  fprintf(output_fp, "Received %d bytes from the socket\n", write_ret);
#endif
	netcat_fhexdump(output_fp, '<', data, write_ret);
      }

      /* update the queue */
      my_sendq->len -= data_len;
      my_sendq->pos += data_len;

      debug_v(("there are %d data bytes left in the queue", my_sendq->len));
      if (my_sendq->len == 0) {
	free(my_sendq->head);
	memset(my_sendq, 0, sizeof(*my_sendq));
      }
      else if (!my_sendq->head) {
	my_sendq->head = malloc(my_sendq->len);
	memcpy(my_sendq->head, my_sendq->pos, my_sendq->len);
	my_sendq->pos = my_sendq->head;
      }
    }				/* end of reading from the socket section */

 handle_signal:			/* FIXME: i'm not sure this is the right place */
    if (got_sigusr1) {
      debug_v(("LOCAL printstats!"));
      netcat_printstats(TRUE);
      got_sigusr1 = FALSE;
    }
    continue;
  }				/* end of while (inloop) */

  /* we've got an EOF from the net, close the sockets */
  shutdown(fd_sock, SHUT_RDWR);
  close(fd_sock);
  nc_main->fd = -1;

  /* close the slave socket only if it wasn't a simulation */
  if (nc_slave->domain != PF_UNSPEC) {
    shutdown(fd_stdin, SHUT_RDWR);
    close(fd_stdin);
    nc_slave->fd = -1;
  }

  /* restore the extarnal signal handler */
  signal_handler = TRUE;

  return 0;
}				/* end of core_readwrite() */
