/*
 * udphelper.c -- advanced udp routines for portability
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <giovanni@giacobbi.net>
 * Copyright (C) 2002 - 2003  Giovanni Giacobbi
 *
 * $Id: udphelper.c,v 1.10 2003/02/28 21:47:23 themnemonic Exp $
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

#ifndef USE_PKTINFO
#include <sys/ioctl.h>
#include <net/if.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

/* Support Solaris extended GIFCONF */
#ifndef SIOCGLIFCONF
# define SIOCGLIFCONF SIOCGIFCONF
# define lifc_len ifc_len
# define lifc_buf ifc_buf
# define lifc_req ifc_req
# define lifconf ifconf
#endif

#if !defined(SIOCGLIFADDR) || !defined(SIOCGLIFFLAGS)
/* FIXME The following warning occurs on FreeBSD:
    udphelper.c:48: warning: `SIOCGLIFADDR' redefined
    /usr/include/sys/sockio.h:78: warning: this is the location of the previous definition
 */
# define SIOCGLIFADDR SIOCGIFADDR
# define SIOCGLIFFLAGS SIOCGIFFLAGS
# define SIOCGLIFDSTADDR SIOCGIFDSTADDR
# define SIOCGLIFNETMASK SIOCGIFNETMASK
# define lifr_addr ifr_addr
# define lifr_name ifr_name
# define lifr_dstaddr ifr_dstaddr
# define lifr_flags ifr_flags
# define ss_family sa_family
# define lifreq ifreq
#endif
#endif	/* !USE_PKTINFO */

#ifdef USE_PKTINFO

/* Reads the ancillary data buffer for the given msghdr and extracts the packet
   destination address which is copied to the `get_addr' struct.
   Returns 0 on success, a negative value otherwise. */

int udphelper_ancillary_read(struct msghdr *my_hdr,
			     struct sockaddr_in *get_addr)
{
  /* let's hope that there is some ancillary data! */
  if (my_hdr->msg_controllen > 0) {
    struct cmsghdr *get_cmsg;

    /* We don't know which is the order of the ancillary messages and we don't
       know how many are there.  So I simply parse all of them until we find
       the right one, checking the index type. */
    for (get_cmsg = CMSG_FIRSTHDR(my_hdr); get_cmsg;
	 get_cmsg = CMSG_NXTHDR(my_hdr, get_cmsg)) {
      debug_v(("Analizing ancillary header (id=%d)", get_cmsg->cmsg_type));

      if (get_cmsg->cmsg_type == IP_PKTINFO) {
	struct in_pktinfo *get_pktinfo;

	/* fetch the data and run away, we don't need to parse everything */
	get_pktinfo = (struct in_pktinfo *) CMSG_DATA(get_cmsg);
	memcpy(&get_addr->sin_addr, &get_pktinfo->ipi_spec_dst,
	       sizeof(get_addr->sin_addr));
	return 0;
      }
    }
  }

  return -1;
}

#else	/* USE_PKTINFO */

/* This function opens an array of sockets (stored in `sockbuf'), one for each
   different interface in the current machine.  The purpose of this is to allow
   the application to determine which interface received the packet that
   otherwise would be unknown.
   Returns -1 if an error occurred; otherwise the return value is a file
   descriptor referencing the socket in the array with the highest number.
   On success, at least one socket is returned. */

int udphelper_sockets_open(int **sockbuf, in_port_t nport)
{
  int ret, i, alloc_size, dummy_sock, if_total = 1;
  int *my_sockbuf = NULL, my_sockbuf_max = 0, sock_total = 0;
  unsigned int if_pos = 0;
  struct lifconf nc_ifconf;
  struct lifreq *nc_ifreq = NULL;

  /* initialize the sockbuf (assuming the function will be positive */
  my_sockbuf = malloc(sizeof(int));
  if (!my_sockbuf) {
    errno = ENOMEM;
    return -1;
  }

  /* this is a dummy socket needed for the ioctl(2) call (this just tells the
     kernel where to look for the needed API */
  dummy_sock = socket(PF_INET, SOCK_DGRAM, 0);
  if (dummy_sock < 0)
    goto err;

  /* find out the interfaces configuration, allocating more memory if
     necessary. */
  do { /* FIXME: set max buffer size (what is max IF num?) */
    /* since we don't need at this stage to find out the exact number of
       interfaces, use bigger step in order not to do too many ioctl()s on
       systems with many interfaces. */
    if_total += 5;
    alloc_size = if_total * sizeof(*nc_ifreq);

    /* like many other syscalls, ioctl() will adjust lifc_len to the REAL
       lifc_len, so try to allocate a larger buffer in order to determine
       the total interfaces number. */
    free(nc_ifreq);	/* don't use realloc here, this way it is faster */
    nc_ifreq = malloc(alloc_size);
    nc_ifconf.lifc_len = alloc_size;
    nc_ifconf.lifc_req = nc_ifreq;
    /* wait for updating nc_ifconf.lifc_req before eventually jumping to the
       error handling or it would cause a double free() to the same pointer */
    if (!nc_ifreq) {
      errno = ENOMEM;
      goto err;
    }

    /* FIXME: nc_ifconf has two other members (lifc_family and lifc_flags) on
       some OS (read: SunOS). They should perhaps be initialized too. */
    ret = ioctl(dummy_sock, SIOCGLIFCONF, (char *)&nc_ifconf);
    if (ret < 0)
      goto err;
  } while (nc_ifconf.lifc_len >= alloc_size);

  /* Now loop */
  if_total = 0;
  while (if_pos < nc_ifconf.lifc_len) {
    int newsock;
    struct sockaddr_in if_addr;

    nc_ifreq = (struct lifreq *)((char *)nc_ifconf.lifc_req + if_pos);

    /* calculate the starting offset of the next nc_ifreq */
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
    if (nc_ifreq->lifr_addr.sa_len > sizeof(struct sockaddr))
      if_pos += sizeof(nc_ifreq->lifr_name) + nc_ifreq->lifr_addr.sa_len;
    else
      if_pos += sizeof(*nc_ifreq);
#else
    if_pos += sizeof(*nc_ifreq);
#endif

    /* truncated? */
    assert(if_pos <= nc_ifconf.lifc_len);

    /* interfaces counter (not really needed, but useful */
    if_total++;

    /* discard any interface not devoted to IP */
    if (nc_ifreq->lifr_addr.ss_family != AF_INET)
      continue;

    /* save the sockaddr_in struct before successive ioctl() calls */
    memcpy(&if_addr, &nc_ifreq->lifr_addr, sizeof(if_addr));

    /* we need to sort out interesting interfaces, so fetch the interface
       flags */
    ret = ioctl(dummy_sock, SIOCGLIFFLAGS, (char *)nc_ifreq);
    if (ret < 0)
      goto err;

    /* check that this interface is up and running */
    if (!(nc_ifreq->lifr_flags & IFF_UP))
      continue;

    debug(("(udphelper) Found interface %s (IP address: %s)\n",
	  nc_ifreq->lifr_name, netcat_inet_ntop(&if_addr.sin_addr)));

    newsock = socket(PF_INET, SOCK_DGRAM, 0);
    if (newsock < 0)
      goto err;

    /* update immediately the sockets buffer so that any following error would
       close this one in the cleanup. */
    my_sockbuf = realloc(my_sockbuf, (++sock_total + 1) * sizeof(int));
    if (!my_sockbuf) {
      errno = ENOMEM;
      goto err;
    }
    my_sockbuf[sock_total] = newsock;
    if (newsock > my_sockbuf_max)
      my_sockbuf_max = newsock;

    /* bind this address to his address and to the common port */
    if_addr.sin_port = nport;
    ret = bind(newsock, (struct sockaddr *)&if_addr, sizeof(if_addr));
    if (ret < 0)
      goto err;

    /* if the nport was set to 0 it means that it is randomly assigned by the
       kernel, but we don't want a different port for each interface, so stick
       to this one. */
    if (nport == 0) {
      int sa_tmp_len = sizeof(if_addr);

      /* we don't need anymore if_addr, so we may corrupt it safely */
      ret = getsockname(newsock, (struct sockaddr *)&if_addr, &sa_tmp_len);
      if (ret < 0)
        goto err;

      nport = if_addr.sin_port;
      assert(nport != 0);
    }
  }				/* end of while (all_interfaces) */

  /* ok we don't need anymore the interfaces list and the dummy socket */
  free(nc_ifconf.lifc_req);
  nc_ifconf.lifc_req = NULL;
  close(dummy_sock);
  dummy_sock = -1;

  /* save the total sock value in the first member of the sockbuf array */
  my_sockbuf[0] = sock_total;
  *sockbuf = my_sockbuf;

  debug(("(udphelper) Successfully created %d socket(s)\n", sock_total));

  /* On success, return the first socket for the application use, while if no
     valid interefaces were found step forward to the error handling */
  if (my_sockbuf[0] > 0)
    return my_sockbuf_max;

  errno = EAFNOSUPPORT;
  my_sockbuf[0] = -1;

 err:
  /* destroy the ifconf struct and buffers */
  free(nc_ifconf.lifc_req);

  /* save the errno value */
  ret = errno;

  if (dummy_sock >= 0)
    close(dummy_sock);

  /* close all the sockets and free the sockets buffer */
  for (i = 1; my_sockbuf && (i <= sock_total); i++)
    close(my_sockbuf[i]);
  free(my_sockbuf);
  *sockbuf = NULL;

  /* restore the errno value for parent function handling */
  errno = ret;

  return -1;
}

#endif	/* USE_PKTINFO */

/* Closes the `sockbuf' previously allocated with udphelper_sockets_open().
   The global errno is not altered by this function. */

void udphelper_sockets_close(int *sockbuf)
{
  int i, saved_errno = errno;

  if (!sockbuf)
    return;

  for (i = 1; i <= sockbuf[0]; i++)
    if (sockbuf[i] >= 0)
      close(sockbuf[i]);

  free(sockbuf);
  errno = saved_errno;
}
