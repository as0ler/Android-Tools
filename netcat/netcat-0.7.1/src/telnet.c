/*
 * telnet.c -- a small implementation of the telnet protocol routines
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <giovanni@giacobbi.net>
 * Copyright (C) 2002 - 2003  Giovanni Giacobbi
 *
 * $Id: telnet.c,v 1.11 2003/02/28 21:49:29 themnemonic Exp $
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

/* RFC0854 DEFINES */
#define TELNET_SE	240	/* End of subnegotiation parameters. */
#define TELNET_NOP	241	/* No operation. */
#define TELNET_DM	242	/* (Data Mark) The data stream portion of a
				 * Synch. This should always be accompanied
				 * by a TCP Urgent notification. */
#define TELNET_BRK	243	/* (Break) NVT character BRK. */
#define TELNET_IP	244	/* (Interrupt Process) The function IP. */
#define TELNET_AO	245	/* (Abort output) The function AO. */
#define TELNET_AYT	246	/* (Are You There) The function AYT. */
#define TELNET_EC	247	/* (Erase character) The function EC. */
#define TELNET_EL	248	/* (Erase Line) The function EL. */
#define TELNET_GA	249	/* (Go ahead) The GA signal. */
#define TELNET_SB	250	/* Indicates that what follows is
				 * subnegotiation of the indicated option. */
#define TELNET_WILL	251	/* Indicates the desire to begin performing,
				 * or confirmation that you are now performing,
				 * the indicated option. */
#define TELNET_WONT	252	/* Indicates the refusal to perform, or to
				 * continue performing, the indicated option. */
#define TELNET_DO	253	/* Indicates the request that the other party
				 * perform, or confirmation that you are
				 * expecting the other party to perform, the
				 * indicated option. */
#define TELNET_DONT	254	/* Indicates the demand that the other party
				 * stop performing, or confirmation that you
				 * are no longer expecting the other party
				 * to perform, the indicated option. */
#define TELNET_IAC	255	/* Data Byte 255. */

/* Handle the RFC0854 telnet codes found in the receiving buffer of the
   specified socket object.  This is a reliable implementation of the rfc,
   which understands most of the described codes, and automatically replies to
   the remote end with the appropriate answer codes.
   The receiving queue is then rewritten with the telnet codes stripped off,
   and the size is updated to the new length which is less than or equal to
   the original one (and can also be 0).
   The case where a telnet code is broken down (i.e. if the buffering block
   cuts it into two different calls to netcat_telnet_parse() is also handled
   properly with an internal buffer.
   If you'll ever need to reset the internal buffer for a fresh call of the
   telnet parsing function just call it with a NULL argument. */

void netcat_telnet_parse(nc_sock_t *ncsock)
{
  static unsigned char getrq[4];
  static int l = 0;
  unsigned char putrq[4], *buf = ncsock->recvq.pos;
  int i, *size = &ncsock->recvq.len, eat_chars = 0, ref_size = *size;
  debug_v(("netcat_telnet_parse(ncsock=%p)", (void *)ncsock));

  /* if the socket object is NULL, assume a reset command */
  if (ncsock == NULL) {
    l = 0;
    return;
  }

  /* loop all chars of the string */
  for (i = 0; i < ref_size; i++) {
    /* if we found IAC char OR we are fetching a IAC code string process it */
    if ((buf[i] != TELNET_IAC) && (l == 0))
      continue;

#ifndef USE_OLD_TELNET
    /* this is surely a char that will be eaten */
    eat_chars++;
#endif

    /* copy the char in the IAC-code-building buffer */
    getrq[l++] = buf[i];

    /* if this is the first char (IAC!) go straight to the next one */
    if (l == 1)
      continue;

    /* identify the IAC code. The effect is resolved here. If the char needs
       further data the subsection just needs to leave the index 'l' set. */
    switch (getrq[1]) {
    case TELNET_SE:
    case TELNET_NOP:
      goto do_eat_chars;
    case TELNET_DM:
    case TELNET_BRK:
    case TELNET_IP:
    case TELNET_AO:
    case TELNET_AYT:
    case TELNET_EC:
    case TELNET_EL:
    case TELNET_GA:
    case TELNET_SB:
      goto do_eat_chars;
    case TELNET_WILL:
    case TELNET_WONT:
      if (l < 3) /* need more data */
        continue;

      /* refuse this option */
      putrq[0] = 0xFF;
      putrq[1] = TELNET_DONT;
      putrq[2] = getrq[2];
      /* FIXME: the rfc seems not clean about what to do if the sending queue
         is not empty.  Since it's the simplest solution, just override the
         queue for now, but this must change in future. */
      write(ncsock->fd, putrq, 3);		/* FIXME: handle failures */
      goto do_eat_chars;
    case TELNET_DO:
    case TELNET_DONT:
      if (l < 3) /* need more data */
        continue;

      /* refuse this option */
      putrq[0] = 0xFF;
      putrq[1] = TELNET_WONT;
      putrq[2] = getrq[2];
      write(ncsock->fd, putrq, 3);
      goto do_eat_chars;
    case TELNET_IAC:
#ifndef USE_OLD_TELNET
      /* insert a byte 255 in the buffer.  Note that we don't know in which
         position we are, but there must be at least 1 eaten char where we
         can park our data byte.  This effect is senseless if using the old
         telnet codes parsing policy. */
      buf[i - --eat_chars] = 0xFF;
#endif
      goto do_eat_chars;
    default:
      /* FIXME: how to handle the unknown code? */
      break;
    }
    continue;

 do_eat_chars:
    /* ... */
    l = 0;

#ifndef USE_OLD_TELNET
    if (eat_chars > 0) {
      unsigned char *from, *to;

      debug(("(telnet) ate %d chars\n", eat_chars));

      /* move the index to the overlapper character */
      i++;

      /* if this is the end of the string, memmove() does not care of a null
         size, it simply does nothing. */
      from = &buf[i];
      to = &buf[i - eat_chars];
      memmove(to, from, ref_size - i);

      /* fix the index.  since the loop will auto-increment the index we need
         to put it one char before.  this means that it can become negative
         but it isn't a big problem since it is signed. */
      i -= eat_chars + 1;
      ref_size -= eat_chars;
      eat_chars = 0;
    }
#endif
  }

  /* we are at the end of the buffer. all we have to do now is updating the
     authoritative buffer size.  In case that there is a broken-down telnet
     code, the do_eat_chars section is not executed, thus there may be some
     pending chars that needs to be removed.  This is handled here in an easy
     way: since they are at the end of the buffer, just cut them playing with
     the buffer length. */

#ifdef USE_OLD_TELNET
  assert(eat_chars == 0);
#endif

  *size = ref_size - eat_chars;
}
