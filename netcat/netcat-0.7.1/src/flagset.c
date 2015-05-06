/*
 * flagset.c -- very big flags array handler
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <giovanni@giacobbi.net>
 * Copyright (C) 2002  Giovanni Giacobbi
 *
 * $Id: flagset.c,v 1.7 2003/12/10 16:18:07 themnemonic Exp $
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

static char *flagset = NULL;
static size_t flagset_len = 0;

/* Initializes the flagset to the given len. */

bool netcat_flag_init(unsigned int len)
{
  /* safe double-init */
  if (flagset)
    return TRUE;

  /* calculates the block len needed */
  len++;		/* the first bit is reserved (FIXME?) */
  flagset_len = (size_t) (len / 8) + (len % 8 ? 1 : 0);
  if (flagset_len == 0) {
    free(flagset);
    flagset = NULL;
    return TRUE;
  }

  /* since we may be asking a big amount of memory, this call could fail */
  flagset = malloc(flagset_len);
  if (!flagset)
    return FALSE;

  memset(flagset, 0, flagset_len);
  return TRUE;
}

/* Sets the specified flag `port' to the specified boolean value `flag'. */

void netcat_flag_set(unsigned short port, bool flag)
{
  register char *p = flagset + (int) (port / 8);
  register int offset = port % 8;

  assert(flagset);
  assert(port < (flagset_len * 8));
  if (flag)
    *p |= 1 << offset;
  else
    *p &= ~(1 << offset);
}

/* Returns the boolean value of the specified flag `port' */

bool netcat_flag_get(unsigned short port)
{
  register char *p = flagset + (int) (port / 8);

  assert(flagset);
  assert(port < (flagset_len * 8));
  if (*p & (1 << (port % 8)))
    return TRUE;
  else
    return FALSE;
}

/* Finds the next bit set after the specified position.
   Returns the position of the next bit if any, otherwise it returns 0 */

unsigned short netcat_flag_next(unsigned short port)
{
  register int offset, pos = (int) (++port / 8);

  assert(flagset);
  assert(port < (flagset_len * 8));
  if (port == 0)			/* just invalid data */
    return 0;

  /* the given port could be inside one byte, so we first need to check each
     single bit after this one in order to complete the byte.  After that, we
     can start with the fast byte check. */
  while ((offset = port % 8)) {
    if (flagset[pos] & (1 << offset))
      return port;
    if (port == 65535)
      return 0;
    port++;
  }

  pos = (int) (port / 8);		/* update the byte position */

  /* fast checking. leaves the port variable set to the the beginning of the
     next block containing at least one bit set, OR to the beginning of the
     LAST block. */
  while ((flagset[pos] == 0) && (port < 65528)) {	/* FIXME */
    pos++;
    port += 8;
  }

  /* parse this last byte carefully, but we are NOT sure that there is at
     least one bit set */
  offset = 0;
  do {
    if ((flagset[pos] & (1 << offset++)))
      return port;
  } while (port++ < 65535);			/* FIXME */

  return 0;
}

/* Returns the number of flags that are set to TRUE in the full flagset */

int netcat_flag_count(void)
{
  register char c;
  register int i;
  int ret = 0;

  assert(flagset);
  /* scan the flagset for set bits, if found, it counts them */
  for (i = 0; i < flagset_len; i++) {
    c = flagset[i];		/* if c is 0, all these 8 bits are FALSE */
    while (c) {
      /* FIXME Ok, here it comes the big trouble. We are in the following
	 situation:
		ret = 0
		c   = 1234 5678

	We will loop and shift bits away until the number `c' becomes 0 (and
	it will of course become 0, soon or late).

	Assumed that the bit number 1 is the sign, and that we will shift the
	bit 1 (or the bit that takes its place later) until the the most right,
	WHY it has to keep the wrong sign? */
      ret -= (c >> 7);
      c <<= 1;
    }
  }

  return ret;
}

/* Returns the position of a random flag set to TRUE.  The returned flag is
   then reset, so you can call netcat_flag_rand() repeatedly to get all the
   flags set in a random order.  If there are no other flags set the function
   returns 0. */

unsigned short netcat_flag_rand(void)
{
  int rand, randmax = netcat_flag_count() - 1;
  unsigned short ret = 0;

  assert(flagset);

  /* if there are no other flags set */
  if (randmax < 0)
    return 0;

#ifdef USE_RANDOM
  /* fetch a random number from the high-order bits */
  rand = 1 + (int) ((float)randmax * RAND() / (RAND_MAX + 1.0));
#else
# ifdef __GNUC__
#  warning "random routines not found, removed random support"
# endif
  rand = 1;				/* simulates a random number */
#endif

  /* loop until we find the specified flag */
  while (rand--)
    ret = netcat_flag_next(ret);

  /* don't return this same flag again */
  netcat_flag_set(ret, FALSE);
  return ret;
}
