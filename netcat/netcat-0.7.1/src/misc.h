/*
 * misc.h -- ncprint constants and debugging functions definition
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <giovanni@giacobbi.net>
 * Copyright (C) 2002 - 2003  Giovanni Giacobbi
 *
 * $Id: misc.h,v 1.8 2003/03/06 00:20:07 themnemonic Exp $
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

/* time to wait (in microseconds) when DELAY is requested (debug mode) */
#define NCPRINT_WAITTIME 500000

/* NCPRINT flags */
#define NCPRINT_STDOUT		0x0001	/* force output to stdout */
#define NCPRINT_NONEWLINE	0x0002	/* don't print a newline at the end */
#define NCPRINT_DELAY		0x0004	/* delay WAITTIME before returning */
#define NCPRINT_EXIT		0x0008	/* exit() after printing the string */
#define NCPRINT_VERB1		0x0010	/* require verbosity level 1 */
#define NCPRINT_VERB2		0x0020	/* require verbosity level 2 */
#define NCPRINT_NOFMT		0x0040	/* do not interpret format strings */

/* NCPRINT commands */
/* normal message printed to stderr by default */
#define NCPRINT_NORMAL		0x0000

/* debug message.  This type of message is only printed if `opt_debug' is true */
#define NCPRINT_DEBUG		0x1000

/* special debug message.  Prepends "(debug)" before the actual string */
#define NCPRINT_DEBUG_V		0x1100

/* prepends "Error:" and flags the message as ERROR */
#define NCPRINT_ERROR		0x1200

/* prepends "Warning:" and flags the message as WARNING */
#define NCPRINT_WARNING		0x1300

/* prepends "Notice:" and flags the message as NOTICE */
#define NCPRINT_NOTICE		0x1400

/* Debugging output routines */
#ifdef DEBUG
# define debug(fmtstring) \
  ncprint(NCPRINT_NOFMT | NCPRINT_NONEWLINE | NCPRINT_DEBUG, debug_fmt fmtstring)
# define debug_d(fmtstring) \
  ncprint(NCPRINT_NOFMT | NCPRINT_NONEWLINE | NCPRINT_DEBUG | NCPRINT_DELAY, debug_fmt fmtstring)
# define debug_v(fmtstring) \
  ncprint(NCPRINT_NOFMT | NCPRINT_DEBUG_V, debug_fmt fmtstring)
# define debug_dv(fmtstring) \
  ncprint(NCPRINT_NOFMT | NCPRINT_DEBUG_V | NCPRINT_DELAY, debug_fmt fmtstring)
#else
# define debug(fmtstring)
# define debug_d(fmtstring)
# define debug_v(fmtstring)
# define debug_dv(fmtstring)
#endif
