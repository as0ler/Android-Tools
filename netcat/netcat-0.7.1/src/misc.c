/*
 * misc.c -- contains generic purposes routines
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <giovanni@giacobbi.net>
 * Copyright (C) 2002 - 2004  Giovanni Giacobbi
 *
 * $Id: misc.c,v 1.37 2004/01/03 16:42:07 themnemonic Exp $
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

/* Hexdump `datalen' bytes starting at `data' to the file pointed to by `stream'.
   If the given block generates a partial line it's rounded up with blank spaces.
   This function was written by Giovanni Giacobbi for The GNU Netcat project,
   credits must be given for any use of this code outside this project */

int netcat_fhexdump(FILE *stream, char c, const void *data, size_t datalen)
{
  size_t pos;
  char buf[80], *ascii_dump, *p = NULL;
  int flag = 0;

#ifndef USE_OLD_HEXDUMP
  buf[78] = 0;
  ascii_dump = &buf[62];
#else
  buf[77] = 0;
  ascii_dump = &buf[61];
#endif

  for (pos = 0; pos < datalen; pos++) {
    unsigned char x;

    /* save the offset */
    if ((flag = pos % 16) == 0) {
      /* we are at the beginning of the line, reset output buffer */
      p = buf;
#ifndef USE_OLD_HEXDUMP
      p += sprintf(p, "%08X  ", (unsigned int) pos);
#else
      p += sprintf(p, "%c %08X ", c, (unsigned int) pos);
#endif
    }

    x = *((unsigned char *)((unsigned char *)data + pos));
#ifndef USE_OLD_HEXDUMP
    p += sprintf(p, "%02hhX ", x);
#else
    p += sprintf(p, "%02hhx ", x);
#endif

    if ((x < 32) || (x > 126))
      ascii_dump[flag] = '.';
    else
      ascii_dump[flag] = x;

#ifndef USE_OLD_HEXDUMP
    if ((pos + 1) % 4 == 0)
      *p++ = ' ';
#endif

    /* if the offset is 15 then we go for the newline */
    if (flag == 15) {
#ifdef USE_OLD_HEXDUMP
      *p++ = '#';
      *p++ = ' ';
#endif
      fprintf(stream, "%s\n", buf);
    }
  }

  /* if last line was incomplete (len % 16) != 0, complete it */
  for (pos = datalen; (flag = pos % 16); pos++) {
    ascii_dump[flag] = ' ';
    strcpy(p, "   ");
    p += 3;

#ifndef USE_OLD_HEXDUMP
    if (((pos + 1) % 4) == 0)
      *p++ = ' ';
#endif

    if (flag == 15) {
#ifdef USE_OLD_HEXDUMP
      *p++ = '#';
      *p++ = ' ';
#endif
      fprintf(stream, "%s\n", buf);
    }
  }

  fflush(stream);
  return 0;
}

/* Fills the buffer pointed to by `str' with the formatted value of `number' */

int netcat_snprintnum(char *str, size_t size, unsigned long number)
{
  char *p = "\0kMGT";

  while ((number > 9999) && (*p != 'T')) {
    number = (number + 500) / 1000;
    p++;
  }
  return snprintf(str, size, "%lu%c", number, *p);
}

/* This is an advanced function for printing normal and error messages for the
   user.  It supports various types and flags which are declared in misc.h. */

void ncprint(int type, const char *fmt, ...)
{
  int flags = type & 0xFF;
  char buf[512], newline = '\n';
  FILE *fstream = stderr;		/* output stream */
  va_list args;

  /* clear the flags section so we obtain the pure command */
  type &= ~0xFF;

  /* return if this requires some verbosity levels and we haven't got it */
  if (!opt_debug) {
    if ((flags & NCPRINT_VERB2) && (opt_verbose < 2))
      goto end;

    if ((flags & NCPRINT_VERB1) && (opt_verbose < 1))
      goto end;
  }

  /* known flags */
  if (flags & NCPRINT_STDOUT)
    fstream = stdout;
  if (flags & NCPRINT_NONEWLINE)
    newline = 0;

  /* from now on, it's very probable that we will need the string formatted,
     so unless we have the NOFMT flag, resolve it */
  if (!(flags & NCPRINT_NOFMT)) {
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
  }
  else {
    strncpy(buf, fmt, sizeof(buf));
    buf[sizeof(buf) - 1] = 0;
  }

  switch (type) {
  case NCPRINT_NORMAL:
    fprintf(fstream, "%s%c", buf, newline);
    break;
#ifdef DEBUG
  case NCPRINT_DEBUG:
    if (opt_debug)
      fprintf(fstream, "%s%c", buf, newline);
    else
      return;		/* other flags has no effect with this flag */
    break;
  case NCPRINT_DEBUG_V:
    if (opt_debug)
      fprintf(fstream, "(debug) %s%c", buf, newline);
    else
      return;		/* other flags has no effect with this flag */
    break;
#endif
  case NCPRINT_ERROR:
    fprintf(fstream, "%s %s%c", _("Error:"), buf, newline);
    break;
  case NCPRINT_WARNING:
    fprintf(fstream, "%s %s%c", _("Warning:"), buf, newline);
    break;
  case NCPRINT_NOTICE:
    fprintf(fstream, "%s %s%c", _("Notice:"), buf, newline);
    break;
  }
  /* discard unknown types */

  /* post-output effects flags */
  if (flags & NCPRINT_DELAY)
    usleep(NCPRINT_WAITTIME);

 end:
  /* now resolve the EXIT flag. If this was a verbosity message but we don't
     have the required level, exit anyway. */
  if (flags & NCPRINT_EXIT)
    exit(EXIT_FAILURE);
}

/* prints statistics to stderr with the right verbosity level.  If `force' is
   TRUE, then the verbosity level is overridden and the statistics are printed
   anyway. */

void netcat_printstats(bool force)
{
  char *p, str_recv[64], str_sent[64];

  /* fill in the buffers but preserve the space for adding the label */
  netcat_snprintnum(str_recv, 32, bytes_recv);
  assert(str_recv[0]);
  for (p = str_recv; *(p + 1); p++);	/* find the last char */
  if ((bytes_recv > 0) && !isdigit((int)*p))
    snprintf(++p, sizeof(str_recv) - 32, " (%lu)", bytes_recv);

  netcat_snprintnum(str_sent, 32, bytes_sent);
  assert(str_sent[0]);
  for (p = str_sent; *(p + 1); p++);	/* find the last char */
  if ((bytes_sent > 0) && !isdigit((int)*p))
    snprintf(++p, sizeof(str_sent) - 32, " (%lu)", bytes_sent);

  ncprint(NCPRINT_NONEWLINE | (force ? 0 : NCPRINT_VERB2),
	  _("Total received bytes: %s\nTotal sent bytes: %s\n"),
	  str_recv, str_sent);
}

/* This is a safe string split function.  It will return a valid pointer
   whatever input parameter was used.  In normal behaviour, it will return a
   null-terminated string containing the first word of the string pointer to by
   `buf', while the `buf' pointer will be updated to point to the following
   char which may also be a space.  Leading spaces are ignored. */

char *netcat_string_split(char **buf)
{
  register char *o, *r;

  if (!buf || (*buf == NULL))
    return *buf = "";
  /* skip all initial spaces */
  for (o = *buf; isspace((int)*o); o++);
  /* save the pointer and move to the next token */
  for (r = o; *o && !isspace((int)*o); o++);
  if (*o)
    *o++ = 0;
  *buf = o;
  return r;
}

/* construct an argv, and hand anything left over to readwrite(). */

void netcat_commandline_read(int *argc, char ***argv)
{
  int my_argc = 1;
  char **my_argv = *argv;
  char *saved_argv0 = my_argv[0];
  char buf[4096], *p, *rest;

  /* using this output style makes sure that a careless translator can't take
     down everything while playing with c-format */
  fprintf(stderr, "%s ", _("Cmd line:"));
  fflush(stderr);			/* this isn't needed, but on ALL OS? */
  commandline_need_newline = TRUE;	/* fancy output handling */
  p = fgets(buf, sizeof(buf), stdin);
  my_argv = malloc(128 * sizeof(char *));	/* FIXME: 128? */
  memset(my_argv, 0, 128 * sizeof(char *));
  my_argv[0] = saved_argv0;		/* leave the program name intact */
  if (!buf[0])				/* there is no input (ctrl+d?) */
    printf("\n");
  commandline_need_newline = FALSE;

  /* fgets() returns a newline, which is stripped by netcat_string_split() */
  do {
    rest = netcat_string_split(&p);
    my_argv[my_argc++] = (rest[0] ? strdup(rest) : NULL);
  } while (rest[0] && (my_argc < 128));

  /* now my_argc counts one more, because we have a NULL element at
   * the end of the list */
  my_argv = realloc(my_argv, my_argc-- * sizeof(char *));

  /* sends out the results */
  *argc = my_argc;
  *argv = my_argv;

#if 0
  /* debug this routine */
  printf("new argc is: %d\n", *argc);
  for (my_argc = 0; my_argc < *argc; my_argc++) {
    printf("my_argv[%d] = \"%s\"\n", my_argc, my_argv[my_argc]);
  }
#endif
}

/* Prints the help screen to stdout */

void netcat_printhelp(char *argv0)
{
  printf(_("GNU netcat %s, a rewrite of the famous networking tool.\n"), VERSION);
  printf(_("Basic usages:\n"));
  printf(_("connect to somewhere:  %s [options] hostname port [port] ...\n"), argv0);
  printf(_("listen for inbound:    %s -l -p port [options] [hostname] [port] ...\n"), argv0);
  printf(_("tunnel to somewhere:   %s -L hostname:port -p port [options]\n"), argv0);
  printf("\n");
  printf(_("Mandatory arguments to long options are mandatory for short options too.\n"));
  printf(_("Options:\n"
"  -c, --close                close connection on EOF from stdin\n"
"  -e, --exec=PROGRAM         program to exec after connect\n"
"  -g, --gateway=LIST         source-routing hop point[s], up to 8\n"
"  -G, --pointer=NUM          source-routing pointer: 4, 8, 12, ...\n"
"  -h, --help                 display this help and exit\n"
"  -i, --interval=SECS        delay interval for lines sent, ports scanned\n"
"  -l, --listen               listen mode, for inbound connects\n"));
  printf(_(""
"  -L, --tunnel=ADDRESS:PORT  forward local port to remote address\n"
"  -n, --dont-resolve         numeric-only IP addresses, no DNS\n"
"  -o, --output=FILE          output hexdump traffic to FILE (implies -x)\n"
"  -p, --local-port=NUM       local port number\n"
"  -r, --randomize            randomize local and remote ports\n"
"  -s, --source=ADDRESS       local source address (ip or hostname)\n"));
#ifndef USE_OLD_COMPAT
  printf(_(""
"  -t, --tcp                  TCP mode (default)\n"
"  -T, --telnet               answer using TELNET negotiation\n"));
#else
  printf(_(""
"      --tcp                  TCP mode (default)\n"
"  -t, --telnet               answer using TELNET negotiation\n"
"  -T                         same as --telnet (compat)\n"));
#endif
  printf(_(""
"  -u, --udp                  UDP mode\n"
"  -v, --verbose              verbose (use twice to be more verbose)\n"
"  -V, --version              output version information and exit\n"
"  -x, --hexdump              hexdump incoming and outgoing traffic\n"
"  -w, --wait=SECS            timeout for connects and final net reads\n"
"  -z, --zero                 zero-I/O mode (used for scanning)\n"));
  printf("\n");
  printf(_("Remote port number can also be specified as range.  "
	   "Example: '1-1024'\n"));
  printf("\n");
}

/* Prints version and license information to stdout */

void netcat_printversion(void)
{
  printf("netcat (The GNU Netcat) %s\n", VERSION);
  printf(_("Copyright (C) 2002 - 2003  Giovanni Giacobbi\n\n"
"This program comes with NO WARRANTY, to the extent permitted by law.\n"
"You may redistribute copies of this program under the terms of\n"
"the GNU General Public License.\n"
"For more information about these matters, see the file named COPYING.\n\n"
"Original idea and design by Avian Research <hobbit@avian.org>,\n"
"Written by Giovanni Giacobbi <giovanni@giacobbi.net>.\n"));
}

#ifdef DEBUG
/* This function resolves in a totally non-threadsafe way the format strings in
   the debug messages in order to wrap the call to the ncprint facility */

const char *debug_fmt(const char *fmt, ...)
{
  static char buf[512];
  va_list args;

  /* resolve the format strings only if it is really needed */
  if (opt_debug) {
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
  }
  else {
    strncpy(buf, fmt, sizeof(buf));
    buf[sizeof(buf) - 1] = 0;
  }

  return buf;
}
#endif

#ifndef USE_LINUX_SELECT
#define TIMEVAL_DIFF(__t1, __t2) {			\
    (__t1)->tv_usec -= (__t2)->tv_usec;			\
    if ((__t1)->tv_usec < 0) {				\
      (__t1)->tv_usec += 1000000L;			\
      (__t1)->tv_sec -= 1;				\
    }							\
    (__t1)->tv_sec -= (__t2)->tv_sec;			\
    if ((__t1)->tv_sec < 0) {				\
      (__t1)->tv_sec = 0;				\
      (__t1)->tv_usec = 0;				\
    }							\
  }

void update_timeval(struct timeval *target)
{
  static struct timeval dd_start;
  struct timeval dd_end;
  struct timezone dd_zone;

  if (target == NULL) {			/* just initialize the seed */
    if (gettimeofday(&dd_start, &dd_zone))
      return;				/* can't handle this type of error */
  }
  else {
    if (gettimeofday(&dd_end, &dd_zone))
      return;				/* can't handle this type of error */

    TIMEVAL_DIFF(&dd_end, &dd_start);	/* get the spent time */
    TIMEVAL_DIFF(target, &dd_end);	/* and update the target struct */
  }
}
#endif
