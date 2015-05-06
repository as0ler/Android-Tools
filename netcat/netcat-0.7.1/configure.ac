#
#  configure.ac
#
#  Author: Giovanni Giacobbi <giovanni@giacobbi.net>
#
#  Copyright (C) 2002 - 2004  Giovanni Giacobbi
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#

dnl initialize with some random file to ensure the source is here.
AC_INIT(ChangeLog)

dnl put any platform specific stuff here
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE(netcat, 0.7.1)
AC_PREREQ(2.53)

dnl without this order in this file, automake will be confused!
AM_CONFIG_HEADER(config.h)

dnl check for programs.  first the c compiler.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_RANLIB

dnl check for pod2man since we'll need it for building documentation
dnl this is really needed only by packagers
dnl AC_CHECK_PROG(netcat_pod2man, pod2man, yes, no)

AC_PATH_PROGS(PERL, perl5 perl, no)
AC_PATH_PROG(POD2MAN, pod2man, no)

dnl add --with-extra-includes and --with-extra-libs switch to ./configure
dnl
all_libraries="$all_libraries $USER_LDFLAGS"
all_includes="$all_includes $USER_INCLUDES"
AC_SUBST(all_includes)
AC_SUBST(all_libraries)

dnl I18n support
ALL_LINGUAS="it sk"
AM_GNU_GETTEXT([external], need-ngettext)
AM_INTL_SUBDIR

dnl find resolver functions and the socket library on some broken OS
AC_LBL_LIBRARY_NET

dnl Fortunately we have Solaris...
AC_CHECK_HEADERS(sys/sockio.h)

AC_CHECK_FUNCS(srandom random)
if test $ac_cv_func_srandom = no; then
  # let's try with the older srand/rand functions
  AC_CHECK_FUNCS(srand rand)
fi

dnl Advanced network address translating functions
AC_CHECK_FUNCS(inet_pton inet_ntop)

dnl Support BSD4.4 "sa_len" extension when calculating sockaddrs arrays
AC_CHECK_MEMBERS(struct sockaddr.sa_len, , , [#include <sys/types.h>
#include <sys/socket.h>])

dnl Check if it is available the RFC2292 IPv4 extension and in_port_t.
AC_CHECK_TYPES([struct in_pktinfo, in_port_t], , , [#include <sys/types.h>
#include <netinet/in.h>])

# check if this compiler supports the common parameter `-Wall'
if test -n "$GCC"; then
  CFLAGS="$CFLAGS -Wall"
fi

# check wether we shall use linux-style select(2) call
case "$host" in
  *-linux*)
    AC_DEFINE(USE_LINUX_SELECT,  , [use the linux-style select(2) call])
    ;;
esac
    

dnl *********************************************************************
dnl ** CONFIGURE SWITCHES ***********************************************
dnl *********************************************************************

dnl the non-debug CFLAGS should include -DNDEBUG in a more stable context
dnl in order to remove the assert() calls

AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug],
	[enable debugging (requires GNU compiler, default: no)]),
	[CFLAGS="$CFLAGS -O0 -g3 -ggdb3 -DDEBUG"])

AC_ARG_ENABLE(compat, AC_HELP_STRING([--enable-compat],
	[enable all old compatibility switches (default: no)]),
	nc_enab_compat=yes
	nc_enab_oldhexdump=yes
	nc_enab_oldtelnet=yes)

AC_ARG_ENABLE(oldhexdump, AC_HELP_STRING([--enable-oldhexdump],
	[use the old style hexdump format (default: no)]),
	nc_enab_oldhexdump=yes)

AC_ARG_ENABLE(oldtelnet, AC_HELP_STRING([--enable-oldtelnet],
	[use old telnet codes parsing policy (default: no)]),
	nc_enab_oldtelnet=yes)

AC_ARG_WITH(included-getopt, AC_HELP_STRING([--with-included-getopt],
	[use the internal getopt library (default: auto)]),
	nc_need_getopt=yes)


# apply the acquired enable options
if test "x$nc_enab_compat" = "xyes"; then
  AC_DEFINE(USE_OLD_COMPAT,  , [misc old compat behaviours])
fi

if test "x$nc_enab_oldhexdump" = "xyes"; then
  AC_DEFINE(USE_OLD_HEXDUMP,  , [use the old style hexdump format])
fi

if test "x$nc_enab_oldtelnet" = "xyes"; then
  AC_DEFINE(USE_OLD_TELNET,  , [use the old telnet codes parsing policy])
fi


dnl *********************************************************************
dnl ** SPECIAL FUNCTIONS VALIDITY CHECKING ******************************
dnl *********************************************************************

dnl Try to see if we need the included getopt
dnl NOTE: with this configuration, it could happen on a really broken
dnl       system, that we have the header file but not the library
dnl       function, and I don't know what would happen.
dnl AC_CHECK_HEADER(getopt.h)
dnl AM_CONDITIONAL(NEED_GETOPT_H, test ac_cv_header_getopt_h = no)

# don't run the check if --with-included-getopt was specified
if test "x$nc_need_getopt" != "xyes"; then
  AC_CHECK_FUNCS(getopt_long)
  if test $ac_cv_func_getopt_long = no; then
    # automatically use the internal getopt library
    nc_need_getopt=yes
    CONTRIBLIBS="../lib/contrib/libcontrib.a"
  fi
fi


dnl *********************************************************************
dnl ** AUTOMAKE CONDITIONALS ********************************************
dnl *********************************************************************

AC_SUBST(CONTRIBLIBS)
AM_CONDITIONAL(NEED_GETOPT, test "x$nc_need_getopt" = "xyes")


dnl *********************************************************************
dnl ** OUTPUT SECTION ***************************************************
dnl *********************************************************************
	
dnl add here all the Makefiles.  These will be created by configure.
dnl
AC_CONFIG_FILES(Makefile m4/Makefile lib/Makefile lib/contrib/Makefile
	src/Makefile doc/Makefile doc/drafts/Makefile po/Makefile.in)

dnl this one is special, it needs the executable flag
dnl
AC_CONFIG_FILES(doc/texi2pod.pl, chmod +x doc/texi2pod.pl)
AC_OUTPUT
