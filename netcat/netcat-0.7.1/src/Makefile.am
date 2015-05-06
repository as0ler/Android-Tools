## Process this file with automake to create Makefile.in

## Makefile for Netcat.

## Copyright (C) 1995, 1996, 1997, 1998, 1999, 2001, 2002 Free
## Software Foundation, Inc.

## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2, or (at your option)
## any later version.

## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.

# $Id: Makefile.am,v 1.14 2003/01/03 22:53:31 themnemonic Exp $

localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"\$(localedir)\" @DEFS@

if NEED_GETOPT
INCLUDES = -I../lib/contrib
endif

bin_PROGRAMS = netcat
netcat_SOURCES = \
	core.c \
	flagset.c \
	misc.c \
	netcat.c \
	network.c \
	telnet.c \
	udphelper.c

netcat_LDADD = @CONTRIBLIBS@ @INTLLIBS@

EXTRA_DIST = *.h

#
# Follows the local installation procedures
#
netcat_nc = $(DESTDIR)$(bindir)/nc

install-exec-hook:
	@if [ ! -L $(netcat_nc) -a ! -e $(netcat_nc) ]; then \
		echo "Creating symlink to the shorter executable name"; \
		ln -s netcat $(netcat_nc); \
	fi

uninstall-hook:
	@if [ -L $(netcat_nc) ]; then \
		echo "Removing symlink to the shorter executable name"; \
		rm -f $(netcat_nc); \
	fi
