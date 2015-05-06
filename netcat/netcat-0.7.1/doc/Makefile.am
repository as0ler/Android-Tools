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

# $Id: Makefile.am,v 1.9 2003/01/03 22:53:32 themnemonic Exp $

info_TEXINFOS = netcat.texi

man_MANS = netcat.1


# Netcat custom building rules

TEXI2POD = $(top_builddir)/doc/texi2pod.pl

netcat.pod: $(srcdir)/netcat.texi
	$(TEXI2POD) $(srcdir)/netcat.texi $@

$(man_MANS): netcat.pod
	$(POD2MAN) --center="Netcat" --release="GNU Netcat @VERSION@" $? > $@

MAINTAINERCLEANFILES = netcat.1 netcat.pod

EXTRA_DIST = netcat.1 netcat.pod migration

## Proceed to subdirs

SUBDIRS = drafts
