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

# $Id: Makefile.am,v 1.4 2003/01/02 14:39:31 themnemonic Exp $

# general rule to build png graphs from the DIA xml file
.xml.png:
	dia -e $@ $(srcdir)/$<

docs: corerw.png resolve.png

# clean images generated at packaging time, and DIA's backup files
MAINTAINERCLEANFILES = corerw.png resolve.png *.xml~

##dist-hook: docs
##	@cp -p $(srcdir)/corerw.png $(distdir)
##	@cp -p $(srcdir)/resolve.png $(distdir)

EXTRA_DIST = *.txt
