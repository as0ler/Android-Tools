/*
 * intl.h -- main i18n support header file
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <giovanni@giacobbi.net>
 * Copyright (C) 2002  Giovanni Giacobbi
 *
 * $Id: intl.h,v 1.6 2002/10/03 10:25:16 themnemonic Exp $
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

#ifdef ENABLE_NLS
#include <libintl.h>

#ifdef HAVE_LOCALE_H
#include <locale.h>
#else
#error You must have locale.h in your system
#endif	/* HAVE_LOCALE_H */

/* Our dear (and very common) gettext macros */
#define _(String) gettext(String)
#define N_(String) String
#define PL_(String1, String2, n) ngettext((String1), (String2), (n))

#else

/* Disabled NLS.
   The casts to 'const char *' serve the purpose of producing warnings
   for invalid uses of the value returned from these functions.
   On pre-ANSI systems without 'const', the config.h file is supposed to
   contain "#define const". */

#define textdomain(Domainname) ((const char *) (Domainname))
#define bindtextdomain(Domainname, Dirname) ((const char *) (Dirname))
#define bind_textdomain_codeset(Domainname, Codeset) ((const char *) (Codeset))

#define _(String) (String)
#define N_(String) String
#define PL_(String1, String2, n) ((n) == 1 ? (String1) : (String2))

#endif	/* ENABLE_NLS */
