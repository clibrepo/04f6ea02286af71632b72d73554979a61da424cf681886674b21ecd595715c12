#!/bin/sh
# ----------------------------------------------------------------------------
# $Id: autogen.sh,v 1.2 2002/12/14 07:41:18 raif Exp $
#
# Copyright (C) 2001, 2002, Free Software Foundation, Inc.
#
# This file is part of GNU Crypto.
#
# GNU Crypto is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# GNU Crypto is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to the
#
#    Free Software Foundation Inc.,
#    59 Temple Place - Suite 330,
#    Boston, MA 02111-1307
#    USA
#
# Linking this library statically or dynamically with other modules is
# making a combined work based on this library.  Thus, the terms and
# conditions of the GNU General Public License cover the whole
# combination.
#
# As a special exception, the copyright holders of this library give
# you permission to link this library with independent modules to
# produce an executable, regardless of the license terms of these
# independent modules, and to copy and distribute the resulting
# executable under terms of your choice, provided that you also meet,
# for each linked independent module, the terms and conditions of the
# license of that module.  An independent module is a module which is
# not derived from or based on this library.  If you modify this
# library, you may extend this exception to your version of the
# library, but you are not obligated to do so.  If you do not wish to
# do so, delete this exception statement from your version.
# ----------------------------------------------------------------------------
#
# A script to generate all needed GNU build toolchain scripts and files before
# packaging a distribution, and for locally building a shared reloadable
# gnu-crypto library.
#
# $Revision: 1.2 $
#

[ -f configure.ac ] || {
   echo "*** Info: You should run this command in a build directory after"
   echo "invoking the 'init.sh' script."
   exit 1
}

DIE=0

(autoconf --version) < /dev/null > /dev/null 2>&1 || {
   echo
   echo "*** Error: Need 'autoconf' to compile GNU Crypto."
   echo "Try ftp://ftp.gnu.org/pub/gnu/autoconf/autoconf-2.56.tar.gz"
   echo "--or a newer version if one is available."
   DIE=1
   NO_AUTOCONF=yes
}

(automake --version) < /dev/null > /dev/null 2>&1 || {
   echo
   echo "*** Error: Need 'automake' to compile GNU Crypto."
   echo "Try ftp://ftp.gnu.org/pub/gnu/automake/automake-1.7.1.tar.gz"
   echo "--or a newer version if one is available."
   DIE=1
   NO_AUTOMAKE=yes
}

# test for aclocal, only if automake was found
test -n "$NO_AUTOMAKE" || (aclocal --version) < /dev/null > /dev/null 2>&1 || {
   echo
   echo "*** Error: Need 'aclocal' to compile GNU Crypto."
   echo "The version of 'automake' found is not recent enough."
   echo "Try ftp://ftp.gnu.org/pub/gnu/automake/automake-1.7.1.tar.gz"
   echo "--or a newer version if one is available."
   DIE=1
}

# TODO: re-activate once libtool works with GCJ
#(libtool --version) < /dev/null > /dev/null 2>&1 || {
#   echo
#   echo "*** Error: Need 'libtool' to compile GNU Crypto."
#   echo "Try ftp://ftp.gnu.org/pub/gnu/libtool-1.4.3.tar.gz"
#   echo "--or a newer version if one is available."
#   DIE=1
#}

if test "$DIE" -eq 1; then
   exit 1
fi

if test -z "$*"; then
   echo "*** Warning: Will invoke 'configure' with no arguments.  If any"
   echo "are required, append them to the "$0" command line."
   echo
fi

echo "*** Info: Generating GNU build toolchain scripts and files for GCJ-friendly GNU Crypto."

# TODO: re-activate once libtool works with GCJ
#echo "libtoolize --force --copy"
#libtoolize --force --copy

echo "aclocal -I ."
aclocal -I .

echo "automake --add-missing --copy"
automake --add-missing --copy

echo "autoconf"
autoconf

conf_flags="--enable-maintainer-mode"
echo "./configure "$conf_flags "$@"
(./configure $conf_flags "$@") || {
   exit 1
}

echo "*** Info: Done.  Type 'make' to compile GNU Crypto."
