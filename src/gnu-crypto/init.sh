#!/bin/sh
#
# ----------------------------------------------------------------------------
# $Id: init.sh,v 1.5.2.1 2004/01/15 01:31:05 rsdio Exp $
#
# Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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
# A script similar to that found under the gcj subtree.  It should be run
# after cd-ing into a build directory.  It does the following:
#
# 1. copy the .java source files from ./source to current directory,
# 2. copy the ./jce tree to current directory,
# 3. copy the 'autogen.sh' script, as well as the 'config.ac' and 'Makefile.am'
#    files, for non-GCJ-specific build, to the current directory.  also copy
#    the GNU Crypto M4 macros (acinclude.m4) from ./ to current directory.
# 4. copy the standard files from ./ to current directory.
# 5. ensure '.sh' files are world executable.
#
# $Revision: 1.5.2.1 $
#

BUILD_DIR=`pwd`
ME="$0"
cd `dirname "$ME"`

# ----- step 1
cp -rf --preserve=timestamps ./source $BUILD_DIR

# ----- step 2
cp -rf --preserve=timestamps ./security $BUILD_DIR
cp -rf --preserve=timestamps ./jce      $BUILD_DIR
cp -rf --preserve=timestamps ./docs     $BUILD_DIR

# ----- step 3
cp -f  autogen.sh   $BUILD_DIR
cp -f  configure.ac $BUILD_DIR
cp -f  Makefile.am  $BUILD_DIR
cp -f  acinclude.m4 $BUILD_DIR

# ----- step 4
cp -f  AUTHORS   $BUILD_DIR
cp -f  ChangeLog $BUILD_DIR
cp -f  COPYING   $BUILD_DIR
cp -f  INSTALL   $BUILD_DIR
cp -f  NEWS      $BUILD_DIR
cp -f  README    $BUILD_DIR

cp -f  aclocal.m4    $BUILD_DIR
cp -f  config.guess  $BUILD_DIR
cp -f  config.sub    $BUILD_DIR
cp -f  configure     $BUILD_DIR
cp -f  install-sh    $BUILD_DIR
cp -f  Makefile.in   $BUILD_DIR
cp -f  missing       $BUILD_DIR
cp -f  mkinstalldirs $BUILD_DIR

# ----- step 5
cd $BUILD_DIR
chmod +x *.sh
chmod +rwx *.m4
chmod +rwx configure
