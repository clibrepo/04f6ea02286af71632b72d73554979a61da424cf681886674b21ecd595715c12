#!/bin/sh
#
# ----------------------------------------------------------------------------
# $Id: init.sh,v 1.9 2003/05/30 13:11:06 raif Exp $
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
# A script that should be run after cd-ing into a build directory.  It does
# the following:
#
# 1. copy files from both ../source and ../jce subtrees to current directory,
# 2. copy files from both ./source and ./jce subtrees to current directory,
#    overwriting the ones with same names,
# 3. generate .java source files for specific algorithm implementations; e.g.
#    Serpent.java from ./../../meta/serpent.m4
# 4. copy the 'autogen.sh' script, as well as the 'config.ac' files, for
#    GCJ-specific build, to the current directory.  also copy the GNU Crypto
#    M4 macros (acinclude.m4) and 'Makefile.am' from ./.. to current directory,
# 5. copy the standard files from both ../ and ./ to current directory,
# 6. copy the GCJ-specific libtool files, as checked in into CVS, to the
#    current directory.  this should go away with time when proper support
#    for GCJ will be incorporated into libtool --today, every version of
#    libtool i tried (starting from version 1.4 to 1.4.3 inclusive do not work.
# 7. ensure '.sh' files are world executable.
#
# $Revision: 1.9 $
#

BUILD_DIR=`pwd`
ME="$0"
cd `dirname "$ME"`

# ----- step 1
cp -rf ../source   $BUILD_DIR
cp -rf ../security $BUILD_DIR
cp -rf ../jce      $BUILD_DIR
cp -rf ../docs     $BUILD_DIR

# ----- step 2
cp -rf source   $BUILD_DIR
cp -rf security $BUILD_DIR
cp -rf jce      $BUILD_DIR

# ----- step 3
chmod -R a+rw $BUILD_DIR
test -f $BUILD_DIR/source/gnu/crypto/cipher/Serpent.java || rm -f $BUILD_DIR/source/gnu/crypto/cipher/Serpent.java
m4 -I../meta $BUILD_DIR/source/gnu/crypto/cipher/Serpent.java.in > $BUILD_DIR/source/gnu/crypto/cipher/Serpent.java

# ----- step 4
cp -f  autogen.sh      $BUILD_DIR
cp -f  configure.ac    $BUILD_DIR
cp -f  ../Makefile.am  $BUILD_DIR
cp -f  ../acinclude.m4 $BUILD_DIR

# ----- step 5
cp -f  ../AUTHORS   $BUILD_DIR
cp -f  ../ChangeLog $BUILD_DIR
cp -f  ../COPYING   $BUILD_DIR
cp -f  ../INSTALL   $BUILD_DIR
cp -f  ../NEWS      $BUILD_DIR
cp -f  ../README    $BUILD_DIR

# ----- step 6
cp -f  libtool.m4 $BUILD_DIR
cp -f  lt*        $BUILD_DIR

cp -f  aclocal.m4    $BUILD_DIR
cp -f  config.guess  $BUILD_DIR
cp -f  config.sub    $BUILD_DIR
cp -f  configure     $BUILD_DIR
cp -f  depcomp       $BUILD_DIR
cp -f  install-sh    $BUILD_DIR
cp -f  libtool       $BUILD_DIR
cp -f  Makefile.in   $BUILD_DIR
cp -f  missing       $BUILD_DIR
cp -f  mkinstalldirs $BUILD_DIR

# ----- step 7
cd $BUILD_DIR
chmod +x *.sh
chmod +rwx *.m4
chmod +rwx configure
