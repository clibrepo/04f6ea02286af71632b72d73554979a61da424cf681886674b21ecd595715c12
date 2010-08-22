## Process this file with automake to produce Makefile.in.
#
# -----------------------------------------------------------------------------
# $Id: Makefile.am,v 1.4 2003/11/08 21:46:07 raif Exp $
#
# Copyright (C) 2003 Free Software Foundation, Inc.
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
# -----------------------------------------------------------------------------
#
# $Revision: 1.4 $
#

SUBDIRS = diagrams
EXTRA_DIST = draft-marshall-gnu-keyring.nroff


# GNU Crypto info manual ------------------------------------------------------
info_TEXINFOS = gnu-crypto.texi
gnu_crypto_TEXINFOS = \
 assembly.texi \
 cascade.texi \
 ciphers.texi \
 fdl.texi \
 gpl.texi \
 hash.texi \
 hlapi.texi \
 intro.texi \
 jce.texi \
 keyagr.texi \
 keygen.texi \
 key.texi \
 mac.texi \
 modes.texi \
 pad.texi \
 prng.texi \
 sig.texi


# GNU Crypto keyring draft proposal -------------------------------------------
draft-marshall-gnu-keyring.txt: draft-marshall-gnu-keyring.nroff
	nroff -ms $< | perl fix.pl > $@
