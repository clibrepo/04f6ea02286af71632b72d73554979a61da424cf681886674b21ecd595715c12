dnl
dnl $Id: serpent.m4,v 1.1 2003/01/01 06:09:57 raif Exp $
dnl
dnl Copyright (C) 2001, 2002, 2003, Free Software Foundation, Inc.
dnl
dnl This file is part of GNU Crypto.
dnl
dnl GNU Crypto is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2, or (at your option)
dnl any later version.
dnl
dnl GNU Crypto is distributed in the hope that it will be useful, but
dnl WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; see the file COPYING.  If not, write to the
dnl
dnl    Free Software Foundation Inc.,
dnl    59 Temple Place - Suite 330,
dnl    Boston, MA 02111-1307
dnl    USA
dnl
dnl Linking this library statically or dynamically with other modules is
dnl making a combined work based on this library.  Thus, the terms and
dnl conditions of the GNU General Public License cover the whole
dnl combination.
dnl
dnl As a special exception, the copyright holders of this library give
dnl you permission to link this library with independent modules to
dnl produce an executable, regardless of the license terms of these
dnl independent modules, and to copy and distribute the resulting
dnl executable under terms of your choice, provided that you also meet,
dnl for each linked independent module, the terms and conditions of the
dnl license of that module.  An independent module is a module which is
dnl not derived from or based on this library.  If you modify this
dnl library, you may extend this exception to your version of the
dnl library, but you are not obligated to do so.  If you do not wish to
dnl do so, delete this exception statement from your version.
dnl
dnl $Revision: 1.1 $
dnl
dnl M4 macros used to generate the GCJ-friendly Serpent.java source file.
dnl The macro expansion code is from Dag Arne Osvik's serpent.c code.
dnl
dnl
define(`m4_K',`
      $4 ^= key.k`'eval(4*$5+3); $3 ^= key.k`'eval(4*$5+2); $2 ^= key.k`'eval(4*$5+1); $1 ^= key.k`'eval(4*$5);')dnl
dnl
define(`m4_LK',`
      $1 = ($1 << 13) | ($1 >>> 19); $3 = ($3 <<  3) | ($3 >>> 29);
      $2 ^= $1; $5 = $1 << 3; $4 ^= $3; $2 ^= $3;
      $2 = ($2 << 1) | ($2 >>> 31); $4 ^= $5;
      $4 = ($4 << 7) | ($4 >>> 25); $5 = $2; $1 ^= $2; $5 <<= 7; $3 ^= $4;
      $1 ^= $4; $3 ^= $5; $4 ^= key.k`'eval(4*$6+3); $2 ^= key.k`'eval(4*$6+1);
      $1 = ($1 <<  5) | ($1 >>> 27); $3 = ($3 << 22) | ($3 >>> 10);
      $1 ^= key.k`'eval(4*$6); $3 ^= key.k`'eval(4*$6+2);')dnl
dnl
define(`m4_KL',`
      $1 ^= key.k`'eval(4*$6); $2 ^= key.k`'eval(4*$6+1); $3 ^= key.k`'eval(4*$6+2); $4 ^= key.k`'eval(4*$6+3);
      $1 = ($1 >>>  5) | ($1 << 27); $3 = ($3 >>> 22) | ($3 << 10);
      $5 = $2; $3 ^= $4; $1 ^= $4; $5 <<= 7; $1 ^= $2;
      $2 = ($2 >>> 1) | ($2 << 31); $3 ^= $5; $4 = ($4 >>> 7) | ($4 << 25);
      $5 = $1 << 3; $2 ^= $1; $4 ^= $5; $1 = ($1 >>> 13) | ($1 << 19);
      $2 ^= $3; $4 ^= $3; $3 = ($3 >>> 3) | ($3 << 29);')dnl
dnl
define(`m4_S0',`
      $5 =  $4; $4 |= $1; $1 ^= $5; $5 ^= $3; $5 = ~$5; $4 ^= $2; $2 &= $1;
      $2 ^= $5; $3 ^= $1; $1 ^= $4; $5 |= $1; $1 ^= $3; $3 &= $2; $4 ^= $3;
      $2 = ~$2; $3 ^= $5; $2 ^= $3;')dnl
dnl
define(`m4_S1',`
      $5 =  $2; $2 ^= $1; $1 ^= $4; $4 = ~$4; $5 &= $2; $1 |= $2; $4 ^= $3;
      $1 ^= $4; $2 ^= $4; $4 ^= $5; $2 |= $5; $5 ^= $3; $3 &= $1; $3 ^= $2;
      $2 |= $1; $1 = ~$1; $1 ^= $3; $5 ^= $2;')dnl
dnl
define(`m4_S2',`
      $4 = ~$4; $2 ^= $1; $5 =  $1; $1 &= $3; $1 ^= $4; $4 |= $5; $3 ^= $2;
      $4 ^= $2; $2 &= $1; $1 ^= $3; $3 &= $4; $4 |= $2; $1 = ~$1; $4 ^= $1;
      $5 ^= $1; $1 ^= $3; $2 |= $3;')dnl
dnl
define(`m4_S3',`
      $5 =  $2; $2 ^= $4; $4 |= $1; $5 &= $1; $1 ^= $3; $3 ^= $2; $2 &= $4;
      $3 ^= $4; $1 |= $5; $5 ^= $4; $2 ^= $1; $1 &= $4; $4 &= $5; $4 ^= $3;
      $5 |= $2; $3 &= $2; $5 ^= $4; $1 ^= $4; $4 ^= $3;')dnl
dnl
define(`m4_S4',`
      $5 =  $4; $4 &= $1; $1 ^= $5; $4 ^= $3; $3 |= $5; $1 ^= $2; $5 ^= $4;
      $3 |= $1; $3 ^= $2; $2 &= $1; $2 ^= $5; $5 &= $3; $3 ^= $4; $5 ^= $1;
      $4 |= $2; $2 = ~$2; $4 ^= $1;')dnl
dnl
define(`m4_S5',`
      $5 =  $2; $2 |= $1; $3 ^= $2; $4 = ~$4; $5 ^= $1; $1 ^= $3; $2 &= $5;
      $5 |= $4; $5 ^= $1; $1 &= $4; $2 ^= $4; $4 ^= $3; $1 ^= $2; $3 &= $5;
      $2 ^= $3; $3 &= $1; $4 ^= $3;')dnl
dnl
define(`m4_S6',`
      $5 =  $2; $4 ^= $1; $2 ^= $3; $3 ^= $1; $1 &= $4; $2 |= $4; $5 = ~$5;
      $1 ^= $2; $2 ^= $3; $4 ^= $5; $5 ^= $1; $3 &= $1; $5 ^= $2; $3 ^= $4;
      $4 &= $2; $4 ^= $1; $2 ^= $3;')dnl
dnl
define(`m4_S7',`
      $2 = ~$2; $5 =  $2; $1 = ~$1; $2 &= $3; $2 ^= $4; $4 |= $5; $5 ^= $3;
      $3 ^= $4; $4 ^= $1; $1 |= $2; $3 &= $1; $1 ^= $5; $5 ^= $4; $4 &= $1;
      $5 ^= $2; $3 ^= $5; $4 ^= $2; $5 |= $1; $5 ^= $2;')dnl
dnl
define(`m4_SI0',`
      $5 =  $4; $2 ^= $1; $4 |= $2; $5 ^= $2; $1 = ~$1; $3 ^= $4; $4 ^= $1;
      $1 &= $2; $1 ^= $3; $3 &= $4; $4 ^= $5; $3 ^= $4; $2 ^= $4; $4 &= $1;
      $2 ^= $1; $1 ^= $3; $5 ^= $4;')dnl
dnl
define(`m4_SI1',`
      $2 ^= $4; $5 =  $1; $1 ^= $3; $3 = ~$3; $5 |= $2; $5 ^= $4; $4 &= $2;
      $2 ^= $3; $3 &= $5; $5 ^= $2; $2 |= $4; $4 ^= $1; $3 ^= $1; $1 |= $5;
      $3 ^= $5; $2 ^= $1; $5 ^= $2;')dnl
dnl
define(`m4_SI2',`
      $3 ^= $2; $5 =  $4; $4 = ~$4; $4 |= $3; $3 ^= $5; $5 ^= $1; $4 ^= $2;
      $2 |= $3; $3 ^= $1; $2 ^= $5; $5 |= $4; $3 ^= $4; $5 ^= $3; $3 &= $2;
      $3 ^= $4; $4 ^= $5; $5 ^= $1;')dnl
dnl
define(`m4_SI3',`
      $3 ^= $2; $5 =  $2; $2 &= $3; $2 ^= $1; $1 |= $5; $5 ^= $4; $1 ^= $4;
      $4 |= $2; $2 ^= $3; $2 ^= $4; $1 ^= $3; $3 ^= $4; $4 &= $2; $2 ^= $1;
      $1 &= $3; $5 ^= $4; $4 ^= $1; $1 ^= $2;')dnl
dnl
define(`m4_SI4',`
      $3 ^= $4; $5 =  $1; $1 &= $2; $1 ^= $3; $3 |= $4; $5 = ~$5; $2 ^= $1;
      $1 ^= $3; $3 &= $5; $3 ^= $1; $1 |= $5; $1 ^= $4; $4 &= $3; $5 ^= $4;
      $4 ^= $2; $2 &= $1; $5 ^= $2; $1 ^= $4;')dnl
dnl
define(`m4_SI5',`
      $5 =  $2; $2 |= $3; $3 ^= $5; $2 ^= $4; $4 &= $5; $3 ^= $4; $4 |= $1;
      $1 = ~$1; $4 ^= $3; $3 |= $1; $5 ^= $2; $3 ^= $5; $5 &= $1; $1 ^= $2;
      $2 ^= $4; $1 &= $3; $3 ^= $4; $1 ^= $3; $3 ^= $5; $5 ^= $4;')dnl
dnl
define(`m4_SI6',`
      $1 ^= $3; $5 =  $1; $1 &= $4; $3 ^= $4; $1 ^= $3; $4 ^= $2; $3 |= $5;
      $3 ^= $4; $4 &= $1; $1 = ~$1; $4 ^= $2; $2 &= $3; $5 ^= $1; $4 ^= $5;
      $5 ^= $3; $1 ^= $2; $3 ^= $1;')dnl
dnl
define(`m4_SI7',`
      $5 =  $4; $4 &= $1; $1 ^= $3; $3 |= $5; $5 ^= $2; $1 = ~$1; $2 |= $4;
      $5 ^= $1; $1 &= $3; $1 ^= $2; $2 &= $3; $4 ^= $3; $5 ^= $4; $3 &= $4;
      $4 |= $1; $2 ^= $5; $4 ^= $5; $5 &= $1; $5 ^= $3;')dnl
dnl
define(`m4_keyiter',`$2 ^= $4; $2 ^= $3; $2 ^= $1; $2 ^= PHI ^ $5; $2 = ($2 << 11) | ($2 >>> 21); w[$5] = $2;')dnl
dnl
define(`m4_storekeys',`
      key.k`'eval($5) = $1; key.k`'eval($5+1) = $2; key.k`'eval($5+2) = $3; key.k`'eval($5+3) = $4;')dnl
dnl
define(`m4_loadkeys',`
      $1 = w[`'eval($5)]; $2 = w[`'eval($5+1)]; $3 = w[`'eval($5+2)]; $4 = w[`'eval($5+3)];')dnl
dnl
