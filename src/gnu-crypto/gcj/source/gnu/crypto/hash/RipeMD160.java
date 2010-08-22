package gnu.crypto.hash;

// ----------------------------------------------------------------------------
// $Id: RipeMD160.java,v 1.1 2002/12/06 21:26:23 raif Exp $
//
// Copyright (C) 2001, 2002, Free Software Foundation, Inc.
//
// This file is part of GNU Crypto.
//
// GNU Crypto is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2, or (at your option)
// any later version.
//
// GNU Crypto is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; see the file COPYING.  If not, write to the
//
//    Free Software Foundation Inc.,
//    59 Temple Place - Suite 330,
//    Boston, MA 02111-1307
//    USA
//
// Linking this library statically or dynamically with other modules is
// making a combined work based on this library.  Thus, the terms and
// conditions of the GNU General Public License cover the whole
// combination.
//
// As a special exception, the copyright holders of this library give
// you permission to link this library with independent modules to
// produce an executable, regardless of the license terms of these
// independent modules, and to copy and distribute the resulting
// executable under terms of your choice, provided that you also meet,
// for each linked independent module, the terms and conditions of the
// license of that module.  An independent module is a module which is
// not derived from or based on this library.  If you modify this
// library, you may extend this exception to your version of the
// library, but you are not obligated to do so.  If you do not wish to
// do so, delete this exception statement from your version.
// ----------------------------------------------------------------------------

import gnu.crypto.Registry;
import gnu.crypto.util.Util;

/**
 * <p>RIPEMD-160 is a 160-bit message digest.</p>
 *
 * <p>References:</p>
 *
 * <ol>
 *    <li><a href="http://www.esat.kuleuven.ac.be/~bosselae/ripemd160.html">
 *    RIPEMD160</a>: A Strengthened Version of RIPEMD.<br>
 *    Hans Dobbertin, Antoon Bosselaers and Bart Preneel.</li>
 * </ol>
 *
 * @version $Revision: 1.1 $
 */
public class RipeMD160 extends BaseHash {

   // Constants and variables
   // -------------------------------------------------------------------------

   private static final int BLOCK_SIZE = 64; // inner block size in bytes
   private static final String DIGEST0 = "9C1185A5C5E9FC54612808977EE8F548B2258D31";

   /** caches the result of the correctness test, once executed. */
   private static Boolean valid;

   /** 160-bit h0, h1, h2, h3, h4 (interim result) */
   private int h0, h1, h2, h3, h4;

   // Constructor(s)
   // -------------------------------------------------------------------------

   /** Trivial 0-arguments constructor. */
   public RipeMD160() {
      super(Registry.RIPEMD160_HASH, 20, BLOCK_SIZE);
   }

   /**
    * <p>Private constructor for cloning purposes.</p>
    *
    * @param md the instance to clone.
    */
   private RipeMD160(RipeMD160 md) {
      this();

      this.h0 = md.h0;
      this.h1 = md.h1;
      this.h2 = md.h2;
      this.h3 = md.h3;
      this.h4 = md.h4;
      this.count = md.count;
      this.buffer = (byte[]) md.buffer.clone();
   }

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   // java.lang.Cloneable interface implementation ----------------------------

   public Object clone() {
      return (new RipeMD160(this));
   }

   // Implementation of concrete methods in BaseHash --------------------------

   protected void transform (byte[] in, int i) {
      int A, B, C, D, E, a, b, c, d, e, T;

      // encode 64 bytes from input block into an array of 16 unsigned integers
      int X0 =  (in[i++] & 0xFF) | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF) << 16 | in[i++] << 24;
      int X1 =  (in[i++] & 0xFF) | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF) << 16 | in[i++] << 24;
      int X2 =  (in[i++] & 0xFF) | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF) << 16 | in[i++] << 24;
      int X3 =  (in[i++] & 0xFF) | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF) << 16 | in[i++] << 24;
      int X4 =  (in[i++] & 0xFF) | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF) << 16 | in[i++] << 24;
      int X5 =  (in[i++] & 0xFF) | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF) << 16 | in[i++] << 24;
      int X6 =  (in[i++] & 0xFF) | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF) << 16 | in[i++] << 24;
      int X7 =  (in[i++] & 0xFF) | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF) << 16 | in[i++] << 24;
      int X8 =  (in[i++] & 0xFF) | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF) << 16 | in[i++] << 24;
      int X9 =  (in[i++] & 0xFF) | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF) << 16 | in[i++] << 24;
      int X10 = (in[i++] & 0xFF) | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF) << 16 | in[i++] << 24;
      int X11 = (in[i++] & 0xFF) | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF) << 16 | in[i++] << 24;
      int X12 = (in[i++] & 0xFF) | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF) << 16 | in[i++] << 24;
      int X13 = (in[i++] & 0xFF) | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF) << 16 | in[i++] << 24;
      int X14 = (in[i++] & 0xFF) | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF) << 16 | in[i++] << 24;
      int X15 = (in[i++] & 0xFF) | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF) << 16 | in[i  ] << 24;

      A = a = h0; B = b = h1; C = c = h2; D = d = h3; E = e = h4;

      // rounds 0..15
      T = A + (B ^ C ^ D) + X0; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 11 | T >>> -11) + A;
      T = a + (b ^ (c | ~d)) + X5 + 0x50A28BE6; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 8 | T >>> -8) + a;

      T = A + (B ^ C ^ D) + X1; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 14 | T >>> -14) + A;
      T = a + (b ^ (c | ~d)) + X14 + 0x50A28BE6; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 9 | T >>> -9) + a;

      T = A + (B ^ C ^ D) + X2; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 15 | T >>> -15) + A;
      T = a + (b ^ (c | ~d)) + X7 + 0x50A28BE6; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 9 | T >>> -9) + a;

      T = A + (B ^ C ^ D) + X3; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 12 | T >>> -12) + A;
      T = a + (b ^ (c | ~d)) + X0 + 0x50A28BE6; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 11 | T >>> -11) + a;

      T = A + (B ^ C ^ D) + X4; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 5 | T >>> -5) + A;
      T = a + (b ^ (c | ~d)) + X9 + 0x50A28BE6; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 13 | T >>> -13) + a;

      T = A + (B ^ C ^ D) + X5; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 8 | T >>> -8) + A;
      T = a + (b ^ (c | ~d)) + X2 + 0x50A28BE6; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 15 | T >>> -15) + a;

      T = A + (B ^ C ^ D) + X6; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 7 | T >>> -7) + A;
      T = a + (b ^ (c | ~d)) + X11 + 0x50A28BE6; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 15 | T >>> -15) + a;

      T = A + (B ^ C ^ D) + X7; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 9 | T >>> -9) + A;
      T = a + (b ^ (c | ~d)) + X4 + 0x50A28BE6; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 5 | T >>> -5) + a;

      T = A + (B ^ C ^ D) + X8; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 11 | T >>> -11) + A;
      T = a + (b ^ (c | ~d)) + X13 + 0x50A28BE6; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 7 | T >>> -7) + a;

      T = A + (B ^ C ^ D) + X9; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 13 | T >>> -13) + A;
      T = a + (b ^ (c | ~d)) + X6 + 0x50A28BE6; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 7 | T >>> -7) + a;

      T = A + (B ^ C ^ D) + X10; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 14 | T >>> -14) + A;
      T = a + (b ^ (c | ~d)) + X15 + 0x50A28BE6; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 8 | T >>> -8) + a;

      T = A + (B ^ C ^ D) + X11; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 15 | T >>> -15) + A;
      T = a + (b ^ (c | ~d)) + X8 + 0x50A28BE6; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 11 | T >>> -11) + a;

      T = A + (B ^ C ^ D) + X12; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 6 | T >>> -6) + A;
      T = a + (b ^ (c | ~d)) + X1 + 0x50A28BE6; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 14 | T >>> -14) + a;

      T = A + (B ^ C ^ D) + X13; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 7 | T >>> -7) + A;
      T = a + (b ^ (c | ~d)) + X10 + 0x50A28BE6; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 14 | T >>> -14) + a;

      T = A + (B ^ C ^ D) + X14; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 9 | T >>> -9) + A;
      T = a + (b ^ (c | ~d)) + X3 + 0x50A28BE6; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 12 | T >>> -12) + a;

      T = A + (B ^ C ^ D) + X15; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 8 | T >>> -8) + A;
      T = a + (b ^ (c | ~d)) + X12 + 0x50A28BE6; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 6 | T >>> -6) + a;

      // rounds 16..31
      T = A + ((B & C) | (~B & D)) + X7 + 0x5A827999; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 7 | T >>> -7) + A;
      T = a + ((b & d) | (c & ~d)) + X6 + 0x5C4DD124; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 9 | T >>> -9) + a;

      T = A + ((B & C) | (~B & D)) + X4 + 0x5A827999; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 6 | T >>> -6) + A;
      T = a + ((b & d) | (c & ~d)) + X11 + 0x5C4DD124; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 13 | T >>> -13) + a;

      T = A + ((B & C) | (~B & D)) + X13 + 0x5A827999; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 8 | T >>> -8) + A;
      T = a + ((b & d) | (c & ~d)) + X3 + 0x5C4DD124; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 15 | T >>> -15) + a;

      T = A + ((B & C) | (~B & D)) + X1 + 0x5A827999; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 13 | T >>> -13) + A;
      T = a + ((b & d) | (c & ~d)) + X7 + 0x5C4DD124; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 7 | T >>> -7) + a;

      T = A + ((B & C) | (~B & D)) + X10 + 0x5A827999; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 11 | T >>> -11) + A;
      T = a + ((b & d) | (c & ~d)) + X0 + 0x5C4DD124; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 12 | T >>> -12) + a;

      T = A + ((B & C) | (~B & D)) + X6 + 0x5A827999; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 9 | T >>> -9) + A;
      T = a + ((b & d) | (c & ~d)) + X13 + 0x5C4DD124; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 8 | T >>> -8) + a;

      T = A + ((B & C) | (~B & D)) + X15 + 0x5A827999; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 7 | T >>> -7) + A;
      T = a + ((b & d) | (c & ~d)) + X5 + 0x5C4DD124; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 9 | T >>> -9) + a;

      T = A + ((B & C) | (~B & D)) + X3 + 0x5A827999; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 15 | T >>> -15) + A;
      T = a + ((b & d) | (c & ~d)) + X10 + 0x5C4DD124; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 11 | T >>> -11) + a;

      T = A + ((B & C) | (~B & D)) + X12 + 0x5A827999; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 7 | T >>> -7) + A;
      T = a + ((b & d) | (c & ~d)) + X14 + 0x5C4DD124; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 7 | T >>> -7) + a;

      T = A + ((B & C) | (~B & D)) + X0 + 0x5A827999; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 12 | T >>> -12) + A;
      T = a + ((b & d) | (c & ~d)) + X15 + 0x5C4DD124; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 7 | T >>> -7) + a;

      T = A + ((B & C) | (~B & D)) + X9 + 0x5A827999; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 15 | T >>> -15) + A;
      T = a + ((b & d) | (c & ~d)) + X8 + 0x5C4DD124; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 12 | T >>> -12) + a;

      T = A + ((B & C) | (~B & D)) + X5 + 0x5A827999; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 9 | T >>> -9) + A;
      T = a + ((b & d) | (c & ~d)) + X12 + 0x5C4DD124; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 7 | T >>> -7) + a;

      T = A + ((B & C) | (~B & D)) + X2 + 0x5A827999; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 11 | T >>> -11) + A;
      T = a + ((b & d) | (c & ~d)) + X4 + 0x5C4DD124; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 6 | T >>> -6) + a;

      T = A + ((B & C) | (~B & D)) + X14 + 0x5A827999; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 7 | T >>> -7) + A;
      T = a + ((b & d) | (c & ~d)) + X9 + 0x5C4DD124; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 15 | T >>> -15) + a;

      T = A + ((B & C) | (~B & D)) + X11 + 0x5A827999; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 13 | T >>> -13) + A;
      T = a + ((b & d) | (c & ~d)) + X1 + 0x5C4DD124; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 13 | T >>> -13) + a;

      T = A + ((B & C) | (~B & D)) + X8 + 0x5A827999; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 12 | T >>> -12) + A;
      T = a + ((b & d) | (c & ~d)) + X2 + 0x5C4DD124; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 11 | T >>> -11) + a;

      // rounds 32..47
      T = A + ((B | ~C) ^ D) + X3 + 0x6ED9EBA1; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 11 | T >>> -11) + A;
      T = a + ((b | ~c) ^ d) + X15 + 0x6D703EF3; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 9 | T >>> -9) + a;

      T = A + ((B | ~C) ^ D) + X10 + 0x6ED9EBA1; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 13 | T >>> -13) + A;
      T = a + ((b | ~c) ^ d) + X5 + 0x6D703EF3; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 7 | T >>> -7) + a;

      T = A + ((B | ~C) ^ D) + X14 + 0x6ED9EBA1; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 6 | T >>> -6) + A;
      T = a + ((b | ~c) ^ d) + X1 + 0x6D703EF3; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 15 | T >>> -15) + a;

      T = A + ((B | ~C) ^ D) + X4 + 0x6ED9EBA1; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 7 | T >>> -7) + A;
      T = a + ((b | ~c) ^ d) + X3 + 0x6D703EF3; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 11 | T >>> -11) + a;

      T = A + ((B | ~C) ^ D) + X9 + 0x6ED9EBA1; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 14 | T >>> -14) + A;
      T = a + ((b | ~c) ^ d) + X7 + 0x6D703EF3; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 8 | T >>> -8) + a;

      T = A + ((B | ~C) ^ D) + X15 + 0x6ED9EBA1; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 9 | T >>> -9) + A;
      T = a + ((b | ~c) ^ d) + X14 + 0x6D703EF3; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 6 | T >>> -6) + a;

      T = A + ((B | ~C) ^ D) + X8 + 0x6ED9EBA1; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 13 | T >>> -13) + A;
      T = a + ((b | ~c) ^ d) + X6 + 0x6D703EF3; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 6 | T >>> -6) + a;

      T = A + ((B | ~C) ^ D) + X1 + 0x6ED9EBA1; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 15 | T >>> -15) + A;
      T = a + ((b | ~c) ^ d) + X9 + 0x6D703EF3; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 14 | T >>> -14) + a;

      T = A + ((B | ~C) ^ D) + X2 + 0x6ED9EBA1; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 14 | T >>> -14) + A;
      T = a + ((b | ~c) ^ d) + X11 + 0x6D703EF3; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 12 | T >>> -12) + a;

      T = A + ((B | ~C) ^ D) + X7 + 0x6ED9EBA1; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 8 | T >>> -8) + A;
      T = a + ((b | ~c) ^ d) + X8 + 0x6D703EF3; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 13 | T >>> -13) + a;

      T = A + ((B | ~C) ^ D) + X0 + 0x6ED9EBA1; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 13 | T >>> -13) + A;
      T = a + ((b | ~c) ^ d) + X12 + 0x6D703EF3; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 5 | T >>> -5) + a;

      T = A + ((B | ~C) ^ D) + X6 + 0x6ED9EBA1; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 6 | T >>> -6) + A;
      T = a + ((b | ~c) ^ d) + X2 + 0x6D703EF3; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 14 | T >>> -14) + a;

      T = A + ((B | ~C) ^ D) + X13 + 0x6ED9EBA1; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 5 | T >>> -5) + A;
      T = a + ((b | ~c) ^ d) + X10 + 0x6D703EF3; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 13 | T >>> -13) + a;

      T = A + ((B | ~C) ^ D) + X11 + 0x6ED9EBA1; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 12 | T >>> -12) + A;
      T = a + ((b | ~c) ^ d) + X0 + 0x6D703EF3; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 13 | T >>> -13) + a;

      T = A + ((B | ~C) ^ D) + X5 + 0x6ED9EBA1; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 7 | T >>> -7) + A;
      T = a + ((b | ~c) ^ d) + X4 + 0x6D703EF3; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 7 | T >>> -7) + a;

      T = A + ((B | ~C) ^ D) + X12 + 0x6ED9EBA1; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 5 | T >>> -5) + A;
      T = a + ((b | ~c) ^ d) + X13 + 0x6D703EF3; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 5 | T >>> -5) + a;

      // rounds 48...63
      T = A + ((B & D) | (C & ~D)) + X1 + 0x8F1BBCDC; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 11 | T >>> -11) + A;
      T = a + ((b & c) | (~b & d)) + X8 + 0x7A6D76E9; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 15 | T >>> -15) + a;

      T = A + ((B & D) | (C & ~D)) + X9 + 0x8F1BBCDC; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 12 | T >>> -12) + A;
      T = a + ((b & c) | (~b & d)) + X6 + 0x7A6D76E9; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 5 | T >>> -5) + a;

      T = A + ((B & D) | (C & ~D)) + X11 + 0x8F1BBCDC; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 14 | T >>> -14) + A;
      T = a + ((b & c) | (~b & d)) + X4 + 0x7A6D76E9; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 8 | T >>> -8) + a;

      T = A + ((B & D) | (C & ~D)) + X10 + 0x8F1BBCDC; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 15 | T >>> -15) + A;
      T = a + ((b & c) | (~b & d)) + X1 + 0x7A6D76E9; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 11 | T >>> -11) + a;

      T = A + ((B & D) | (C & ~D)) + X0 + 0x8F1BBCDC; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 14 | T >>> -14) + A;
      T = a + ((b & c) | (~b & d)) + X3 + 0x7A6D76E9; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 14 | T >>> -14) + a;

      T = A + ((B & D) | (C & ~D)) + X8 + 0x8F1BBCDC; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 15 | T >>> -15) + A;
      T = a + ((b & c) | (~b & d)) + X11 + 0x7A6D76E9; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 14 | T >>> -14) + a;

      T = A + ((B & D) | (C & ~D)) + X12 + 0x8F1BBCDC; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 9 | T >>> -9) + A;
      T = a + ((b & c) | (~b & d)) + X15 + 0x7A6D76E9; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 6 | T >>> -6) + a;

      T = A + ((B & D) | (C & ~D)) + X4 + 0x8F1BBCDC; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 8 | T >>> -8) + A;
      T = a + ((b & c) | (~b & d)) + X0 + 0x7A6D76E9; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 14 | T >>> -14) + a;

      T = A + ((B & D) | (C & ~D)) + X13 + 0x8F1BBCDC; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 9 | T >>> -9) + A;
      T = a + ((b & c) | (~b & d)) + X5 + 0x7A6D76E9; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 6 | T >>> -6) + a;

      T = A + ((B & D) | (C & ~D)) + X3 + 0x8F1BBCDC; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 14 | T >>> -14) + A;
      T = a + ((b & c) | (~b & d)) + X12 + 0x7A6D76E9; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 9 | T >>> -9) + a;

      T = A + ((B & D) | (C & ~D)) + X7 + 0x8F1BBCDC; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 5 | T >>> -5) + A;
      T = a + ((b & c) | (~b & d)) + X2 + 0x7A6D76E9; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 12 | T >>> -12) + a;

      T = A + ((B & D) | (C & ~D)) + X15 + 0x8F1BBCDC; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 6 | T >>> -6) + A;
      T = a + ((b & c) | (~b & d)) + X13 + 0x7A6D76E9; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 9 | T >>> -9) + a;

      T = A + ((B & D) | (C & ~D)) + X14 + 0x8F1BBCDC; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 8 | T >>> -8) + A;
      T = a + ((b & c) | (~b & d)) + X9 + 0x7A6D76E9; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 12 | T >>> -12) + a;

      T = A + ((B & D) | (C & ~D)) + X5 + 0x8F1BBCDC; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 6 | T >>> -6) + A;
      T = a + ((b & c) | (~b & d)) + X7 + 0x7A6D76E9; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 5 | T >>> -5) + a;

      T = A + ((B & D) | (C & ~D)) + X6 + 0x8F1BBCDC; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 5 | T >>> -5) + A;
      T = a + ((b & c) | (~b & d)) + X10 + 0x7A6D76E9; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 15 | T >>> -15) + a;

      T = A + ((B & D) | (C & ~D)) + X2 + 0x8F1BBCDC; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 12 | T >>> -12) + A;
      T = a + ((b & c) | (~b & d)) + X14 + 0x7A6D76E9; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 8 | T >>> -8) + a;

      // rounds 64...79
      T = A + (B ^ (C | ~D)) + X4 + 0xA953FD4E; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 9 | T >>> -9) + A;
      T = a + (b ^ c ^ d) + X12; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 8 | T >>> -8) + a;

      T = A + (B ^ (C | ~D)) + X0 + 0xA953FD4E; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 15 | T >>> -15) + A;
      T = a + (b ^ c ^ d) + X15; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 5 | T >>> -5) + a;

      T = A + (B ^ (C | ~D)) + X5 + 0xA953FD4E; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 5 | T >>> -5) + A;
      T = a + (b ^ c ^ d) + X10; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 12 | T >>> -12) + a;

      T = A + (B ^ (C | ~D)) + X9 + 0xA953FD4E; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 11 | T >>> -11) + A;
      T = a + (b ^ c ^ d) + X4; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 9 | T >>> -9) + a;

      T = A + (B ^ (C | ~D)) + X7 + 0xA953FD4E; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 6 | T >>> -6) + A;
      T = a + (b ^ c ^ d) + X1; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 12 | T >>> -12) + a;

      T = A + (B ^ (C | ~D)) + X12 + 0xA953FD4E; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 8 | T >>> -8) + A;
      T = a + (b ^ c ^ d) + X5; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 5 | T >>> -5) + a;

      T = A + (B ^ (C | ~D)) + X2 + 0xA953FD4E; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 13 | T >>> -13) + A;
      T = a + (b ^ c ^ d) + X8; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 14 | T >>> -14) + a;

      T = A + (B ^ (C | ~D)) + X10 + 0xA953FD4E; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 12 | T >>> -12) + A;
      T = a + (b ^ c ^ d) + X7; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 6 | T >>> -6) + a;

      T = A + (B ^ (C | ~D)) + X14 + 0xA953FD4E; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 5 | T >>> -5) + A;
      T = a + (b ^ c ^ d) + X6; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 8 | T >>> -8) + a;

      T = A + (B ^ (C | ~D)) + X1 + 0xA953FD4E; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 12 | T >>> -12) + A;
      T = a + (b ^ c ^ d) + X2; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 13 | T >>> -13) + a;

      T = A + (B ^ (C | ~D)) + X3 + 0xA953FD4E; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 13 | T >>> -13) + A;
      T = a + (b ^ c ^ d) + X13; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 6 | T >>> -6) + a;

      T = A + (B ^ (C | ~D)) + X8 + 0xA953FD4E; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 14 | T >>> -14) + A;
      T = a + (b ^ c ^ d) + X14; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 5 | T >>> -5) + a;

      T = A + (B ^ (C | ~D)) + X11 + 0xA953FD4E; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 11 | T >>> -11) + A;
      T = a + (b ^ c ^ d) + X0; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 15 | T >>> -15) + a;

      T = A + (B ^ (C | ~D)) + X6 + 0xA953FD4E; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 8 | T >>> -8) + A;
      T = a + (b ^ c ^ d) + X3; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 13 | T >>> -13) + a;

      T = A + (B ^ (C | ~D)) + X15 + 0xA953FD4E; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 5 | T >>> -5) + A;
      T = a + (b ^ c ^ d) + X9; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 11 | T >>> -11) + a;

      T = A + (B ^ (C | ~D)) + X13 + 0xA953FD4E; A = E; E = D; D = C << 10 | C >>> 22; C = B; B = (T << 6 | T >>> -6) + A;
      T = a + (b ^ c ^ d) + X11; a = e; e = d; d = c << 10 | c >>> 22; c = b; b = (T << 11 | T >>> -11) + a;

      T =  h1 + C + d; h1 = h2 + D + e; h2 = h3 + E + a; h3 = h4 + A + b; h4 = h0 + B + c; h0 = T;
   }

   protected byte[] padBuffer() {
      int n = (int)(count % BLOCK_SIZE);
      int padding = (n < 56) ? (56 - n) : (120 - n);
      byte[] result = new byte[padding + 8];

      // padding is always binary 1 followed by binary 0s
      result[0] = (byte) 0x80;

      // save number of bits, casting the long to an array of 8 bytes
      long bits = count << 3;
      result[padding++] = (byte) bits;
      result[padding++] = (byte)(bits >>>  8);
      result[padding++] = (byte)(bits >>> 16);
      result[padding++] = (byte)(bits >>> 24);
      result[padding++] = (byte)(bits >>> 32);
      result[padding++] = (byte)(bits >>> 40);
      result[padding++] = (byte)(bits >>> 48);
      result[padding  ] = (byte)(bits >>> 56);

      return result;
   }

   protected byte[] getResult() {
      byte[] result = new byte[] {
         (byte) h0, (byte)(h0 >>> 8), (byte)(h0 >>> 16), (byte)(h0 >>> 24),
         (byte) h1, (byte)(h1 >>> 8), (byte)(h1 >>> 16), (byte)(h1 >>> 24),
         (byte) h2, (byte)(h2 >>> 8), (byte)(h2 >>> 16), (byte)(h2 >>> 24),
         (byte) h3, (byte)(h3 >>> 8), (byte)(h3 >>> 16), (byte)(h3 >>> 24),
         (byte) h4, (byte)(h4 >>> 8), (byte)(h4 >>> 16), (byte)(h4 >>> 24)
      };

      return result;
   }

   protected void resetContext() {
      // magic RIPEMD160 initialisation constants
      h0 = 0x67452301;
      h1 = 0xEFCDAB89;
      h2 = 0x98BADCFE;
      h3 = 0x10325476;
      h4 = 0xC3D2E1F0;
   }

   public boolean selfTest() {
      if (valid == null) {
         valid = new Boolean(DIGEST0.equals(Util.toString(new RipeMD160().digest())));
      }
      return valid.booleanValue();
   }
}
