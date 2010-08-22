package gnu.crypto.cipher;

// ----------------------------------------------------------------------------
// $Id: Square.java,v 1.1 2002/11/29 12:00:44 raif Exp $
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

import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;

/**
 * <p>Square is a 128-bit key, 128-bit block cipher algorithm developed by Joan
 * Daemen, Lars Knudsen and Vincent Rijmen.</p>
 *
 * <p>References:</p>
 *
 * <ol>
 *    <li><a href="http://www.esat.kuleuven.ac.be/~rijmen/square/">The block
 *    cipher Square</a>.<br>
 *    <a href="mailto:daemen.j@protonworld.com">Joan Daemen</a>,
 *    <a href="mailto:lars.knudsen@esat.kuleuven.ac.be">Lars Knudsen</a> and
 *    <a href="mailto:vincent.rijmen@esat.kuleuven.ac.be">Vincent Rijmen</a>.</li>
 * </ol>
 *
 * @version $Revision: 1.1 $
 */
public final class Square extends BaseCipher {

   // Constants and variables
   // -------------------------------------------------------------------------

   private static final int DEFAULT_BLOCK_SIZE = 16; // in bytes
   private static final int DEFAULT_KEY_SIZE = 16; // in bytes

   private static final int ROUNDS = 8;
   private static final int ROOT = 0x1F5; // for generating GF(2**8)
   private static final int[] OFFSET = new int[ROUNDS];

   private static final String Sdata =
      "\uB1CE\uC395\u5AAD\uE702\u4D44\uFB91\u0C87\uA150"+
      "\uCB67\u54DD\u468F\uE14E\uF0FD\uFCEB\uF9C4\u1A6E"+
      "\u5EF5\uCC8D\u1C56\u43FE\u0761\uF875\u59FF\u0322"+
      "\u8AD1\u13EE\u8800\u0E34\u1580\u94E3\uEDB5\u5323"+
      "\u4B47\u17A7\u9035\uABD8\uB8DF\u4F57\u9A92\uDB1B"+
      "\u3CC8\u9904\u8EE0\uD77D\u85BB\u402C\u3A45\uF142"+
      "\u6520\u4118\u7225\u9370\u3605\uF20B\uA379\uEC08"+
      "\u2731\u32B6\u7CB0\u0A73\u5B7B\uB781\uD20D\u6A26"+
      "\u9E58\u9C83\u74B3\uAC30\u7A69\u770F\uAE21\uDED0"+
      "\u2E97\u10A4\u98A8\uD468\u2D62\u296D\u1649\u76C7"+
      "\uE8C1\u9637\uE5CA\uF4E9\u6312\uC2A6\u14BC\uD328"+
      "\uAF2F\uE624\u52C6\uA009\uBD8C\uCF5D\u115F\u01C5"+
      "\u9F3D\uA29B\uC93B\uBE51\u191F\u3F5C\uB2EF\u4ACD"+
      "\uBFBA\u6F64\uD9F3\u3EB4\uAADC\uD506\uC07E\uF666"+
      "\u6C84\u7138\uB91D\u7F9D\u488B\u2ADA\uA533\u8239"+
      "\uD678\u86FA\uE42B\uA91E\u8960\u6BEA\u554C\uF7E2";

   /** Substitution boxes for encryption and decryption. */
   private static final byte[] Se = new byte[256];
   private static final byte[] Sd = new byte[256];

   /** Transposition boxes for encryption and decryption. */
   private static final int[] Te = new int[256];
   private static final int[] Td = new int[256];

   /**
    * KAT vector (from ecb_vk):
    * I=87
    * KEY=00000000000000000000020000000000
    * CT=A9DF031B4E25E89F527EFFF89CB0BEBA
    */
   private static final byte[] KAT_KEY =
         Util.toBytesFromString("00000000000000000000020000000000");
   private static final byte[] KAT_CT =
         Util.toBytesFromString("A9DF031B4E25E89F527EFFF89CB0BEBA");

   /** caches the result of the correctness test, once executed. */
   private static Boolean valid;

   // Static code - to initialise lookup tables -------------------------------

   static {
      int i, j;

      // re-construct Se box values
      int limit = Sdata.length();
      char c1;
      for (i = 0, j = 0; i < limit; i++) {
         c1 = Sdata.charAt(i);
         Se[j++] = (byte)(c1 >>> 8);
         Se[j++] = (byte) c1;
      }

      // compute Sd box values
      for (i = 0; i < 256; i++) {
         Sd[Se[i] & 0xFF] = (byte) i;
      }

      // generate OFFSET values
      OFFSET[0] = 1;
      for (i = 1; i < ROUNDS; i++) {
         OFFSET[i] = mul(OFFSET[i - 1], 2);
         OFFSET[i - 1] <<= 24;
      }

      OFFSET[ROUNDS - 1] <<= 24;

      // generate Te and Td boxes if we're not reading their values
      // Notes:
      // (1) The function mul() computes the product of two elements of GF(2**8)
      // with ROOT as reduction polynomial.
      // (2) the values used in computing the Te and Td are the GF(2**8)
      // coefficients of the diffusion polynomial c(x) and its inverse
      // (modulo x**4 + 1) d(x), defined in sections 2.1 and 4 of the Square
      // paper.
      for (i = 0; i < 256; i++) {
         j = Se[i] & 0xFF;
         Te[i] = (Se[i & 3] == 0)
            ? 0 : mul(j, 2) << 24 | j << 16 | j << 8 | mul(j, 3);

         j = Sd[i] & 0xFF;
         Td[i] = (Sd[i & 3] == 0)
            ? 0 : mul(j, 14) << 24 | mul(j, 9) << 16 | mul(j, 13) << 8 | mul(j, 11);
      }
   }

   // Constructor(s)
   // -------------------------------------------------------------------------

   /** Trivial 0-arguments constructor. */
   public Square() {
      super(Registry.SQUARE_CIPHER, DEFAULT_BLOCK_SIZE, DEFAULT_KEY_SIZE);
   }

   // Class methods
   // -------------------------------------------------------------------------

   private static final void
   square(byte[] in, int i, byte[] out, int j, int[][] K, int[] T, byte[] S) {
      int a, b, c, d;
      a = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K[0][0];
      b = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K[0][1];
      c = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K[0][2];
      d = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i  ] & 0xFF)) ^ K[0][3];

      int aa, bb, cc, tb, tc, td;

      // R - 1 full rounds
      tb = T[b >>> 24]; tc = T[c >>> 24]; td = T[d >>> 24];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      aa = T[a >>> 24] ^ tb ^ tc ^ td ^ K[1][0];
      tb = T[(b >>> 16) & 0xFF]; tc = T[(c >>> 16) & 0xFF]; td = T[(d >>> 16) & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      bb = T[(a >>> 16) & 0xFF] ^ tb ^ tc ^ td ^ K[1][1];
      tb = T[(b >>> 8) & 0xFF]; tc = T[(c >>> 8) & 0xFF]; td = T[(d >>> 8) & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      cc = T[(a >>> 8) & 0xFF] ^ tb ^ tc ^ td ^ K[1][2];
      tb = T[b & 0xFF]; tc = T[c & 0xFF]; td = T[d & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      d = T[a & 0xFF] ^ tb ^ tc ^ td ^ K[1][3];
      a = aa; b = bb; c = cc;

      tb = T[b >>> 24]; tc = T[c >>> 24]; td = T[d >>> 24];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      aa = T[a >>> 24] ^ tb ^ tc ^ td ^ K[2][0];
      tb = T[(b >>> 16) & 0xFF]; tc = T[(c >>> 16) & 0xFF]; td = T[(d >>> 16) & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      bb = T[(a >>> 16) & 0xFF] ^ tb ^ tc ^ td ^ K[2][1];
      tb = T[(b >>> 8) & 0xFF]; tc = T[(c >>> 8) & 0xFF]; td = T[(d >>> 8) & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      cc = T[(a >>> 8) & 0xFF] ^ tb ^ tc ^ td ^ K[2][2];
      tb = T[b & 0xFF]; tc = T[c & 0xFF]; td = T[d & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      d = T[a & 0xFF] ^ tb ^ tc ^ td ^ K[2][3];
      a = aa; b = bb; c = cc;

      tb = T[b >>> 24]; tc = T[c >>> 24]; td = T[d >>> 24];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      aa = T[a >>> 24] ^ tb ^ tc ^ td ^ K[3][0];
      tb = T[(b >>> 16) & 0xFF]; tc = T[(c >>> 16) & 0xFF]; td = T[(d >>> 16) & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      bb = T[(a >>> 16) & 0xFF] ^ tb ^ tc ^ td ^ K[3][1];
      tb = T[(b >>> 8) & 0xFF]; tc = T[(c >>> 8) & 0xFF]; td = T[(d >>> 8) & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      cc = T[(a >>> 8) & 0xFF] ^ tb ^ tc ^ td ^ K[3][2];
      tb = T[b & 0xFF]; tc = T[c & 0xFF]; td = T[d & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      d = T[a & 0xFF] ^ tb ^ tc ^ td ^ K[3][3];
      a = aa; b = bb; c = cc;

      tb = T[b >>> 24]; tc = T[c >>> 24]; td = T[d >>> 24];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      aa = T[a >>> 24] ^ tb ^ tc ^ td ^ K[4][0];
      tb = T[(b >>> 16) & 0xFF]; tc = T[(c >>> 16) & 0xFF]; td = T[(d >>> 16) & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      bb = T[(a >>> 16) & 0xFF] ^ tb ^ tc ^ td ^ K[4][1];
      tb = T[(b >>> 8) & 0xFF]; tc = T[(c >>> 8) & 0xFF]; td = T[(d >>> 8) & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      cc = T[(a >>> 8) & 0xFF] ^ tb ^ tc ^ td ^ K[4][2];
      tb = T[b & 0xFF]; tc = T[c & 0xFF]; td = T[d & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      d = T[a & 0xFF] ^ tb ^ tc ^ td ^ K[4][3];
      a = aa; b = bb; c = cc;

      tb = T[b >>> 24]; tc = T[c >>> 24]; td = T[d >>> 24];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      aa = T[a >>> 24] ^ tb ^ tc ^ td ^ K[5][0];
      tb = T[(b >>> 16) & 0xFF]; tc = T[(c >>> 16) & 0xFF]; td = T[(d >>> 16) & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      bb = T[(a >>> 16) & 0xFF] ^ tb ^ tc ^ td ^ K[5][1];
      tb = T[(b >>> 8) & 0xFF]; tc = T[(c >>> 8) & 0xFF]; td = T[(d >>> 8) & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      cc = T[(a >>> 8) & 0xFF] ^ tb ^ tc ^ td ^ K[5][2];
      tb = T[b & 0xFF]; tc = T[c & 0xFF]; td = T[d & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      d = T[a & 0xFF] ^ tb ^ tc ^ td ^ K[5][3];
      a = aa; b = bb; c = cc;

      tb = T[b >>> 24]; tc = T[c >>> 24]; td = T[d >>> 24];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      aa = T[a >>> 24] ^ tb ^ tc ^ td ^ K[6][0];
      tb = T[(b >>> 16) & 0xFF]; tc = T[(c >>> 16) & 0xFF]; td = T[(d >>> 16) & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      bb = T[(a >>> 16) & 0xFF] ^ tb ^ tc ^ td ^ K[6][1];
      tb = T[(b >>> 8) & 0xFF]; tc = T[(c >>> 8) & 0xFF]; td = T[(d >>> 8) & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      cc = T[(a >>> 8) & 0xFF] ^ tb ^ tc ^ td ^ K[6][2];
      tb = T[b & 0xFF]; tc = T[c & 0xFF]; td = T[d & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      d = T[a & 0xFF] ^ tb ^ tc ^ td ^ K[6][3];
      a = aa; b = bb; c = cc;

      tb = T[b >>> 24]; tc = T[c >>> 24]; td = T[d >>> 24];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      aa = T[a >>> 24] ^ tb ^ tc ^ td ^ K[7][0];
      tb = T[(b >>> 16) & 0xFF]; tc = T[(c >>> 16) & 0xFF]; td = T[(d >>> 16) & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      bb = T[(a >>> 16) & 0xFF] ^ tb ^ tc ^ td ^ K[7][1];
      tb = T[(b >>> 8) & 0xFF]; tc = T[(c >>> 8) & 0xFF]; td = T[(d >>> 8) & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      cc = T[(a >>> 8) & 0xFF] ^ tb ^ tc ^ td ^ K[7][2];
      tb = T[b & 0xFF]; tc = T[c & 0xFF]; td = T[d & 0xFF];
      tb = tb >>> 8 | tb << 24; tc = tc >>> 16 | tc << 16; td = td >>> 24 | td << 8;
      d = T[a & 0xFF] ^ tb ^ tc ^ td ^ K[7][3];
      a = aa; b = bb; c = cc;

      // last round (diffusion becomes only transposition)
      aa = ( S[ a >>> 24        ]         << 24 |
            (S[ b >>> 24        ] & 0xFF) << 16 |
            (S[ c >>> 24        ] & 0xFF) <<  8 |
            (S[ d >>> 24        ] & 0xFF)       ) ^ K[ROUNDS][0];
      bb = ( S[(a >>> 16) & 0xFF]         << 24 |
            (S[(b >>> 16) & 0xFF] & 0xFF) << 16 |
            (S[(c >>> 16) & 0xFF] & 0xFF) <<  8 |
            (S[(d >>> 16) & 0xFF] & 0xFF)       ) ^ K[ROUNDS][1];
      cc = ( S[(a >>>  8) & 0xFF]         << 24 |
            (S[(b >>>  8) & 0xFF] & 0xFF) << 16 |
            (S[(c >>>  8) & 0xFF] & 0xFF) <<  8 |
            (S[(d >>>  8) & 0xFF] & 0xFF)       ) ^ K[ROUNDS][2];
      d  = ( S[ a         & 0xFF]         << 24 |
            (S[ b         & 0xFF] & 0xFF) << 16 |
            (S[ c         & 0xFF] & 0xFF) <<  8 |
            (S[ d         & 0xFF] & 0xFF)       ) ^ K[ROUNDS][3];

      out[j++] = (byte)(aa >>> 24);
      out[j++] = (byte)(aa >>> 16);
      out[j++] = (byte)(aa >>>  8);
      out[j++] = (byte) aa;
      out[j++] = (byte)(bb >>> 24);
      out[j++] = (byte)(bb >>> 16);
      out[j++] = (byte)(bb >>>  8);
      out[j++] = (byte) bb;
      out[j++] = (byte)(cc >>> 24);
      out[j++] = (byte)(cc >>> 16);
      out[j++] = (byte)(cc >>>  8);
      out[j++] = (byte) cc;
      out[j++] = (byte)(d  >>> 24);
      out[j++] = (byte)(d  >>> 16);
      out[j++] = (byte)(d  >>>  8);
      out[j  ] = (byte) d;
   }

   /**
    * <p>Applies the Theta function to an input <i>in</i> in order to produce in
    * <i>out</i> an internal session sub-key.</p>
    *
    * <p>Both <i>in</i> and <i>out</i> are arrays of four ints.</p>
    *
    * <p>Pseudo-code is:</p>
    * <pre>
    *    for (i = 0; i < 4; i++) {
    *       out[i] = 0;
    *       for (j = 0, n = 24; j < 4; j++, n -= 8) {
    *          k = mul(in[i] >>> 24, G[0][j]) ^
    *              mul(in[i] >>> 16, G[1][j]) ^
    *              mul(in[i] >>>  8, G[2][j]) ^
    *              mul(in[i]       , G[3][j]);
    *          out[i] ^= k << n;
    *       }
    *    }
    * </pre>
    */
   private static final void transform(int a, int b, int c, int d, int[] out) {
      int l3, l2, l1, l0;

      l3 = a; l2 = l3 >>> 8; l1 = l3 >>> 16; l0 = l3 >>> 24;
      out[0] = (mul(l0, 2) ^ mul(l1, 3) ^ l2         ^ l3        )         << 24 |
              ((l0         ^ mul(l1, 2) ^ mul(l2, 3) ^ l3        ) & 0xFF) << 16 |
              ((l0         ^ l1         ^ mul(l2, 2) ^ mul(l3, 3)) & 0xFF) <<  8 |
              ((mul(l0, 3) ^ l1         ^ l2         ^ mul(l3, 2)) & 0xFF);

      l3 = b; l2 = l3 >>> 8; l1 = l3 >>> 16; l0 = l3 >>> 24;
      out[1] = (mul(l0, 2) ^ mul(l1, 3) ^ l2         ^ l3        )         << 24 |
              ((l0         ^ mul(l1, 2) ^ mul(l2, 3) ^ l3        ) & 0xFF) << 16 |
              ((l0         ^ l1         ^ mul(l2, 2) ^ mul(l3, 3)) & 0xFF) <<  8 |
              ((mul(l0, 3) ^ l1         ^ l2         ^ mul(l3, 2)) & 0xFF);

      l3 = c; l2 = l3 >>> 8; l1 = l3 >>> 16; l0 = l3 >>> 24;
      out[2] = (mul(l0, 2) ^ mul(l1, 3) ^ l2         ^ l3        )         << 24 |
              ((l0         ^ mul(l1, 2) ^ mul(l2, 3) ^ l3        ) & 0xFF) << 16 |
              ((l0         ^ l1         ^ mul(l2, 2) ^ mul(l3, 3)) & 0xFF) <<  8 |
              ((mul(l0, 3) ^ l1         ^ l2         ^ mul(l3, 2)) & 0xFF);

      l3 = d; l2 = l3 >>> 8; l1 = l3 >>> 16; l0 = l3 >>> 24;
      out[3] = (mul(l0, 2) ^ mul(l1, 3) ^ l2         ^ l3        )         << 24 |
              ((l0         ^ mul(l1, 2) ^ mul(l2, 3) ^ l3        ) & 0xFF) << 16 |
              ((l0         ^ l1         ^ mul(l2, 2) ^ mul(l3, 3)) & 0xFF) <<  8 |
              ((mul(l0, 3) ^ l1         ^ l2         ^ mul(l3, 2)) & 0xFF);
   }

   /**
    * <p>Returns the product of two binary numbers a and b, using the generator
    * ROOT as the modulus: p = (a * b) mod ROOT. ROOT Generates a suitable
    * Galois Field in GF(2**8).</p>
    *
    * <p>For best performance call it with abs(b) &lt; abs(a).</p>
    *
    * @param a operand for multiply.
    * @param b operand for multiply.
    * @return the result of (a * b) % ROOT.
    */
   private static final int mul(int a, int b) {
      if (a == 0) {
         return 0;
      }
      a &= 0xFF;
      b &= 0xFF;
      int result = 0;
      while (b != 0) {
         if ((b & 0x01) != 0) {
            result ^= a;
         }
         b >>>= 1;
         a <<= 1;
         if (a > 0xFF) {
            a ^= ROOT;
         }
      }
      return result & 0xFF;
   }

   // Instance methods
   // -------------------------------------------------------------------------

   // java.lang.Cloneable interface implementation ----------------------------

   public Object clone() {
      Square result = new Square();
      result.currentBlockSize = this.currentBlockSize;

      return result;
   }

   // IBlockCipherSpi interface implementation --------------------------------

   public Iterator blockSizes() {
      ArrayList al = new ArrayList();
      al.add(new Integer(DEFAULT_BLOCK_SIZE));

      return Collections.unmodifiableList(al).iterator();
   }

   public Iterator keySizes() {
      ArrayList al = new ArrayList();
      al.add(new Integer(DEFAULT_KEY_SIZE));

      return Collections.unmodifiableList(al).iterator();
   }

   public Object makeKey(byte[] uk, int bs) throws InvalidKeyException {
      if (bs != DEFAULT_BLOCK_SIZE) {
         throw new IllegalArgumentException();
      }
      if (uk == null) {
         throw new InvalidKeyException("Empty key");
      }
      if (uk.length != DEFAULT_KEY_SIZE) {
         throw new InvalidKeyException("Key is not 128-bit.");
      }

      int[][] Ke = new int[ROUNDS + 1][4];
      int[][] Kd = new int[ROUNDS + 1][4];
      int t00, t01, t02, t03;
      int t10, t11, t12, t13;

      t00 = Ke[0][0] = uk[ 0] << 24 | (uk[ 1] & 0xFF) << 16 | (uk[ 2] & 0xFF) << 8 | (uk[ 3] & 0xFF);
      t01 = Ke[0][1] = uk[ 4] << 24 | (uk[ 5] & 0xFF) << 16 | (uk[ 6] & 0xFF) << 8 | (uk[ 7] & 0xFF);
      t02 = Ke[0][2] = uk[ 8] << 24 | (uk[ 9] & 0xFF) << 16 | (uk[10] & 0xFF) << 8 | (uk[11] & 0xFF);
      t03 = Ke[0][3] = uk[12] << 24 | (uk[13] & 0xFF) << 16 | (uk[14] & 0xFF) << 8 | (uk[15] & 0xFF);
      transform(t00, t01, t02, t03, Kd[ROUNDS]);

      // i = 1, j = 0
      Kd[7][0] = Ke[1][0] = t10 = t00 ^ (t03 << 8 | t03 >>> 24) ^ OFFSET[0];
      Kd[7][1] = Ke[1][1] = t11 = t01 ^ t10;
      Kd[7][2] = Ke[1][2] = t12 = t02 ^ t11;
      Kd[7][3] = Ke[1][3] = t13 = t03 ^ t12;
      transform(t00, t01, t02, t03, Ke[0]);
      // i = 2, j = 1
      Kd[6][0] = Ke[2][0] = t00 = t10 ^ (t13 << 8 | t13 >>> 24) ^ OFFSET[1];
      Kd[6][1] = Ke[2][1] = t01 = t11 ^ t00;
      Kd[6][2] = Ke[2][2] = t02 = t12 ^ t01;
      Kd[6][3] = Ke[2][3] = t03 = t13 ^ t02;
      transform(t10, t11, t12, t13, Ke[1]);
      // i = 3, j = 2
      Kd[5][0] = Ke[3][0] = t10 = t00 ^ (t03 << 8 | t03 >>> 24) ^ OFFSET[2];
      Kd[5][1] = Ke[3][1] = t11 = t01 ^ t10;
      Kd[5][2] = Ke[3][2] = t12 = t02 ^ t11;
      Kd[5][3] = Ke[3][3] = t13 = t03 ^ t12;
      transform(t00, t01, t02, t03, Ke[2]);
      // i = 4, j = 3
      Kd[4][0] = Ke[4][0] = t00 = t10 ^ (t13 << 8 | t13 >>> 24) ^ OFFSET[3];
      Kd[4][1] = Ke[4][1] = t01 = t11 ^ t00;
      Kd[4][2] = Ke[4][2] = t02 = t12 ^ t01;
      Kd[4][3] = Ke[4][3] = t03 = t13 ^ t02;
      transform(t10, t11, t12, t13, Ke[3]);
      // i = 5, j = 4
      Kd[3][0] = Ke[5][0] = t10 = t00 ^ (t03 << 8 | t03 >>> 24) ^ OFFSET[4];
      Kd[3][1] = Ke[5][1] = t11 = t01 ^ t10;
      Kd[3][2] = Ke[5][2] = t12 = t02 ^ t11;
      Kd[3][3] = Ke[5][3] = t13 = t03 ^ t12;
      transform(t00, t01, t02, t03, Ke[4]);
      // i = 6, j = 5
      Kd[2][0] = Ke[6][0] = t00 = t10 ^ (t13 << 8 | t13 >>> 24) ^ OFFSET[5];
      Kd[2][1] = Ke[6][1] = t01 = t11 ^ t00;
      Kd[2][2] = Ke[6][2] = t02 = t12 ^ t01;
      Kd[2][3] = Ke[6][3] = t03 = t13 ^ t02;
      transform(t10, t11, t12, t13, Ke[5]);
      // i = 7, j = 6
      Kd[1][0] = Ke[7][0] = t10 = t00 ^ (t03 << 8 | t03 >>> 24) ^ OFFSET[6];
      Kd[1][1] = Ke[7][1] = t11 = t01 ^ t10;
      Kd[1][2] = Ke[7][2] = t12 = t02 ^ t11;
      Kd[1][3] = Ke[7][3] = t13 = t03 ^ t12;
      transform(t00, t01, t02, t03, Ke[6]);
      // i = 8, j = 7
      Kd[0][0] = Ke[8][0] = t00 = t10 ^ (t13 << 8 | t13 >>> 24) ^ OFFSET[7];
      Kd[0][1] = Ke[8][1] = t01 = t11 ^ t00;
      Kd[0][2] = Ke[8][2] = t02 = t12 ^ t01;
      Kd[0][3] = Ke[8][3] = t03 = t13 ^ t02;
      transform(t10, t11, t12, t13, Ke[7]);

      return new Object[] {Ke, Kd};
   }

   public void encrypt(byte[] in, int i, byte[] out, int j, Object k, int bs) {
      if (bs != DEFAULT_BLOCK_SIZE) {
         throw new IllegalArgumentException();
      }

      int[][] K = (int[][])((Object[]) k)[0];
      square(in, i, out, j, K, Te, Se);
   }

   public void decrypt(byte[] in, int i, byte[] out, int j, Object k, int bs) {
      if (bs != DEFAULT_BLOCK_SIZE) {
         throw new IllegalArgumentException();
      }

      int[][] K = (int[][])((Object[]) k)[1];
      square(in, i, out, j, K, Td, Sd);
   }

   public boolean selfTest() {
      if (valid == null) {
         boolean result = super.selfTest(); // do symmetry tests
         if (result) {
            result = testKat(KAT_KEY, KAT_CT);
         }
         valid = new Boolean(result);
      }
      return valid.booleanValue();
   }
}
