package gnu.crypto.hash;

// ----------------------------------------------------------------------------
// $Id: Sha160.java,v 1.2 2002/12/03 09:16:25 raif Exp $
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
 * <p>The Secure Hash Algorithm (SHA-1) is required for use with the Digital
 * Signature Algorithm (DSA) as specified in the Digital Signature Standard
 * (DSS) and whenever a secure hash algorithm is required for federal
 * applications. For a message of length less than 2^64 bits, the SHA-1
 * produces a 160-bit condensed representation of the message called a message
 * digest. The message digest is used during generation of a signature for the
 * message. The SHA-1 is also used to compute a message digest for the received
 * version of the message during the process of verifying the signature. Any
 * change to the message in transit will, with very high probability, result in
 * a different message digest, and the signature will fail to verify.</p>
 *
 * <p>The SHA-1 is designed to have the following properties: it is
 * computationally infeasible to find a message which corresponds to a given
 * message digest, or to find two different messages which produce the same
 * message digest.</p>
 *
 * <p>References:</p>
 *
 * <ol>
 *    <li><a href="http://www.itl.nist.gov/fipspubs/fip180-1.htm">SECURE HASH
 *    STANDARD</a><br>
 *    Federal Information, Processing Standards Publication 180-1, 1995 April 17.
 *    </li>
 * </ol>
 *
 * @version $Revision: 1.2 $
 */
public class Sha160 extends BaseHash {

   // Constants and variables
   // -------------------------------------------------------------------------

   private static final int BLOCK_SIZE = 64; // inner block size in bytes

   private static final String DIGEST0 = "A9993E364706816ABA3E25717850C26C9CD0D89D";

   /** work area. */
   private static final Block W = new Block();

   /** caches the result of the correctness test, once executed. */
   private static Boolean valid;

   /** 160-bit interim result. */
   private int h0, h1, h2, h3, h4;

   // Constructor(s)
   // -------------------------------------------------------------------------

   /** Trivial 0-arguments constructor. */
   public Sha160() {
      super(Registry.SHA160_HASH, 20, BLOCK_SIZE);
   }

   /**
    * <p>Private constructor for cloning purposes.</p>
    *
    * @param md the instance to clone.
    */
   private Sha160(Sha160 md) {
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

   public static final int[]
   G(int hh0, int hh1, int hh2, int hh3, int hh4, byte[] in, int offset) {
      return sha(hh0, hh1, hh2, hh3, hh4, in, offset);
   }

   // Instance methods
   // -------------------------------------------------------------------------

   // java.lang.Cloneable interface implementation ----------------------------

   public Object clone() {
      return new Sha160(this);
   }

   // Implementation of concrete methods in BaseHash --------------------------

   protected void transform(byte[] in, int offset) {
      int[] result = sha(h0, h1, h2, h3, h4, in, offset);

      h0 = result[0];
      h1 = result[1];
      h2 = result[2];
      h3 = result[3];
      h4 = result[4];
   }

   protected byte[] padBuffer() {
      int n = (int)(count % BLOCK_SIZE);
      int padding = (n < 56) ? (56 - n) : (120 - n);
      byte[] result = new byte[padding + 8];

      // padding is always binary 1 followed by binary 0s
      result[0] = (byte) 0x80;

      // save number of bits, casting the long to an array of 8 bytes
      long bits = count << 3;
      result[padding++] = (byte)(bits >>> 56);
      result[padding++] = (byte)(bits >>> 48);
      result[padding++] = (byte)(bits >>> 40);
      result[padding++] = (byte)(bits >>> 32);
      result[padding++] = (byte)(bits >>> 24);
      result[padding++] = (byte)(bits >>> 16);
      result[padding++] = (byte)(bits >>>  8);
      result[padding  ] = (byte) bits;

      return result;
   }

   protected byte[] getResult() {
      byte[] result = new byte[] {
         (byte)(h0 >>> 24), (byte)(h0 >>> 16), (byte)(h0 >>> 8), (byte) h0,
         (byte)(h1 >>> 24), (byte)(h1 >>> 16), (byte)(h1 >>> 8), (byte) h1,
         (byte)(h2 >>> 24), (byte)(h2 >>> 16), (byte)(h2 >>> 8), (byte) h2,
         (byte)(h3 >>> 24), (byte)(h3 >>> 16), (byte)(h3 >>> 8), (byte) h3,
         (byte)(h4 >>> 24), (byte)(h4 >>> 16), (byte)(h4 >>> 8), (byte) h4
      };

      return result;
   }

   protected void resetContext() {
      // magic SHA-1/RIPEMD160 initialisation constants
      h0 = 0x67452301;
      h1 = 0xEFCDAB89;
      h2 = 0x98BADCFE;
      h3 = 0x10325476;
      h4 = 0xC3D2E1F0;
   }

   public boolean selfTest() {
      if (valid == null) {
         Sha160 md = new Sha160();
         md.update((byte) 0x61); // a
         md.update((byte) 0x62); // b
         md.update((byte) 0x63); // c
         String result = Util.toString(md.digest());
         valid = new Boolean(DIGEST0.equals(result));
      }
      return valid.booleanValue();
   }

   // SHA specific methods ----------------------------------------------------

   private static final synchronized int[]
   sha(int hh0, int hh1, int hh2, int hh3, int hh4, byte[] in, int i) {
      int A = hh0, B = hh1, C = hh2, D = hh3, E = hh4, T;

      W.w0  = in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF);
      W.w1  = in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF);
      W.w2  = in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF);
      W.w3  = in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF);
      W.w4  = in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF);
      W.w5  = in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF);
      W.w6  = in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF);
      W.w7  = in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF);
      W.w8  = in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF);
      W.w9  = in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF);
      W.w10 = in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF);
      W.w11 = in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF);
      W.w12 = in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF);
      W.w13 = in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF);
      W.w14 = in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF);
      W.w15 = in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i  ] & 0xFF);

      T = W.w13 ^ W.w8  ^ W.w2  ^ W.w0 ; W.w16 = T << 1 | T >>> 31;
      T = W.w14 ^ W.w9  ^ W.w3  ^ W.w1 ; W.w17 = T << 1 | T >>> 31;
      T = W.w15 ^ W.w10 ^ W.w4  ^ W.w2 ; W.w18 = T << 1 | T >>> 31;
      T = W.w16 ^ W.w11 ^ W.w5  ^ W.w3 ; W.w19 = T << 1 | T >>> 31;
      T = W.w17 ^ W.w12 ^ W.w6  ^ W.w4 ; W.w20 = T << 1 | T >>> 31;
      T = W.w18 ^ W.w13 ^ W.w7  ^ W.w5 ; W.w21 = T << 1 | T >>> 31;
      T = W.w19 ^ W.w14 ^ W.w8  ^ W.w6 ; W.w22 = T << 1 | T >>> 31;
      T = W.w20 ^ W.w15 ^ W.w9  ^ W.w7 ; W.w23 = T << 1 | T >>> 31;
      T = W.w21 ^ W.w16 ^ W.w10 ^ W.w8 ; W.w24 = T << 1 | T >>> 31;
      T = W.w22 ^ W.w17 ^ W.w11 ^ W.w9 ; W.w25 = T << 1 | T >>> 31;
      T = W.w23 ^ W.w18 ^ W.w12 ^ W.w10; W.w26 = T << 1 | T >>> 31;
      T = W.w24 ^ W.w19 ^ W.w13 ^ W.w11; W.w27 = T << 1 | T >>> 31;
      T = W.w25 ^ W.w20 ^ W.w14 ^ W.w12; W.w28 = T << 1 | T >>> 31;
      T = W.w26 ^ W.w21 ^ W.w15 ^ W.w13; W.w29 = T << 1 | T >>> 31;
      T = W.w27 ^ W.w22 ^ W.w16 ^ W.w14; W.w30 = T << 1 | T >>> 31;
      T = W.w28 ^ W.w23 ^ W.w17 ^ W.w15; W.w31 = T << 1 | T >>> 31;
      T = W.w29 ^ W.w24 ^ W.w18 ^ W.w16; W.w32 = T << 1 | T >>> 31;
      T = W.w30 ^ W.w25 ^ W.w19 ^ W.w17; W.w33 = T << 1 | T >>> 31;
      T = W.w31 ^ W.w26 ^ W.w20 ^ W.w18; W.w34 = T << 1 | T >>> 31;
      T = W.w32 ^ W.w27 ^ W.w21 ^ W.w19; W.w35 = T << 1 | T >>> 31;
      T = W.w33 ^ W.w28 ^ W.w22 ^ W.w20; W.w36 = T << 1 | T >>> 31;
      T = W.w34 ^ W.w29 ^ W.w23 ^ W.w21; W.w37 = T << 1 | T >>> 31;
      T = W.w35 ^ W.w30 ^ W.w24 ^ W.w22; W.w38 = T << 1 | T >>> 31;
      T = W.w36 ^ W.w31 ^ W.w25 ^ W.w23; W.w39 = T << 1 | T >>> 31;
      T = W.w37 ^ W.w32 ^ W.w26 ^ W.w24; W.w40 = T << 1 | T >>> 31;
      T = W.w38 ^ W.w33 ^ W.w27 ^ W.w25; W.w41 = T << 1 | T >>> 31;
      T = W.w39 ^ W.w34 ^ W.w28 ^ W.w26; W.w42 = T << 1 | T >>> 31;
      T = W.w40 ^ W.w35 ^ W.w29 ^ W.w27; W.w43 = T << 1 | T >>> 31;
      T = W.w41 ^ W.w36 ^ W.w30 ^ W.w28; W.w44 = T << 1 | T >>> 31;
      T = W.w42 ^ W.w37 ^ W.w31 ^ W.w29; W.w45 = T << 1 | T >>> 31;
      T = W.w43 ^ W.w38 ^ W.w32 ^ W.w30; W.w46 = T << 1 | T >>> 31;
      T = W.w44 ^ W.w39 ^ W.w33 ^ W.w31; W.w47 = T << 1 | T >>> 31;
      T = W.w45 ^ W.w40 ^ W.w34 ^ W.w32; W.w48 = T << 1 | T >>> 31;
      T = W.w46 ^ W.w41 ^ W.w35 ^ W.w33; W.w49 = T << 1 | T >>> 31;
      T = W.w47 ^ W.w42 ^ W.w36 ^ W.w34; W.w50 = T << 1 | T >>> 31;
      T = W.w48 ^ W.w43 ^ W.w37 ^ W.w35; W.w51 = T << 1 | T >>> 31;
      T = W.w49 ^ W.w44 ^ W.w38 ^ W.w36; W.w52 = T << 1 | T >>> 31;
      T = W.w50 ^ W.w45 ^ W.w39 ^ W.w37; W.w53 = T << 1 | T >>> 31;
      T = W.w51 ^ W.w46 ^ W.w40 ^ W.w38; W.w54 = T << 1 | T >>> 31;
      T = W.w52 ^ W.w47 ^ W.w41 ^ W.w39; W.w55 = T << 1 | T >>> 31;
      T = W.w53 ^ W.w48 ^ W.w42 ^ W.w40; W.w56 = T << 1 | T >>> 31;
      T = W.w54 ^ W.w49 ^ W.w43 ^ W.w41; W.w57 = T << 1 | T >>> 31;
      T = W.w55 ^ W.w50 ^ W.w44 ^ W.w42; W.w58 = T << 1 | T >>> 31;
      T = W.w56 ^ W.w51 ^ W.w45 ^ W.w43; W.w59 = T << 1 | T >>> 31;
      T = W.w57 ^ W.w52 ^ W.w46 ^ W.w44; W.w60 = T << 1 | T >>> 31;
      T = W.w58 ^ W.w53 ^ W.w47 ^ W.w45; W.w61 = T << 1 | T >>> 31;
      T = W.w59 ^ W.w54 ^ W.w48 ^ W.w46; W.w62 = T << 1 | T >>> 31;
      T = W.w60 ^ W.w55 ^ W.w49 ^ W.w47; W.w63 = T << 1 | T >>> 31;
      T = W.w61 ^ W.w56 ^ W.w50 ^ W.w48; W.w64 = T << 1 | T >>> 31;
      T = W.w62 ^ W.w57 ^ W.w51 ^ W.w49; W.w65 = T << 1 | T >>> 31;
      T = W.w63 ^ W.w58 ^ W.w52 ^ W.w50; W.w66 = T << 1 | T >>> 31;
      T = W.w64 ^ W.w59 ^ W.w53 ^ W.w51; W.w67 = T << 1 | T >>> 31;
      T = W.w65 ^ W.w60 ^ W.w54 ^ W.w52; W.w68 = T << 1 | T >>> 31;
      T = W.w66 ^ W.w61 ^ W.w55 ^ W.w53; W.w69 = T << 1 | T >>> 31;
      T = W.w67 ^ W.w62 ^ W.w56 ^ W.w54; W.w70 = T << 1 | T >>> 31;
      T = W.w68 ^ W.w63 ^ W.w57 ^ W.w55; W.w71 = T << 1 | T >>> 31;
      T = W.w69 ^ W.w64 ^ W.w58 ^ W.w56; W.w72 = T << 1 | T >>> 31;
      T = W.w70 ^ W.w65 ^ W.w59 ^ W.w57; W.w73 = T << 1 | T >>> 31;
      T = W.w71 ^ W.w66 ^ W.w60 ^ W.w58; W.w74 = T << 1 | T >>> 31;
      T = W.w72 ^ W.w67 ^ W.w61 ^ W.w59; W.w75 = T << 1 | T >>> 31;
      T = W.w73 ^ W.w68 ^ W.w62 ^ W.w60; W.w76 = T << 1 | T >>> 31;
      T = W.w74 ^ W.w69 ^ W.w63 ^ W.w61; W.w77 = T << 1 | T >>> 31;
      T = W.w75 ^ W.w70 ^ W.w64 ^ W.w62; W.w78 = T << 1 | T >>> 31;
      T = W.w76 ^ W.w71 ^ W.w65 ^ W.w63; W.w79 = T << 1 | T >>> 31;

      // rounds 0-19
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w0  + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w1  + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w2  + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w3  + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w4  + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w5  + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w6  + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w7  + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w8  + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w9  + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w10 + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w11 + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w12 + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w13 + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w14 + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w15 + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w16 + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w17 + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w18 + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + ((B & C) | (~B & D)) + E + W.w19 + 0x5A827999;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;

      // rounds 20-39
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w20 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w21 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w22 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w23 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w24 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w25 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w26 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w27 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w28 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w29 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w30 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w31 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w32 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w33 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w34 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w35 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w36 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w37 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w38 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w39 + 0x6ED9EBA1;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;

      // rounds 40-59
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w40 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w41 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w42 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w43 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w44 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w45 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w46 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w47 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w48 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w49 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w50 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w51 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w52 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w53 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w54 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w55 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w56 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w57 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w58 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B & C | B & D | C & D) + E + W.w59 + 0x8F1BBCDC;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;

      // rounds 60-79
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w60 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w61 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w62 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w63 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w64 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w65 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w66 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w67 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w68 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w69 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w70 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w71 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w72 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w73 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w74 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w75 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w76 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w77 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w78 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;
      T = (A << 5 | A >>> 27) + (B ^ C ^ D) + E + W.w79 + 0xCA62C1D6;
      E = D; D = C; C = B << 30 | B >>> 2; B = A; A = T;

      return new int[] { hh0+A, hh1+B, hh2+C, hh3+D, hh4+E };
   }

   // Inner class(es)
   // =========================================================================

   /** A trivial class to eliminate array index range-checking at runtime. */
   private static class Block {
      int w0,  w1,  w2,  w3,  w4,  w5,  w6,  w7,  w8,  w9,  w10, w11, w12, w13, w14, w15,
          w16, w17, w18, w19, w20, w21, w22, w23, w24, w25, w26, w27, w28, w29, w30, w31,
          w32, w33, w34, w35, w36, w37, w38, w39, w40, w41, w42, w43, w44, w45, w46, w47,
          w48, w49, w50, w51, w52, w53, w54, w55, w56, w57, w58, w59, w60, w61, w62, w63,
          w64, w65, w66, w67, w68, w69, w70, w71, w72, w73, w74, w75, w76, w77, w78, w79;
   }
}
