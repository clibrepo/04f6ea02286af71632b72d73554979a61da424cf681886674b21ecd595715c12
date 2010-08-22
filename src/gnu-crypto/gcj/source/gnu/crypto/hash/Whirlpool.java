package gnu.crypto.hash;

// ----------------------------------------------------------------------------
// $Id: Whirlpool.java,v 1.1 2002/12/10 13:07:32 raif Exp $
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
 * <p>Whirlpool, a new 512-bit hashing function operating on messages less than
 * 2 ** 256 bits in length. The function structure is designed according to the
 * Wide Trail strategy and permits a wide variety of implementation trade-offs.
 * </p>
 *
 * <p><b>IMPORTANT</b>: This implementation is not thread-safe.</p>
 *
 * <p>References:</p>
 *
 * <ol>
 *    <li><a href="http://planeta.terra.com.br/informatica/paulobarreto/WhirlpoolPage.html">
 *    The WHIRLPOOL Hashing Function</a>.<br>
 *    <a href="mailto:paulo.barreto@terra.com.br">Paulo S.L.M. Barreto</a> and
 *    <a href="mailto:vincent.rijmen@esat.kuleuven.ac.be">Vincent Rijmen</a>.</li>
 * </ol>
 *
 * @version $Revision: 1.1 $
 */
public final class Whirlpool extends BaseHash {

   // Debugging methods and variables
   // -------------------------------------------------------------------------

   private static final boolean DEBUG = false;
   private static final int debuglevel = 3;

   // Constants and variables
   // -------------------------------------------------------------------------

   private static final int BLOCK_SIZE = 64; // inner block size in bytes

   /** The digest of the 0-bit long message. */
   private static final String DIGEST0 =
         "470F0409ABAA446E49667D4EBE12A14387CEDBD10DD17B8243CAD550A089DC0F"+
         "EEA7AA40F6C2AAAB71C6EBD076E43C7CFCA0AD32567897DCB5969861049A0F5A";

   private static final int R = 10; // default number of rounds

   private static final String Sd = // p. 19 [WHIRLPOOL]
         "\u1823\uc6E8\u87B8\u014F\u36A6\ud2F5\u796F\u9152"+
         "\u60Bc\u9B8E\uA30c\u7B35\u1dE0\ud7c2\u2E4B\uFE57"+
         "\u1577\u37E5\u9FF0\u4AdA\u58c9\u290A\uB1A0\u6B85"+
         "\uBd5d\u10F4\ucB3E\u0567\uE427\u418B\uA77d\u95d8"+
         "\uFBEE\u7c66\udd17\u479E\ucA2d\uBF07\uAd5A\u8333"+
         "\u6302\uAA71\uc819\u49d9\uF2E3\u5B88\u9A26\u32B0"+
         "\uE90F\ud580\uBEcd\u3448\uFF7A\u905F\u2068\u1AAE"+
         "\uB454\u9322\u64F1\u7312\u4008\uc3Ec\udBA1\u8d3d"+
         "\u9700\ucF2B\u7682\ud61B\uB5AF\u6A50\u45F3\u30EF"+
         "\u3F55\uA2EA\u65BA\u2Fc0\udE1c\uFd4d\u9275\u068A"+
         "\uB2E6\u0E1F\u62d4\uA896\uF9c5\u2559\u8472\u394c"+
         "\u5E78\u388c\ud1A5\uE261\uB321\u9c1E\u43c7\uFc04"+
         "\u5199\u6d0d\uFAdF\u7E24\u3BAB\ucE11\u8F4E\uB7EB"+
         "\u3c81\u94F7\uB913\u2cd3\uE76E\uc403\u5644\u7FA9"+
         "\u2ABB\uc153\udc0B\u9d6c\u3174\uF646\uAc89\u14E1"+
         "\u163A\u6909\u70B6\ud0Ed\ucc42\u98A4\u285c\uF886";

   private static final long[] T0 = new long[256];
   private static final long[] T1 = new long[256];
   private static final long[] T2 = new long[256];
   private static final long[] T3 = new long[256];
   private static final long[] T4 = new long[256];
   private static final long[] T5 = new long[256];
   private static final long[] T6 = new long[256];
   private static final long[] T7 = new long[256];
   private static final long[] rc = new long[R];

   /** caches the result of the correctness test, once executed. */
   private static Boolean valid;

   /** The 512-bit context as 8 longs. */
   private long H0, H1, H2, H3, H4, H5, H6, H7;

   // Static code - to intialise lookup tables --------------------------------

   static {
      int ROOT = 0x11D; // para. 2.1 [WHIRLPOOL]
      int i, r, j;
      long s, s2, s3, s4, s5, s8, s9, t;
      char c;
      final byte[] S =  new byte[256];
      for (i = 0; i < 256; i++) {
         c = Sd.charAt(i >>> 1);

         s = ((i & 1) == 0 ? c >>> 8 : c) & 0xFFL;
         s2 = s << 1;
         if (s2 > 0xFFL) {
            s2 ^= ROOT;
         }
         s3 = s2 ^ s;
         s4 = s2 << 1;
         if (s4 > 0xFFL) {
            s4 ^= ROOT;
         }
         s5 = s4 ^ s;
         s8 = s4 << 1;
         if (s8 > 0xFFL) {
            s8 ^= ROOT;
         }
         s9 = s8 ^ s;

         S[i] = (byte) s;
         T0[i] = t = s  << 56 | s  << 48 | s3 << 40 | s  << 32 |
                     s5 << 24 | s8 << 16 | s9 <<  8 | s5;
         T1[i] = t >>>  8 | t << 56;
         T2[i] = t >>> 16 | t << 48;
         T3[i] = t >>> 24 | t << 40;
         T4[i] = t >>> 32 | t << 32;
         T5[i] = t >>> 40 | t << 24;
         T6[i] = t >>> 48 | t << 16;
         T7[i] = t >>> 56 | t << 8;
      }

      for (r = 1, i = 0, j = 0; r < R+1; r++) {
         rc[i++] = (S[j++] & 0xFFL) << 56 | (S[j++] & 0xFFL) << 48 |
                   (S[j++] & 0xFFL) << 40 | (S[j++] & 0xFFL) << 32 |
                   (S[j++] & 0xFFL) << 24 | (S[j++] & 0xFFL) << 16 |
                   (S[j++] & 0xFFL) <<  8 | (S[j++] & 0xFFL);
      }
   }

   // Constructor(s)
   // -------------------------------------------------------------------------

   /** Trivial 0-arguments constructor. */
   public Whirlpool() {
      super(Registry.WHIRLPOOL_HASH, 20, BLOCK_SIZE);
   }

   /**
    * <p>Private constructor for cloning purposes.</p>
    *
    * @param md the instance to clone.
    */
   private Whirlpool(Whirlpool md) {
      this();

      this.H0 = md.H0;
      this.H1 = md.H1;
      this.H2 = md.H2;
      this.H3 = md.H3;
      this.H4 = md.H4;
      this.H5 = md.H5;
      this.H6 = md.H6;
      this.H7 = md.H7;
      this.count = md.count;
      this.buffer = (byte[]) md.buffer.clone();
   }

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   // java.lang.Cloneable interface implementation ----------------------------

   public Object clone() {
      return (new Whirlpool(this));
   }

   // Implementation of concrete methods in BaseHash --------------------------

   protected void transform(byte[] in, int i) {
      // apply mu to the input
      long nn0 = (in[i++] & 0xFFL) << 56 | (in[i++] & 0xFFL) << 48 | (in[i++] & 0xFFL) << 40 | (in[i++] & 0xFFL) << 32 |
                 (in[i++] & 0xFFL) << 24 | (in[i++] & 0xFFL) << 16 | (in[i++] & 0xFFL) <<  8 | (in[i++] & 0xFFL);
      long nn1 = (in[i++] & 0xFFL) << 56 | (in[i++] & 0xFFL) << 48 | (in[i++] & 0xFFL) << 40 | (in[i++] & 0xFFL) << 32 |
                 (in[i++] & 0xFFL) << 24 | (in[i++] & 0xFFL) << 16 | (in[i++] & 0xFFL) <<  8 | (in[i++] & 0xFFL);
      long nn2 = (in[i++] & 0xFFL) << 56 | (in[i++] & 0xFFL) << 48 | (in[i++] & 0xFFL) << 40 | (in[i++] & 0xFFL) << 32 |
                 (in[i++] & 0xFFL) << 24 | (in[i++] & 0xFFL) << 16 | (in[i++] & 0xFFL) <<  8 | (in[i++] & 0xFFL);
      long nn3 = (in[i++] & 0xFFL) << 56 | (in[i++] & 0xFFL) << 48 | (in[i++] & 0xFFL) << 40 | (in[i++] & 0xFFL) << 32 |
                 (in[i++] & 0xFFL) << 24 | (in[i++] & 0xFFL) << 16 | (in[i++] & 0xFFL) <<  8 | (in[i++] & 0xFFL);
      long nn4 = (in[i++] & 0xFFL) << 56 | (in[i++] & 0xFFL) << 48 | (in[i++] & 0xFFL) << 40 | (in[i++] & 0xFFL) << 32 |
                 (in[i++] & 0xFFL) << 24 | (in[i++] & 0xFFL) << 16 | (in[i++] & 0xFFL) <<  8 | (in[i++] & 0xFFL);
      long nn5 = (in[i++] & 0xFFL) << 56 | (in[i++] & 0xFFL) << 48 | (in[i++] & 0xFFL) << 40 | (in[i++] & 0xFFL) << 32 |
                 (in[i++] & 0xFFL) << 24 | (in[i++] & 0xFFL) << 16 | (in[i++] & 0xFFL) <<  8 | (in[i++] & 0xFFL);
      long nn6 = (in[i++] & 0xFFL) << 56 | (in[i++] & 0xFFL) << 48 | (in[i++] & 0xFFL) << 40 | (in[i++] & 0xFFL) << 32 |
                 (in[i++] & 0xFFL) << 24 | (in[i++] & 0xFFL) << 16 | (in[i++] & 0xFFL) <<  8 | (in[i++] & 0xFFL);
      long nn7 = (in[i++] & 0xFFL) << 56 | (in[i++] & 0xFFL) << 48 | (in[i++] & 0xFFL) << 40 | (in[i++] & 0xFFL) << 32 |
                 (in[i++] & 0xFFL) << 24 | (in[i++] & 0xFFL) << 16 | (in[i++] & 0xFFL) <<  8 | (in[i  ] & 0xFFL);

      // transform K into the key schedule Kr; 0 <= r <= R
      long k0, k1, k2, k3, k4, k5, k6, k7;
      k0 = H0; k1 = H1; k2 = H2; k3 = H3; k4 = H4; k5 = H5; k6 = H6; k7 = H7;

      long n0 = nn0 ^ k0;
      long n1 = nn1 ^ k1;
      long n2 = nn2 ^ k2;
      long n3 = nn3 ^ k3;
      long n4 = nn4 ^ k4;
      long n5 = nn5 ^ k5;
      long n6 = nn6 ^ k6;
      long n7 = nn7 ^ k7;

      // intermediate cipher output
      long Kr0, Kr1, Kr2, Kr3, Kr4, Kr5, Kr6, Kr7, w0, w1, w2, w3, w4, w5, w6, w7;
      w0 = w1 = w2 = w3 = w4 = w5 = w6 = w7 = 0L;
      for (int r = 0; r < R; r++) {
         // 1. compute intermediate round key schedule by applying ro[rc]
         // to the previous round key schedule --rc being the round constant
         Kr0 = T0[(int)((k0 >> 56) & 0xFFL)] ^ T1[(int)((k7 >> 48) & 0xFFL)] ^ T2[(int)((k6 >> 40) & 0xFFL)] ^ T3[(int)((k5 >> 32) & 0xFFL)] ^
               T4[(int)((k4 >> 24) & 0xFFL)] ^ T5[(int)((k3 >> 16) & 0xFFL)] ^ T6[(int)((k2 >>  8) & 0xFFL)] ^ T7[(int)(k1 & 0xFFL)] ^ rc[r];
         Kr1 = T0[(int)((k1 >> 56) & 0xFFL)] ^ T1[(int)((k0 >> 48) & 0xFFL)] ^ T2[(int)((k7 >> 40) & 0xFFL)] ^ T3[(int)((k6 >> 32) & 0xFFL)] ^
               T4[(int)((k5 >> 24) & 0xFFL)] ^ T5[(int)((k4 >> 16) & 0xFFL)] ^ T6[(int)((k3 >>  8) & 0xFFL)] ^ T7[(int)(k2 & 0xFFL)];
         Kr2 = T0[(int)((k2 >> 56) & 0xFFL)] ^ T1[(int)((k1 >> 48) & 0xFFL)] ^ T2[(int)((k0 >> 40) & 0xFFL)] ^ T3[(int)((k7 >> 32) & 0xFFL)] ^
               T4[(int)((k6 >> 24) & 0xFFL)] ^ T5[(int)((k5 >> 16) & 0xFFL)] ^ T6[(int)((k4 >>  8) & 0xFFL)] ^ T7[(int)(k3 & 0xFFL)];
         Kr3 = T0[(int)((k3 >> 56) & 0xFFL)] ^ T1[(int)((k2 >> 48) & 0xFFL)] ^ T2[(int)((k1 >> 40) & 0xFFL)] ^ T3[(int)((k0 >> 32) & 0xFFL)] ^
               T4[(int)((k7 >> 24) & 0xFFL)] ^ T5[(int)((k6 >> 16) & 0xFFL)] ^ T6[(int)((k5 >>  8) & 0xFFL)] ^ T7[(int)(k4 & 0xFFL)];
         Kr4 = T0[(int)((k4 >> 56) & 0xFFL)] ^ T1[(int)((k3 >> 48) & 0xFFL)] ^ T2[(int)((k2 >> 40) & 0xFFL)] ^ T3[(int)((k1 >> 32) & 0xFFL)] ^
               T4[(int)((k0 >> 24) & 0xFFL)] ^ T5[(int)((k7 >> 16) & 0xFFL)] ^ T6[(int)((k6 >>  8) & 0xFFL)] ^ T7[(int)(k5 & 0xFFL)];
         Kr5 = T0[(int)((k5 >> 56) & 0xFFL)] ^ T1[(int)((k4 >> 48) & 0xFFL)] ^ T2[(int)((k3 >> 40) & 0xFFL)] ^ T3[(int)((k2 >> 32) & 0xFFL)] ^
               T4[(int)((k1 >> 24) & 0xFFL)] ^ T5[(int)((k0 >> 16) & 0xFFL)] ^ T6[(int)((k7 >>  8) & 0xFFL)] ^ T7[(int)(k6 & 0xFFL)];
         Kr6 = T0[(int)((k6 >> 56) & 0xFFL)] ^ T1[(int)((k5 >> 48) & 0xFFL)] ^ T2[(int)((k4 >> 40) & 0xFFL)] ^ T3[(int)((k3 >> 32) & 0xFFL)] ^
               T4[(int)((k2 >> 24) & 0xFFL)] ^ T5[(int)((k1 >> 16) & 0xFFL)] ^ T6[(int)((k0 >>  8) & 0xFFL)] ^ T7[(int)(k7 & 0xFFL)];
         Kr7 = T0[(int)((k7 >> 56) & 0xFFL)] ^ T1[(int)((k6 >> 48) & 0xFFL)] ^ T2[(int)((k5 >> 40) & 0xFFL)] ^ T3[(int)((k4 >> 32) & 0xFFL)] ^
               T4[(int)((k3 >> 24) & 0xFFL)] ^ T5[(int)((k2 >> 16) & 0xFFL)] ^ T6[(int)((k1 >>  8) & 0xFFL)] ^ T7[(int)(k0 & 0xFFL)];

         k0 = Kr0; k1 = Kr1; k2 = Kr2; k3 = Kr3; k4 = Kr4; k5 = Kr5; k6 = Kr6; k7 = Kr7;

         // 2. incrementally compute the cipher output
         w0 = T0[(int)((n0 >> 56) & 0xFFL)] ^ T1[(int)((n7 >> 48) & 0xFFL)] ^ T2[(int)((n6 >> 40) & 0xFFL)] ^ T3[(int)((n5 >> 32) & 0xFFL)] ^
              T4[(int)((n4 >> 24) & 0xFFL)] ^ T5[(int)((n3 >> 16) & 0xFFL)] ^ T6[(int)((n2 >>  8) & 0xFFL)] ^ T7[(int)(n1 & 0xFFL)] ^ Kr0;
         w1 = T0[(int)((n1 >> 56) & 0xFFL)] ^ T1[(int)((n0 >> 48) & 0xFFL)] ^ T2[(int)((n7 >> 40) & 0xFFL)] ^ T3[(int)((n6 >> 32) & 0xFFL)] ^
              T4[(int)((n5 >> 24) & 0xFFL)] ^ T5[(int)((n4 >> 16) & 0xFFL)] ^ T6[(int)((n3 >>  8) & 0xFFL)] ^ T7[(int)(n2 & 0xFFL)] ^ Kr1;
         w2 = T0[(int)((n2 >> 56) & 0xFFL)] ^ T1[(int)((n1 >> 48) & 0xFFL)] ^ T2[(int)((n0 >> 40) & 0xFFL)] ^ T3[(int)((n7 >> 32) & 0xFFL)] ^
              T4[(int)((n6 >> 24) & 0xFFL)] ^ T5[(int)((n5 >> 16) & 0xFFL)] ^ T6[(int)((n4 >>  8) & 0xFFL)] ^ T7[(int)(n3 & 0xFFL)] ^ Kr2;
         w3 = T0[(int)((n3 >> 56) & 0xFFL)] ^ T1[(int)((n2 >> 48) & 0xFFL)] ^ T2[(int)((n1 >> 40) & 0xFFL)] ^ T3[(int)((n0 >> 32) & 0xFFL)] ^
              T4[(int)((n7 >> 24) & 0xFFL)] ^ T5[(int)((n6 >> 16) & 0xFFL)] ^ T6[(int)((n5 >>  8) & 0xFFL)] ^ T7[(int)(n4 & 0xFFL)] ^ Kr3;
         w4 = T0[(int)((n4 >> 56) & 0xFFL)] ^ T1[(int)((n3 >> 48) & 0xFFL)] ^ T2[(int)((n2 >> 40) & 0xFFL)] ^ T3[(int)((n1 >> 32) & 0xFFL)] ^
              T4[(int)((n0 >> 24) & 0xFFL)] ^ T5[(int)((n7 >> 16) & 0xFFL)] ^ T6[(int)((n6 >>  8) & 0xFFL)] ^ T7[(int)(n5 & 0xFFL)] ^ Kr4;
         w5 = T0[(int)((n5 >> 56) & 0xFFL)] ^ T1[(int)((n4 >> 48) & 0xFFL)] ^ T2[(int)((n3 >> 40) & 0xFFL)] ^ T3[(int)((n2 >> 32) & 0xFFL)] ^
              T4[(int)((n1 >> 24) & 0xFFL)] ^ T5[(int)((n0 >> 16) & 0xFFL)] ^ T6[(int)((n7 >>  8) & 0xFFL)] ^ T7[(int)(n6 & 0xFFL)] ^ Kr5;
         w6 = T0[(int)((n6 >> 56) & 0xFFL)] ^ T1[(int)((n5 >> 48) & 0xFFL)] ^ T2[(int)((n4 >> 40) & 0xFFL)] ^ T3[(int)((n3 >> 32) & 0xFFL)] ^
              T4[(int)((n2 >> 24) & 0xFFL)] ^ T5[(int)((n1 >> 16) & 0xFFL)] ^ T6[(int)((n0 >>  8) & 0xFFL)] ^ T7[(int)(n7 & 0xFFL)] ^ Kr6;
         w7 = T0[(int)((n7 >> 56) & 0xFFL)] ^ T1[(int)((n6 >> 48) & 0xFFL)] ^ T2[(int)((n5 >> 40) & 0xFFL)] ^ T3[(int)((n4 >> 32) & 0xFFL)] ^
              T4[(int)((n3 >> 24) & 0xFFL)] ^ T5[(int)((n2 >> 16) & 0xFFL)] ^ T6[(int)((n1 >>  8) & 0xFFL)] ^ T7[(int)(n0 & 0xFFL)] ^ Kr7;

         n0 = w0; n1 = w1; n2 = w2; n3 = w3; n4 = w4; n5 = w5; n6 = w6; n7 = w7;
      }
      // apply the Miyaguchi-Preneel hash scheme
      H0 ^= w0 ^ nn0; H1 ^= w1 ^ nn1; H2 ^= w2 ^ nn2; H3 ^= w3 ^ nn3; H4 ^= w4 ^ nn4; H5 ^= w5 ^ nn5; H6 ^= w6 ^ nn6; H7 ^= w7 ^ nn7;
   }

   protected byte[] padBuffer() {
      // [WHIRLPOOL] p. 6:
      // "...padded with a 1-bit, then with as few 0-bits as necessary to
      // obtain a bit string whose length is an odd multiple of 256, and
      // finally with the 256-bit right-justied binary representation of L."
      // in this implementation we use 'count' as the number of bytes hashed
      // so far. hence the minimal number of bytes added to the message proper
      // are 33 (1 for the 1-bit followed by the 0-bits and the encoding of
      // the count framed in a 256-bit block). our formula is then:
      //		count + 33 + padding = 0 (mod BLOCK_SIZE)
      int n = (int)((count+33) % BLOCK_SIZE);
      int padding = n == 0 ? 33 : BLOCK_SIZE - n + 33;

      byte[] result = new byte[padding];

      // padding is always binary 1 followed by binary 0s
      result[0] = (byte) 0x80;

      // save (right justified) the number of bits hashed
      long bits = count * 8;
      int i = padding - 8;
      result[i++] = (byte)(bits >>> 56);
      result[i++] = (byte)(bits >>> 48);
      result[i++] = (byte)(bits >>> 40);
      result[i++] = (byte)(bits >>> 32);
      result[i++] = (byte)(bits >>> 24);
      result[i++] = (byte)(bits >>> 16);
      result[i++] = (byte)(bits >>>  8);
      result[i  ] = (byte) bits;

      return result;
   }

   protected byte[] getResult() {
      // apply inverse mu to the context
      byte[] result = new byte[] {
         (byte)(H0 >>> 56), (byte)(H0 >>> 48), (byte)(H0 >>> 40), (byte)(H0 >>> 32),
         (byte)(H0 >>> 24), (byte)(H0 >>> 16), (byte)(H0 >>>  8), (byte) H0,
         (byte)(H1 >>> 56), (byte)(H1 >>> 48), (byte)(H1 >>> 40), (byte)(H1 >>> 32),
         (byte)(H1 >>> 24), (byte)(H1 >>> 16), (byte)(H1 >>>  8), (byte) H1,
         (byte)(H2 >>> 56), (byte)(H2 >>> 48), (byte)(H2 >>> 40), (byte)(H2 >>> 32),
         (byte)(H2 >>> 24), (byte)(H2 >>> 16), (byte)(H2 >>>  8), (byte) H2,
         (byte)(H3 >>> 56), (byte)(H3 >>> 48), (byte)(H3 >>> 40), (byte)(H3 >>> 32),
         (byte)(H3 >>> 24), (byte)(H3 >>> 16), (byte)(H3 >>>  8), (byte) H3,
         (byte)(H4 >>> 56), (byte)(H4 >>> 48), (byte)(H4 >>> 40), (byte)(H4 >>> 32),
         (byte)(H4 >>> 24), (byte)(H4 >>> 16), (byte)(H4 >>>  8), (byte) H4,
         (byte)(H5 >>> 56), (byte)(H5 >>> 48), (byte)(H5 >>> 40), (byte)(H5 >>> 32),
         (byte)(H5 >>> 24), (byte)(H5 >>> 16), (byte)(H5 >>>  8), (byte) H5,
         (byte)(H6 >>> 56), (byte)(H6 >>> 48), (byte)(H6 >>> 40), (byte)(H6 >>> 32),
         (byte)(H6 >>> 24), (byte)(H6 >>> 16), (byte)(H6 >>>  8), (byte) H6,
         (byte)(H7 >>> 56), (byte)(H7 >>> 48), (byte)(H7 >>> 40), (byte)(H7 >>> 32),
         (byte)(H7 >>> 24), (byte)(H7 >>> 16), (byte)(H7 >>>  8), (byte) H7
      };

      return result;
   }

   protected void resetContext() {
      H0 = H1 = H2 = H3 = H4 = H5 = H6 = H7 = 0L;
   }

   public boolean selfTest() {
      if (valid == null) {
         valid = new Boolean(DIGEST0.equals(Util.toString(new Whirlpool().digest())));
      }
      return valid.booleanValue();
   }
}
