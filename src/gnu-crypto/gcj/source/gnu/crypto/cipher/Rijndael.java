package gnu.crypto.cipher;

// ----------------------------------------------------------------------------
// $Id: Rijndael.java,v 1.1 2002/12/01 04:41:06 raif Exp $
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
 * <p>Rijndael --pronounced Reindaal-- is the AES. It is a variable block-size
 * (128-, 192- and 256-bit), variable key-size (128-, 192- and 256-bit)
 * symmetric key block cipher.</p>
 *
 * <p>References:</p>
 *
 * <ol>
 *    <li><a href="http://www.esat.kuleuven.ac.be/~rijmen/rijndael/">The
 *    Rijndael Block Cipher - AES Proposal</a>.<br>
 *    <a href="mailto:vincent.rijmen@esat.kuleuven.ac.be">Vincent Rijmen</a> and
 *    <a href="mailto:daemen.j@protonworld.com">Joan Daemen</a>.</li>
 * </ol>
 *
 * @version $Revision: 1.1 $
 */
public final class Rijndael extends BaseCipher {

   // Constants and variables
   // -------------------------------------------------------------------------

   private static final int DEFAULT_BLOCK_SIZE = 16; // in bytes
   private static final int DEFAULT_KEY_SIZE = 16; // in bytes
   private static final String SS =
      "\u637C\u777B\uF26B\u6FC5\u3001\u672B\uFED7\uAB76" +
      "\uCA82\uC97D\uFA59\u47F0\uADD4\uA2AF\u9CA4\u72C0" +
      "\uB7FD\u9326\u363F\uF7CC\u34A5\uE5F1\u71D8\u3115" +
      "\u04C7\u23C3\u1896\u059A\u0712\u80E2\uEB27\uB275" +
      "\u0983\u2C1A\u1B6E\u5AA0\u523B\uD6B3\u29E3\u2F84" +
      "\u53D1\u00ED\u20FC\uB15B\u6ACB\uBE39\u4A4C\u58CF" +
      "\uD0EF\uAAFB\u434D\u3385\u45F9\u027F\u503C\u9FA8" +
      "\u51A3\u408F\u929D\u38F5\uBCB6\uDA21\u10FF\uF3D2" +
      "\uCD0C\u13EC\u5F97\u4417\uC4A7\u7E3D\u645D\u1973" +
      "\u6081\u4FDC\u222A\u9088\u46EE\uB814\uDE5E\u0BDB" +
      "\uE032\u3A0A\u4906\u245C\uC2D3\uAC62\u9195\uE479" +
      "\uE7C8\u376D\u8DD5\u4EA9\u6C56\uF4EA\u657A\uAE08" +
      "\uBA78\u252E\u1CA6\uB4C6\uE8DD\u741F\u4BBD\u8B8A" +
      "\u703E\uB566\u4803\uF60E\u6135\u57B9\u86C1\u1D9E" +
      "\uE1F8\u9811\u69D9\u8E94\u9B1E\u87E9\uCE55\u28DF" +
      "\u8CA1\u890D\uBFE6\u4268\u4199\u2D0F\uB054\uBB16";

   private static final byte[] S =  new byte[256];
   private static final byte[] Si = new byte[256];
   private static final int[] T1 = new int[256];
   private static final int[] T2 = new int[256];
   private static final int[] T3 = new int[256];
   private static final int[] T4 = new int[256];
   private static final int[] T5 = new int[256];
   private static final int[] T6 = new int[256];
   private static final int[] T7 = new int[256];
   private static final int[] T8 = new int[256];
   private static final int[] U1 = new int[256];
   private static final int[] U2 = new int[256];
   private static final int[] U3 = new int[256];
   private static final int[] U4 = new int[256];
   private static final byte[] rcon = new byte[30];

   /**
    * KAT vector (from ecb_vk):
    * I=96
    * KEY=0000000000000000000000010000000000000000000000000000000000000000
    * CT=E44429474D6FC3084EB2A6B8B46AF754
    */
   private static final byte[] KAT_KEY =
         Util.toBytesFromString("0000000000000000000000010000000000000000000000000000000000000000");
   private static final byte[] KAT_CT =
         Util.toBytesFromString("E44429474D6FC3084EB2A6B8B46AF754");

   /** caches the result of the correctness test, once executed. */
   private static Boolean valid;

   // Static code - to intialise lookup tables --------------------------------

   static {
      long time = System.currentTimeMillis();

      int ROOT = 0x11B;
      int i = 0;

      // S-box, inverse S-box, T-boxes, U-boxes
      int s, s2, s3, i2, i4, i8, i9, ib, id, ie, t;
      char c;
      for (i = 0; i < 256; i++) {
         c = SS.charAt(i >>> 1);
         S[i] = (byte)(((i & 1) == 0) ? c >>> 8 : c & 0xFF);
         s = S[i] & 0xFF;
         Si[s] = (byte) i;
         s2 = s << 1;
         if (s2 >= 0x100) {
            s2 ^= ROOT;
         }
         s3 = s2 ^ s;
         i2 = i << 1;
         if (i2 >= 0x100) {
            i2 ^= ROOT;
         }
         i4 = i2 << 1;
         if (i4 >= 0x100) {
            i4 ^= ROOT;
         }
         i8 = i4 << 1;
         if (i8 >= 0x100) {
            i8 ^= ROOT;
         }
         i9 = i8 ^ i;
         ib = i9 ^ i2;
         id = i9 ^ i4;
         ie = i8 ^ i4 ^ i2;

         T1[i] = t = s2 << 24 | s << 16 | s << 8 | s3;
         T2[i] = t >>>  8 | t << 24;
         T3[i] = t >>> 16 | t << 16;
         T4[i] = t >>> 24 | t <<  8;

         T5[s] = U1[i] = t = ie << 24 | i9 << 16 | id << 8 | ib;
         T6[s] = U2[i] = t >>>  8 | t << 24;
         T7[s] = U3[i] = t >>> 16 | t << 16;
         T8[s] = U4[i] = t >>> 24 | t <<  8;
      }
      //
      // round constants
      //
      int r = 1;
      rcon[0] = 1;
      for (i = 1; i < 30; i++) {
         r <<= 1;
         if (r >= 0x100) {
            r ^= ROOT;
         }
         rcon[i] = (byte) r;
      }

      time = System.currentTimeMillis() - time;
   }

   // Constructor(s)
   // -------------------------------------------------------------------------

   /** Trivial 0-arguments constructor. */
   public Rijndael() {
      super(Registry.RIJNDAEL_CIPHER, DEFAULT_BLOCK_SIZE, DEFAULT_KEY_SIZE);
   }

   // Class methods
   // -------------------------------------------------------------------------

   /**
    * <p>Returns the number of rounds for a given Rijndael's key and block
    * sizes.</p>
    *
    * @param ks the size of the user key material in bytes.
    * @param bs the desired block size in bytes.
    * @return the number of rounds for a given Rijndael's key and block sizes.
    */
   public static final int getRounds(int ks, int bs) {
      switch (ks) {
      case 16: return bs == 16 ? 10 : (bs == 24 ? 12 : 14);
      case 24: return bs != 32 ? 12 : 14;
      default: return 14; // 32 bytes = 256 bits
      }
   }

   private static final void
   aesEncrypt(byte[] in, int i, byte[] out, int j, Object key) {
      Key K = (Key)((Object[]) key)[0]; // extract decryption round keys
      int t0, t1, t2, t3, a0, a1, a2, a3;

      // plaintext to ints + key
      t0 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k00;
      t1 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k01;
      t2 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k02;
      t3 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i  ] & 0xFF)) ^ K.k03;

      // apply rounds-1 transforms
      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k10; t1 = a1 ^ K.k11; t2 = a2 ^ K.k12; t3 = a3 ^ K.k13;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k20; t1 = a1 ^ K.k21; t2 = a2 ^ K.k22; t3 = a3 ^ K.k23;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k30; t1 = a1 ^ K.k31; t2 = a2 ^ K.k32; t3 = a3 ^ K.k33;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k40; t1 = a1 ^ K.k41; t2 = a2 ^ K.k42; t3 = a3 ^ K.k43;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k50; t1 = a1 ^ K.k51; t2 = a2 ^ K.k52; t3 = a3 ^ K.k53;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k60; t1 = a1 ^ K.k61; t2 = a2 ^ K.k62; t3 = a3 ^ K.k63;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k70; t1 = a1 ^ K.k71; t2 = a2 ^ K.k72; t3 = a3 ^ K.k73;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k80; t1 = a1 ^ K.k81; t2 = a2 ^ K.k82; t3 = a3 ^ K.k83;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k90; t1 = a1 ^ K.k91; t2 = a2 ^ K.k92; t3 = a3 ^ K.k93;

      if (K.rounds == 10) { // last round is special
         a0 = K.k100;
         out[j++] = (byte)(S[ t0 >>> 24        ] ^ (a0 >>> 24));
         out[j++] = (byte)(S[(t1 >>> 16) & 0xFF] ^ (a0 >>> 16));
         out[j++] = (byte)(S[(t2 >>>  8) & 0xFF] ^ (a0 >>>  8));
         out[j++] = (byte)(S[ t3         & 0xFF] ^  a0        );
         a1 = K.k101;
         out[j++] = (byte)(S[ t1 >>> 24        ] ^ (a1 >>> 24));
         out[j++] = (byte)(S[(t2 >>> 16) & 0xFF] ^ (a1 >>> 16));
         out[j++] = (byte)(S[(t3 >>>  8) & 0xFF] ^ (a1 >>>  8));
         out[j++] = (byte)(S[ t0         & 0xFF] ^  a1        );
         a2 = K.k102;
         out[j++] = (byte)(S[ t2 >>> 24        ] ^ (a2 >>> 24));
         out[j++] = (byte)(S[(t3 >>> 16) & 0xFF] ^ (a2 >>> 16));
         out[j++] = (byte)(S[(t0 >>>  8) & 0xFF] ^ (a2 >>>  8));
         out[j++] = (byte)(S[ t1         & 0xFF] ^  a2        );
         a3 = K.k103;
         out[j++] = (byte)(S[ t3 >>> 24        ] ^ (a3 >>> 24));
         out[j++] = (byte)(S[(t0 >>> 16) & 0xFF] ^ (a3 >>> 16));
         out[j++] = (byte)(S[(t1 >>>  8) & 0xFF] ^ (a3 >>>  8));
         out[j  ] = (byte)(S[ t2         & 0xFF] ^  a3        );

         return;
      }

      // 12 or 14 rounds
      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k100; t1 = a1 ^ K.k101; t2 = a2 ^ K.k102; t3 = a3 ^ K.k103;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k110; t1 = a1 ^ K.k111; t2 = a2 ^ K.k112; t3 = a3 ^ K.k113;

      if (K.rounds == 12) { // last round is special
         a0 = K.k120;
         out[j++] = (byte)(S[ t0 >>> 24        ] ^ (a0 >>> 24));
         out[j++] = (byte)(S[(t1 >>> 16) & 0xFF] ^ (a0 >>> 16));
         out[j++] = (byte)(S[(t2 >>>  8) & 0xFF] ^ (a0 >>>  8));
         out[j++] = (byte)(S[ t3         & 0xFF] ^  a0        );
         a1 = K.k121;
         out[j++] = (byte)(S[ t1 >>> 24        ] ^ (a1 >>> 24));
         out[j++] = (byte)(S[(t2 >>> 16) & 0xFF] ^ (a1 >>> 16));
         out[j++] = (byte)(S[(t3 >>>  8) & 0xFF] ^ (a1 >>>  8));
         out[j++] = (byte)(S[ t0         & 0xFF] ^  a1        );
         a2 = K.k122;
         out[j++] = (byte)(S[ t2 >>> 24        ] ^ (a2 >>> 24));
         out[j++] = (byte)(S[(t3 >>> 16) & 0xFF] ^ (a2 >>> 16));
         out[j++] = (byte)(S[(t0 >>>  8) & 0xFF] ^ (a2 >>>  8));
         out[j++] = (byte)(S[ t1         & 0xFF] ^  a2        );
         a3 = K.k123;
         out[j++] = (byte)(S[ t3 >>> 24        ] ^ (a3 >>> 24));
         out[j++] = (byte)(S[(t0 >>> 16) & 0xFF] ^ (a3 >>> 16));
         out[j++] = (byte)(S[(t1 >>>  8) & 0xFF] ^ (a3 >>>  8));
         out[j  ] = (byte)(S[ t2         & 0xFF] ^  a3        );

         return;
      }

      // 14 rounds
      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k120; t1 = a1 ^ K.k121; t2 = a2 ^ K.k122; t3 = a3 ^ K.k123;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k130; t1 = a1 ^ K.k131; t2 = a2 ^ K.k132; t3 = a3 ^ K.k133;

      // last round is special
      a0 = K.k140;
      out[j++] = (byte)(S[ t0 >>> 24        ] ^ (a0 >>> 24));
      out[j++] = (byte)(S[(t1 >>> 16) & 0xFF] ^ (a0 >>> 16));
      out[j++] = (byte)(S[(t2 >>>  8) & 0xFF] ^ (a0 >>>  8));
      out[j++] = (byte)(S[ t3         & 0xFF] ^  a0        );
      a1 = K.k141;
      out[j++] = (byte)(S[ t1 >>> 24        ] ^ (a1 >>> 24));
      out[j++] = (byte)(S[(t2 >>> 16) & 0xFF] ^ (a1 >>> 16));
      out[j++] = (byte)(S[(t3 >>>  8) & 0xFF] ^ (a1 >>>  8));
      out[j++] = (byte)(S[ t0         & 0xFF] ^  a1        );
      a2 = K.k142;
      out[j++] = (byte)(S[ t2 >>> 24        ] ^ (a2 >>> 24));
      out[j++] = (byte)(S[(t3 >>> 16) & 0xFF] ^ (a2 >>> 16));
      out[j++] = (byte)(S[(t0 >>>  8) & 0xFF] ^ (a2 >>>  8));
      out[j++] = (byte)(S[ t1         & 0xFF] ^  a2        );
      a3 = K.k143;
      out[j++] = (byte)(S[ t3 >>> 24        ] ^ (a3 >>> 24));
      out[j++] = (byte)(S[(t0 >>> 16) & 0xFF] ^ (a3 >>> 16));
      out[j++] = (byte)(S[(t1 >>>  8) & 0xFF] ^ (a3 >>>  8));
      out[j  ] = (byte)(S[ t2         & 0xFF] ^  a3        );
   }

   private static final void
   aesDecrypt(byte[] in, int i, byte[] out, int j, Object key) {
      Key K = (Key)((Object[]) key)[1]; // extract decryption round keys
      int t0, t1, t2, t3, a0, a1, a2, a3;

      // ciphertext to ints + key
      t0 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k00;
      t1 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k01;
      t2 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k02;
      t3 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i  ] & 0xFF)) ^ K.k03;

      // apply rounds-1 transforms
      a0 = T5[t0 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      t0 = a0 ^ K.k10; t1 = a1 ^ K.k11; t2 = a2 ^ K.k12; t3 = a3 ^ K.k13;

      a0 = T5[t0 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      t0 = a0 ^ K.k20; t1 = a1 ^ K.k21; t2 = a2 ^ K.k22; t3 = a3 ^ K.k23;

      a0 = T5[t0 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      t0 = a0 ^ K.k30; t1 = a1 ^ K.k31; t2 = a2 ^ K.k32; t3 = a3 ^ K.k33;

      a0 = T5[t0 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      t0 = a0 ^ K.k40; t1 = a1 ^ K.k41; t2 = a2 ^ K.k42; t3 = a3 ^ K.k43;

      a0 = T5[t0 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      t0 = a0 ^ K.k50; t1 = a1 ^ K.k51; t2 = a2 ^ K.k52; t3 = a3 ^ K.k53;

      a0 = T5[t0 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      t0 = a0 ^ K.k60; t1 = a1 ^ K.k61; t2 = a2 ^ K.k62; t3 = a3 ^ K.k63;

      a0 = T5[t0 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      t0 = a0 ^ K.k70; t1 = a1 ^ K.k71; t2 = a2 ^ K.k72; t3 = a3 ^ K.k73;

      a0 = T5[t0 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      t0 = a0 ^ K.k80; t1 = a1 ^ K.k81; t2 = a2 ^ K.k82; t3 = a3 ^ K.k83;

      a0 = T5[t0 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      t0 = a0 ^ K.k90; t1 = a1 ^ K.k91; t2 = a2 ^ K.k92; t3 = a3 ^ K.k93;

      if (K.rounds == 10) { // last round is special
         a0 = K.k100;
         out[j++] = (byte)(Si[ t0 >>> 24        ] ^ (a0 >>> 24));
         out[j++] = (byte)(Si[(t3 >>> 16) & 0xFF] ^ (a0 >>> 16));
         out[j++] = (byte)(Si[(t2 >>>  8) & 0xFF] ^ (a0 >>>  8));
         out[j++] = (byte)(Si[ t1         & 0xFF] ^  a0        );
         a1 = K.k101;
         out[j++] = (byte)(Si[ t1 >>> 24        ] ^ (a1 >>> 24));
         out[j++] = (byte)(Si[(t0 >>> 16) & 0xFF] ^ (a1 >>> 16));
         out[j++] = (byte)(Si[(t3 >>>  8) & 0xFF] ^ (a1 >>>  8));
         out[j++] = (byte)(Si[ t2         & 0xFF] ^  a1        );
         a2 = K.k102;
         out[j++] = (byte)(Si[ t2 >>> 24        ] ^ (a2 >>> 24));
         out[j++] = (byte)(Si[(t1 >>> 16) & 0xFF] ^ (a2 >>> 16));
         out[j++] = (byte)(Si[(t0 >>>  8) & 0xFF] ^ (a2 >>>  8));
         out[j++] = (byte)(Si[ t3         & 0xFF] ^  a2        );
         a3 = K.k103;
         out[j++] = (byte)(Si[ t3 >>> 24        ] ^ (a3 >>> 24));
         out[j++] = (byte)(Si[(t2 >>> 16) & 0xFF] ^ (a3 >>> 16));
         out[j++] = (byte)(Si[(t1 >>>  8) & 0xFF] ^ (a3 >>>  8));
         out[j  ] = (byte)(Si[ t0         & 0xFF] ^  a3        );

         return;
      }

      a0 = T5[t0 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      t0 = a0 ^ K.k100; t1 = a1 ^ K.k101; t2 = a2 ^ K.k102; t3 = a3 ^ K.k103;

      a0 = T5[t0 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      t0 = a0 ^ K.k110; t1 = a1 ^ K.k111; t2 = a2 ^ K.k112; t3 = a3 ^ K.k113;

      if (K.rounds == 12) { // last round is special
         a0 = K.k120;
         out[j++] = (byte)(Si[ t0 >>> 24        ] ^ (a0 >>> 24));
         out[j++] = (byte)(Si[(t3 >>> 16) & 0xFF] ^ (a0 >>> 16));
         out[j++] = (byte)(Si[(t2 >>>  8) & 0xFF] ^ (a0 >>>  8));
         out[j++] = (byte)(Si[ t1         & 0xFF] ^  a0        );
         a1 = K.k121;
         out[j++] = (byte)(Si[ t1 >>> 24        ] ^ (a1 >>> 24));
         out[j++] = (byte)(Si[(t0 >>> 16) & 0xFF] ^ (a1 >>> 16));
         out[j++] = (byte)(Si[(t3 >>>  8) & 0xFF] ^ (a1 >>>  8));
         out[j++] = (byte)(Si[ t2         & 0xFF] ^  a1        );
         a2 = K.k122;
         out[j++] = (byte)(Si[ t2 >>> 24        ] ^ (a2 >>> 24));
         out[j++] = (byte)(Si[(t1 >>> 16) & 0xFF] ^ (a2 >>> 16));
         out[j++] = (byte)(Si[(t0 >>>  8) & 0xFF] ^ (a2 >>>  8));
         out[j++] = (byte)(Si[ t3         & 0xFF] ^  a2        );
         a3 = K.k123;
         out[j++] = (byte)(Si[ t3 >>> 24        ] ^ (a3 >>> 24));
         out[j++] = (byte)(Si[(t2 >>> 16) & 0xFF] ^ (a3 >>> 16));
         out[j++] = (byte)(Si[(t1 >>>  8) & 0xFF] ^ (a3 >>>  8));
         out[j  ] = (byte)(Si[ t0         & 0xFF] ^  a3        );

         return;
      }

      a0 = T5[t0 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      t0 = a0 ^ K.k120; t1 = a1 ^ K.k121; t2 = a2 ^ K.k122; t3 = a3 ^ K.k123;

      a0 = T5[t0 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      t0 = a0 ^ K.k130; t1 = a1 ^ K.k131; t2 = a2 ^ K.k132; t3 = a3 ^ K.k133;

      // last round is special
      a0 = K.k140;
      out[j++] = (byte)(Si[ t0 >>> 24        ] ^ (a0 >>> 24));
      out[j++] = (byte)(Si[(t3 >>> 16) & 0xFF] ^ (a0 >>> 16));
      out[j++] = (byte)(Si[(t2 >>>  8) & 0xFF] ^ (a0 >>>  8));
      out[j++] = (byte)(Si[ t1         & 0xFF] ^  a0        );
      a1 = K.k141;
      out[j++] = (byte)(Si[ t1 >>> 24        ] ^ (a1 >>> 24));
      out[j++] = (byte)(Si[(t0 >>> 16) & 0xFF] ^ (a1 >>> 16));
      out[j++] = (byte)(Si[(t3 >>>  8) & 0xFF] ^ (a1 >>>  8));
      out[j++] = (byte)(Si[ t2         & 0xFF] ^  a1        );
      a2 = K.k142;
      out[j++] = (byte)(Si[ t2 >>> 24        ] ^ (a2 >>> 24));
      out[j++] = (byte)(Si[(t1 >>> 16) & 0xFF] ^ (a2 >>> 16));
      out[j++] = (byte)(Si[(t0 >>>  8) & 0xFF] ^ (a2 >>>  8));
      out[j++] = (byte)(Si[ t3         & 0xFF] ^  a2        );
      a3 = K.k143;
      out[j++] = (byte)(Si[ t3 >>> 24        ] ^ (a3 >>> 24));
      out[j++] = (byte)(Si[(t2 >>> 16) & 0xFF] ^ (a3 >>> 16));
      out[j++] = (byte)(Si[(t1 >>>  8) & 0xFF] ^ (a3 >>>  8));
      out[j  ] = (byte)(Si[ t0         & 0xFF] ^  a3        );
   }

   private static final void
   rijndael192Encrypt(byte[] in, int i, byte[] out, int j, Object key) {
      Key K = (Key)((Object[]) key)[0]; // extract encryption round keys
      int t0, t1, t2, t3, t4, t5, a0, a1, a2, a3, a4, a5;

      // plaintext to ints + key
      t0 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k00;
      t1 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k01;
      t2 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k02;
      t3 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k03;
      t4 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k04;
      t5 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i  ] & 0xFF)) ^ K.k05;

      // apply rounds-1 transforms
      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k10; t1 = a1 ^ K.k11; t2 = a2 ^ K.k12;
      t3 = a3 ^ K.k13; t4 = a4 ^ K.k14; t5 = a5 ^ K.k15;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k20; t1 = a1 ^ K.k21; t2 = a2 ^ K.k22;
      t3 = a3 ^ K.k23; t4 = a4 ^ K.k24; t5 = a5 ^ K.k25;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k30; t1 = a1 ^ K.k31; t2 = a2 ^ K.k32;
      t3 = a3 ^ K.k33; t4 = a4 ^ K.k34; t5 = a5 ^ K.k35;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k40; t1 = a1 ^ K.k41; t2 = a2 ^ K.k42;
      t3 = a3 ^ K.k43; t4 = a4 ^ K.k44; t5 = a5 ^ K.k45;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k50; t1 = a1 ^ K.k51; t2 = a2 ^ K.k52;
      t3 = a3 ^ K.k53; t4 = a4 ^ K.k54; t5 = a5 ^ K.k55;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k60; t1 = a1 ^ K.k61; t2 = a2 ^ K.k62;
      t3 = a3 ^ K.k63; t4 = a4 ^ K.k64; t5 = a5 ^ K.k65;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k70; t1 = a1 ^ K.k71; t2 = a2 ^ K.k72;
      t3 = a3 ^ K.k73; t4 = a4 ^ K.k74; t5 = a5 ^ K.k75;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k80; t1 = a1 ^ K.k81; t2 = a2 ^ K.k82;
      t3 = a3 ^ K.k83; t4 = a4 ^ K.k84; t5 = a5 ^ K.k85;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k90; t1 = a1 ^ K.k91; t2 = a2 ^ K.k92;
      t3 = a3 ^ K.k93; t4 = a4 ^ K.k94; t5 = a5 ^ K.k95;

      if (K.rounds == 10) { // last round is special
         a0 = K.k100;
         out[j++] = (byte)(S[ t0 >>> 24        ] ^ (a0 >>> 24));
         out[j++] = (byte)(S[(t1 >>> 16) & 0xFF] ^ (a0 >>> 16));
         out[j++] = (byte)(S[(t2 >>>  8) & 0xFF] ^ (a0 >>>  8));
         out[j++] = (byte)(S[ t3         & 0xFF] ^  a0        );
         a1 = K.k101;
         out[j++] = (byte)(S[ t1 >>> 24        ] ^ (a1 >>> 24));
         out[j++] = (byte)(S[(t2 >>> 16) & 0xFF] ^ (a1 >>> 16));
         out[j++] = (byte)(S[(t3 >>>  8) & 0xFF] ^ (a1 >>>  8));
         out[j++] = (byte)(S[ t4         & 0xFF] ^  a1        );
         a2 = K.k102;
         out[j++] = (byte)(S[ t2 >>> 24        ] ^ (a2 >>> 24));
         out[j++] = (byte)(S[(t3 >>> 16) & 0xFF] ^ (a2 >>> 16));
         out[j++] = (byte)(S[(t4 >>>  8) & 0xFF] ^ (a2 >>>  8));
         out[j++] = (byte)(S[ t5         & 0xFF] ^  a2        );
         a3 = K.k103;
         out[j++] = (byte)(S[ t3 >>> 24        ] ^ (a3 >>> 24));
         out[j++] = (byte)(S[(t4 >>> 16) & 0xFF] ^ (a3 >>> 16));
         out[j++] = (byte)(S[(t5 >>>  8) & 0xFF] ^ (a3 >>>  8));
         out[j++] = (byte)(S[ t0         & 0xFF] ^  a3        );
         a4 = K.k104;
         out[j++] = (byte)(S[ t4 >>> 24        ] ^ (a4 >>> 24));
         out[j++] = (byte)(S[(t5 >>> 16) & 0xFF] ^ (a4 >>> 16));
         out[j++] = (byte)(S[(t0 >>>  8) & 0xFF] ^ (a4 >>>  8));
         out[j++] = (byte)(S[ t1         & 0xFF] ^  a4        );
         a5 = K.k105;
         out[j++] = (byte)(S[ t5 >>> 24        ] ^ (a5 >>> 24));
         out[j++] = (byte)(S[(t0 >>> 16) & 0xFF] ^ (a5 >>> 16));
         out[j++] = (byte)(S[(t1 >>>  8) & 0xFF] ^ (a5 >>>  8));
         out[j  ] = (byte)(S[ t2         & 0xFF] ^  a5        );

         return;
      }

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k100; t1 = a1 ^ K.k101; t2 = a2 ^ K.k102;
      t3 = a3 ^ K.k103; t4 = a4 ^ K.k104; t5 = a5 ^ K.k105;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k110; t1 = a1 ^ K.k111; t2 = a2 ^ K.k112;
      t3 = a3 ^ K.k113; t4 = a4 ^ K.k114; t5 = a5 ^ K.k115;

      if (K.rounds == 12) { // last round is special
         a0 = K.k120;
         out[j++] = (byte)(S[ t0 >>> 24        ] ^ (a0 >>> 24));
         out[j++] = (byte)(S[(t1 >>> 16) & 0xFF] ^ (a0 >>> 16));
         out[j++] = (byte)(S[(t2 >>>  8) & 0xFF] ^ (a0 >>>  8));
         out[j++] = (byte)(S[ t3         & 0xFF] ^  a0        );
         a1 = K.k121;
         out[j++] = (byte)(S[ t1 >>> 24        ] ^ (a1 >>> 24));
         out[j++] = (byte)(S[(t2 >>> 16) & 0xFF] ^ (a1 >>> 16));
         out[j++] = (byte)(S[(t3 >>>  8) & 0xFF] ^ (a1 >>>  8));
         out[j++] = (byte)(S[ t4         & 0xFF] ^  a1        );
         a2 = K.k122;
         out[j++] = (byte)(S[ t2 >>> 24        ] ^ (a2 >>> 24));
         out[j++] = (byte)(S[(t3 >>> 16) & 0xFF] ^ (a2 >>> 16));
         out[j++] = (byte)(S[(t4 >>>  8) & 0xFF] ^ (a2 >>>  8));
         out[j++] = (byte)(S[ t5         & 0xFF] ^  a2        );
         a3 = K.k123;
         out[j++] = (byte)(S[ t3 >>> 24        ] ^ (a3 >>> 24));
         out[j++] = (byte)(S[(t4 >>> 16) & 0xFF] ^ (a3 >>> 16));
         out[j++] = (byte)(S[(t5 >>>  8) & 0xFF] ^ (a3 >>>  8));
         out[j++] = (byte)(S[ t0         & 0xFF] ^  a3        );
         a4 = K.k124;
         out[j++] = (byte)(S[ t4 >>> 24        ] ^ (a4 >>> 24));
         out[j++] = (byte)(S[(t5 >>> 16) & 0xFF] ^ (a4 >>> 16));
         out[j++] = (byte)(S[(t0 >>>  8) & 0xFF] ^ (a4 >>>  8));
         out[j++] = (byte)(S[ t1         & 0xFF] ^  a4        );
         a5 = K.k125;
         out[j++] = (byte)(S[ t5 >>> 24        ] ^ (a5 >>> 24));
         out[j++] = (byte)(S[(t0 >>> 16) & 0xFF] ^ (a5 >>> 16));
         out[j++] = (byte)(S[(t1 >>>  8) & 0xFF] ^ (a5 >>>  8));
         out[j  ] = (byte)(S[ t2         & 0xFF] ^  a5        );

         return;
      }

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k120; t1 = a1 ^ K.k121; t2 = a2 ^ K.k122;
      t3 = a3 ^ K.k123; t4 = a4 ^ K.k124; t5 = a5 ^ K.k125;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      t0 = a0 ^ K.k130; t1 = a1 ^ K.k131; t2 = a2 ^ K.k132;
      t3 = a3 ^ K.k133; t4 = a4 ^ K.k134; t5 = a5 ^ K.k135;

      // last round is special
      a0 = K.k140;
      out[j++] = (byte)(S[ t0 >>> 24        ] ^ (a0 >>> 24));
      out[j++] = (byte)(S[(t1 >>> 16) & 0xFF] ^ (a0 >>> 16));
      out[j++] = (byte)(S[(t2 >>>  8) & 0xFF] ^ (a0 >>>  8));
      out[j++] = (byte)(S[ t3         & 0xFF] ^  a0        );
      a1 = K.k141;
      out[j++] = (byte)(S[ t1 >>> 24        ] ^ (a1 >>> 24));
      out[j++] = (byte)(S[(t2 >>> 16) & 0xFF] ^ (a1 >>> 16));
      out[j++] = (byte)(S[(t3 >>>  8) & 0xFF] ^ (a1 >>>  8));
      out[j++] = (byte)(S[ t4         & 0xFF] ^  a1        );
      a2 = K.k142;
      out[j++] = (byte)(S[ t2 >>> 24        ] ^ (a2 >>> 24));
      out[j++] = (byte)(S[(t3 >>> 16) & 0xFF] ^ (a2 >>> 16));
      out[j++] = (byte)(S[(t4 >>>  8) & 0xFF] ^ (a2 >>>  8));
      out[j++] = (byte)(S[ t5         & 0xFF] ^  a2        );
      a3 = K.k143;
      out[j++] = (byte)(S[ t3 >>> 24        ] ^ (a3 >>> 24));
      out[j++] = (byte)(S[(t4 >>> 16) & 0xFF] ^ (a3 >>> 16));
      out[j++] = (byte)(S[(t5 >>>  8) & 0xFF] ^ (a3 >>>  8));
      out[j++] = (byte)(S[ t0         & 0xFF] ^  a3        );
      a4 = K.k144;
      out[j++] = (byte)(S[ t4 >>> 24        ] ^ (a4 >>> 24));
      out[j++] = (byte)(S[(t5 >>> 16) & 0xFF] ^ (a4 >>> 16));
      out[j++] = (byte)(S[(t0 >>>  8) & 0xFF] ^ (a4 >>>  8));
      out[j++] = (byte)(S[ t1         & 0xFF] ^  a4        );
      a5 = K.k145;
      out[j++] = (byte)(S[ t5 >>> 24        ] ^ (a5 >>> 24));
      out[j++] = (byte)(S[(t0 >>> 16) & 0xFF] ^ (a5 >>> 16));
      out[j++] = (byte)(S[(t1 >>>  8) & 0xFF] ^ (a5 >>>  8));
      out[j  ] = (byte)(S[ t2         & 0xFF] ^  a5        );
   }

   private static final void
   rijndael192Decrypt(byte[] in, int i, byte[] out, int j, Object key) {
      Key K = (Key)((Object[]) key)[1]; // extract decryption round keys
      int t0, t1, t2, t3, t4, t5, a0, a1, a2, a3, a4, a5;

      // ciphertext to ints + key
      t0 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k00;
      t1 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k01;
      t2 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k02;
      t3 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k03;
      t4 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k04;
      t5 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i  ] & 0xFF)) ^ K.k05;

      // apply rounds-1 transforms
      a0 = T5[t0 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      t0 = a0 ^ K.k10; t1 = a1 ^ K.k11; t2 = a2 ^ K.k12;
      t3 = a3 ^ K.k13; t4 = a4 ^ K.k14; t5 = a5 ^ K.k15;

      a0 = T5[t0 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      t0 = a0 ^ K.k20; t1 = a1 ^ K.k21; t2 = a2 ^ K.k22;
      t3 = a3 ^ K.k23; t4 = a4 ^ K.k24; t5 = a5 ^ K.k25;

      a0 = T5[t0 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      t0 = a0 ^ K.k30; t1 = a1 ^ K.k31; t2 = a2 ^ K.k32;
      t3 = a3 ^ K.k33; t4 = a4 ^ K.k34; t5 = a5 ^ K.k35;

      a0 = T5[t0 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      t0 = a0 ^ K.k40; t1 = a1 ^ K.k41; t2 = a2 ^ K.k42;
      t3 = a3 ^ K.k43; t4 = a4 ^ K.k44; t5 = a5 ^ K.k45;

      a0 = T5[t0 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      t0 = a0 ^ K.k50; t1 = a1 ^ K.k51; t2 = a2 ^ K.k52;
      t3 = a3 ^ K.k53; t4 = a4 ^ K.k54; t5 = a5 ^ K.k55;

      a0 = T5[t0 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      t0 = a0 ^ K.k60; t1 = a1 ^ K.k61; t2 = a2 ^ K.k62;
      t3 = a3 ^ K.k63; t4 = a4 ^ K.k64; t5 = a5 ^ K.k65;

      a0 = T5[t0 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      t0 = a0 ^ K.k70; t1 = a1 ^ K.k71; t2 = a2 ^ K.k72;
      t3 = a3 ^ K.k73; t4 = a4 ^ K.k74; t5 = a5 ^ K.k75;

      a0 = T5[t0 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      t0 = a0 ^ K.k80; t1 = a1 ^ K.k81; t2 = a2 ^ K.k82;
      t3 = a3 ^ K.k83; t4 = a4 ^ K.k84; t5 = a5 ^ K.k85;

      a0 = T5[t0 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      t0 = a0 ^ K.k90; t1 = a1 ^ K.k91; t2 = a2 ^ K.k92;
      t3 = a3 ^ K.k93; t4 = a4 ^ K.k94; t5 = a5 ^ K.k95;

      if (K.rounds == 10) {
         a0 = K.k100;
         out[j++] = (byte)(Si[ t0 >>> 24        ] ^ (a0 >>> 24));
         out[j++] = (byte)(Si[(t5 >>> 16) & 0xFF] ^ (a0 >>> 16));
         out[j++] = (byte)(Si[(t4 >>>  8) & 0xFF] ^ (a0 >>>  8));
         out[j++] = (byte)(Si[ t3         & 0xFF] ^  a0        );
         a1 = K.k101;
         out[j++] = (byte)(Si[ t1 >>> 24        ] ^ (a1 >>> 24));
         out[j++] = (byte)(Si[(t0 >>> 16) & 0xFF] ^ (a1 >>> 16));
         out[j++] = (byte)(Si[(t5 >>>  8) & 0xFF] ^ (a1 >>>  8));
         out[j++] = (byte)(Si[ t4         & 0xFF] ^  a1        );
         a2 = K.k102;
         out[j++] = (byte)(Si[ t2 >>> 24        ] ^ (a2 >>> 24));
         out[j++] = (byte)(Si[(t1 >>> 16) & 0xFF] ^ (a2 >>> 16));
         out[j++] = (byte)(Si[(t0 >>>  8) & 0xFF] ^ (a2 >>>  8));
         out[j++] = (byte)(Si[ t5         & 0xFF] ^  a2        );
         a3 = K.k103;
         out[j++] = (byte)(Si[ t3 >>> 24        ] ^ (a3 >>> 24));
         out[j++] = (byte)(Si[(t2 >>> 16) & 0xFF] ^ (a3 >>> 16));
         out[j++] = (byte)(Si[(t1 >>>  8) & 0xFF] ^ (a3 >>>  8));
         out[j++] = (byte)(Si[ t0         & 0xFF] ^  a3        );
         a4 = K.k104;
         out[j++] = (byte)(Si[ t4 >>> 24        ] ^ (a4 >>> 24));
         out[j++] = (byte)(Si[(t3 >>> 16) & 0xFF] ^ (a4 >>> 16));
         out[j++] = (byte)(Si[(t2 >>>  8) & 0xFF] ^ (a4 >>>  8));
         out[j++] = (byte)(Si[ t1         & 0xFF] ^  a4        );
         a5 = K.k105;
         out[j++] = (byte)(Si[ t5 >>> 24        ] ^ (a5 >>> 24));
         out[j++] = (byte)(Si[(t4 >>> 16) & 0xFF] ^ (a5 >>> 16));
         out[j++] = (byte)(Si[(t3 >>>  8) & 0xFF] ^ (a5 >>>  8));
         out[j  ] = (byte)(Si[ t2         & 0xFF] ^  a5        );

         return;
      }

      a0 = T5[t0 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      t0 = a0 ^ K.k100; t1 = a1 ^ K.k101; t2 = a2 ^ K.k102;
      t3 = a3 ^ K.k103; t4 = a4 ^ K.k104; t5 = a5 ^ K.k105;

      a0 = T5[t0 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      t0 = a0 ^ K.k110; t1 = a1 ^ K.k111; t2 = a2 ^ K.k112;
      t3 = a3 ^ K.k113; t4 = a4 ^ K.k114; t5 = a5 ^ K.k115;

      if (K.rounds == 12) {
         a0 = K.k120;
         out[j++] = (byte)(Si[ t0 >>> 24        ] ^ (a0 >>> 24));
         out[j++] = (byte)(Si[(t5 >>> 16) & 0xFF] ^ (a0 >>> 16));
         out[j++] = (byte)(Si[(t4 >>>  8) & 0xFF] ^ (a0 >>>  8));
         out[j++] = (byte)(Si[ t3         & 0xFF] ^  a0        );
         a1 = K.k121;
         out[j++] = (byte)(Si[ t1 >>> 24        ] ^ (a1 >>> 24));
         out[j++] = (byte)(Si[(t0 >>> 16) & 0xFF] ^ (a1 >>> 16));
         out[j++] = (byte)(Si[(t5 >>>  8) & 0xFF] ^ (a1 >>>  8));
         out[j++] = (byte)(Si[ t4         & 0xFF] ^  a1        );
         a2 = K.k122;
         out[j++] = (byte)(Si[ t2 >>> 24        ] ^ (a2 >>> 24));
         out[j++] = (byte)(Si[(t1 >>> 16) & 0xFF] ^ (a2 >>> 16));
         out[j++] = (byte)(Si[(t0 >>>  8) & 0xFF] ^ (a2 >>>  8));
         out[j++] = (byte)(Si[ t5         & 0xFF] ^  a2        );
         a3 = K.k123;
         out[j++] = (byte)(Si[ t3 >>> 24        ] ^ (a3 >>> 24));
         out[j++] = (byte)(Si[(t2 >>> 16) & 0xFF] ^ (a3 >>> 16));
         out[j++] = (byte)(Si[(t1 >>>  8) & 0xFF] ^ (a3 >>>  8));
         out[j++] = (byte)(Si[ t0         & 0xFF] ^  a3        );
         a4 = K.k124;
         out[j++] = (byte)(Si[ t4 >>> 24        ] ^ (a4 >>> 24));
         out[j++] = (byte)(Si[(t3 >>> 16) & 0xFF] ^ (a4 >>> 16));
         out[j++] = (byte)(Si[(t2 >>>  8) & 0xFF] ^ (a4 >>>  8));
         out[j++] = (byte)(Si[ t1         & 0xFF] ^  a4        );
         a5 = K.k125;
         out[j++] = (byte)(Si[ t5 >>> 24        ] ^ (a5 >>> 24));
         out[j++] = (byte)(Si[(t4 >>> 16) & 0xFF] ^ (a5 >>> 16));
         out[j++] = (byte)(Si[(t3 >>>  8) & 0xFF] ^ (a5 >>>  8));
         out[j  ] = (byte)(Si[ t2         & 0xFF] ^  a5        );

         return;
      }

      a0 = T5[t0 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      t0 = a0 ^ K.k120; t1 = a1 ^ K.k121; t2 = a2 ^ K.k122;
      t3 = a3 ^ K.k123; t4 = a4 ^ K.k124; t5 = a5 ^ K.k125;

      a0 = T5[t0 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      t0 = a0 ^ K.k130; t1 = a1 ^ K.k131; t2 = a2 ^ K.k132;
      t3 = a3 ^ K.k133; t4 = a4 ^ K.k134; t5 = a5 ^ K.k135;

      a0 = K.k140;
      out[j++] = (byte)(Si[ t0 >>> 24        ] ^ (a0 >>> 24));
      out[j++] = (byte)(Si[(t5 >>> 16) & 0xFF] ^ (a0 >>> 16));
      out[j++] = (byte)(Si[(t4 >>>  8) & 0xFF] ^ (a0 >>>  8));
      out[j++] = (byte)(Si[ t3         & 0xFF] ^  a0        );
      a1 = K.k141;
      out[j++] = (byte)(Si[ t1 >>> 24        ] ^ (a1 >>> 24));
      out[j++] = (byte)(Si[(t0 >>> 16) & 0xFF] ^ (a1 >>> 16));
      out[j++] = (byte)(Si[(t5 >>>  8) & 0xFF] ^ (a1 >>>  8));
      out[j++] = (byte)(Si[ t4         & 0xFF] ^  a1        );
      a2 = K.k142;
      out[j++] = (byte)(Si[ t2 >>> 24        ] ^ (a2 >>> 24));
      out[j++] = (byte)(Si[(t1 >>> 16) & 0xFF] ^ (a2 >>> 16));
      out[j++] = (byte)(Si[(t0 >>>  8) & 0xFF] ^ (a2 >>>  8));
      out[j++] = (byte)(Si[ t5         & 0xFF] ^  a2        );
      a3 = K.k143;
      out[j++] = (byte)(Si[ t3 >>> 24        ] ^ (a3 >>> 24));
      out[j++] = (byte)(Si[(t2 >>> 16) & 0xFF] ^ (a3 >>> 16));
      out[j++] = (byte)(Si[(t1 >>>  8) & 0xFF] ^ (a3 >>>  8));
      out[j++] = (byte)(Si[ t0         & 0xFF] ^  a3        );
      a4 = K.k144;
      out[j++] = (byte)(Si[ t4 >>> 24        ] ^ (a4 >>> 24));
      out[j++] = (byte)(Si[(t3 >>> 16) & 0xFF] ^ (a4 >>> 16));
      out[j++] = (byte)(Si[(t2 >>>  8) & 0xFF] ^ (a4 >>>  8));
      out[j++] = (byte)(Si[ t1         & 0xFF] ^  a4        );
      a5 = K.k145;
      out[j++] = (byte)(Si[ t5 >>> 24        ] ^ (a5 >>> 24));
      out[j++] = (byte)(Si[(t4 >>> 16) & 0xFF] ^ (a5 >>> 16));
      out[j++] = (byte)(Si[(t3 >>>  8) & 0xFF] ^ (a5 >>>  8));
      out[j  ] = (byte)(Si[ t2         & 0xFF] ^  a5        );
   }

   private static final void
   rijndael256Encrypt(byte[] in, int i, byte[] out, int j, Object key) {
      Key K = (Key)((Object[]) key)[0]; // extract encryption round keys
      int t0, t1, t2, t3, t4, t5, t6, t7, a0, a1, a2, a3, a4, a5, a6, a7;

      // plaintext to ints + key
      t0 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k00;
      t1 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k01;
      t2 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k02;
      t3 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k03;
      t4 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k04;
      t5 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k05;
      t6 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k06;
      t7 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i  ] & 0xFF)) ^ K.k07;

      // apply rounds-1 transforms
      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t6 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t6 >>> 8) & 0xFF] ^ T4[t7 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t7 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t6 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a6 = T1[t6 >>> 24] ^ T2[(t7 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      a7 = T1[t7 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      t0 = a0 ^ K.k10; t1 = a1 ^ K.k11; t2 = a2 ^ K.k12; t3 = a3 ^ K.k13;
      t4 = a4 ^ K.k14; t5 = a5 ^ K.k15; t6 = a6 ^ K.k16; t7 = a7 ^ K.k17;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t6 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t6 >>> 8) & 0xFF] ^ T4[t7 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t7 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t6 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a6 = T1[t6 >>> 24] ^ T2[(t7 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      a7 = T1[t7 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      t0 = a0 ^ K.k20; t1 = a1 ^ K.k21; t2 = a2 ^ K.k22; t3 = a3 ^ K.k23;
      t4 = a4 ^ K.k24; t5 = a5 ^ K.k25; t6 = a6 ^ K.k26; t7 = a7 ^ K.k27;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t6 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t6 >>> 8) & 0xFF] ^ T4[t7 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t7 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t6 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a6 = T1[t6 >>> 24] ^ T2[(t7 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      a7 = T1[t7 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      t0 = a0 ^ K.k30; t1 = a1 ^ K.k31; t2 = a2 ^ K.k32; t3 = a3 ^ K.k33;
      t4 = a4 ^ K.k34; t5 = a5 ^ K.k35; t6 = a6 ^ K.k36; t7 = a7 ^ K.k37;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t6 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t6 >>> 8) & 0xFF] ^ T4[t7 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t7 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t6 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a6 = T1[t6 >>> 24] ^ T2[(t7 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      a7 = T1[t7 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      t0 = a0 ^ K.k40; t1 = a1 ^ K.k41; t2 = a2 ^ K.k42; t3 = a3 ^ K.k43;
      t4 = a4 ^ K.k44; t5 = a5 ^ K.k45; t6 = a6 ^ K.k46; t7 = a7 ^ K.k47;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t6 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t6 >>> 8) & 0xFF] ^ T4[t7 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t7 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t6 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a6 = T1[t6 >>> 24] ^ T2[(t7 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      a7 = T1[t7 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      t0 = a0 ^ K.k50; t1 = a1 ^ K.k51; t2 = a2 ^ K.k52; t3 = a3 ^ K.k53;
      t4 = a4 ^ K.k54; t5 = a5 ^ K.k55; t6 = a6 ^ K.k56; t7 = a7 ^ K.k57;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t6 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t6 >>> 8) & 0xFF] ^ T4[t7 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t7 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t6 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a6 = T1[t6 >>> 24] ^ T2[(t7 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      a7 = T1[t7 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      t0 = a0 ^ K.k60; t1 = a1 ^ K.k61; t2 = a2 ^ K.k62; t3 = a3 ^ K.k63;
      t4 = a4 ^ K.k64; t5 = a5 ^ K.k65; t6 = a6 ^ K.k66; t7 = a7 ^ K.k67;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t6 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t6 >>> 8) & 0xFF] ^ T4[t7 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t7 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t6 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a6 = T1[t6 >>> 24] ^ T2[(t7 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      a7 = T1[t7 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      t0 = a0 ^ K.k70; t1 = a1 ^ K.k71; t2 = a2 ^ K.k72; t3 = a3 ^ K.k73;
      t4 = a4 ^ K.k74; t5 = a5 ^ K.k75; t6 = a6 ^ K.k76; t7 = a7 ^ K.k77;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t6 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t6 >>> 8) & 0xFF] ^ T4[t7 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t7 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t6 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a6 = T1[t6 >>> 24] ^ T2[(t7 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      a7 = T1[t7 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      t0 = a0 ^ K.k80; t1 = a1 ^ K.k81; t2 = a2 ^ K.k82; t3 = a3 ^ K.k83;
      t4 = a4 ^ K.k84; t5 = a5 ^ K.k85; t6 = a6 ^ K.k86; t7 = a7 ^ K.k87;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t6 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t6 >>> 8) & 0xFF] ^ T4[t7 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t7 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t6 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a6 = T1[t6 >>> 24] ^ T2[(t7 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      a7 = T1[t7 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      t0 = a0 ^ K.k90; t1 = a1 ^ K.k91; t2 = a2 ^ K.k92; t3 = a3 ^ K.k93;
      t4 = a4 ^ K.k94; t5 = a5 ^ K.k95; t6 = a6 ^ K.k96; t7 = a7 ^ K.k97;

      if (K.rounds == 10) { // last round is special
         a0 = K.k100;
         out[j++] = (byte)(S[ t0 >>> 24        ] ^ (a0 >>> 24));
         out[j++] = (byte)(S[(t1 >>> 16) & 0xFF] ^ (a0 >>> 16));
         out[j++] = (byte)(S[(t3 >>>  8) & 0xFF] ^ (a0 >>>  8));
         out[j++] = (byte)(S[ t4         & 0xFF] ^  a0        );
         a1 = K.k101;
         out[j++] = (byte)(S[ t1 >>> 24        ] ^ (a1 >>> 24));
         out[j++] = (byte)(S[(t2 >>> 16) & 0xFF] ^ (a1 >>> 16));
         out[j++] = (byte)(S[(t4 >>>  8) & 0xFF] ^ (a1 >>>  8));
         out[j++] = (byte)(S[ t5         & 0xFF] ^  a1        );
         a2 = K.k102;
         out[j++] = (byte)(S[ t2 >>> 24        ] ^ (a2 >>> 24));
         out[j++] = (byte)(S[(t3 >>> 16) & 0xFF] ^ (a2 >>> 16));
         out[j++] = (byte)(S[(t5 >>>  8) & 0xFF] ^ (a2 >>>  8));
         out[j++] = (byte)(S[ t6         & 0xFF] ^  a2        );
         a3 = K.k103;
         out[j++] = (byte)(S[ t3 >>> 24        ] ^ (a3 >>> 24));
         out[j++] = (byte)(S[(t4 >>> 16) & 0xFF] ^ (a3 >>> 16));
         out[j++] = (byte)(S[(t6 >>>  8) & 0xFF] ^ (a3 >>>  8));
         out[j++] = (byte)(S[ t7         & 0xFF] ^  a3        );
         a4 = K.k104;
         out[j++] = (byte)(S[ t4 >>> 24        ] ^ (a4 >>> 24));
         out[j++] = (byte)(S[(t5 >>> 16) & 0xFF] ^ (a4 >>> 16));
         out[j++] = (byte)(S[(t7 >>>  8) & 0xFF] ^ (a4 >>>  8));
         out[j++] = (byte)(S[ t0         & 0xFF] ^  a4        );
         a5 = K.k105;
         out[j++] = (byte)(S[ t5 >>> 24        ] ^ (a5 >>> 24));
         out[j++] = (byte)(S[(t6 >>> 16) & 0xFF] ^ (a5 >>> 16));
         out[j++] = (byte)(S[(t0 >>>  8) & 0xFF] ^ (a5 >>>  8));
         out[j++] = (byte)(S[ t1         & 0xFF] ^  a5        );
         a6 = K.k106;
         out[j++] = (byte)(S[ t6 >>> 24        ] ^ (a6 >>> 24));
         out[j++] = (byte)(S[(t7 >>> 16) & 0xFF] ^ (a6 >>> 16));
         out[j++] = (byte)(S[(t1 >>>  8) & 0xFF] ^ (a6 >>>  8));
         out[j++] = (byte)(S[ t2         & 0xFF] ^  a6        );
         a7 = K.k107;
         out[j++] = (byte)(S[ t7 >>> 24        ] ^ (a7 >>> 24));
         out[j++] = (byte)(S[(t0 >>> 16) & 0xFF] ^ (a7 >>> 16));
         out[j++] = (byte)(S[(t2 >>>  8) & 0xFF] ^ (a7 >>>  8));
         out[j  ] = (byte)(S[ t3         & 0xFF] ^  a7        );

         return;
      }

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t6 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t6 >>> 8) & 0xFF] ^ T4[t7 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t7 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t6 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a6 = T1[t6 >>> 24] ^ T2[(t7 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      a7 = T1[t7 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      t0 = a0 ^ K.k100; t1 = a1 ^ K.k101; t2 = a2 ^ K.k102; t3 = a3 ^ K.k103;
      t4 = a4 ^ K.k104; t5 = a5 ^ K.k105; t6 = a6 ^ K.k106; t7 = a7 ^ K.k107;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t6 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t6 >>> 8) & 0xFF] ^ T4[t7 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t7 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t6 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a6 = T1[t6 >>> 24] ^ T2[(t7 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      a7 = T1[t7 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      t0 = a0 ^ K.k110; t1 = a1 ^ K.k111; t2 = a2 ^ K.k112; t3 = a3 ^ K.k113;
      t4 = a4 ^ K.k114; t5 = a5 ^ K.k115; t6 = a6 ^ K.k116; t7 = a7 ^ K.k117;

      if (K.rounds == 12) { // last round is special
         a0 = K.k120;
         out[j++] = (byte)(S[ t0 >>> 24        ] ^ (a0 >>> 24));
         out[j++] = (byte)(S[(t1 >>> 16) & 0xFF] ^ (a0 >>> 16));
         out[j++] = (byte)(S[(t3 >>>  8) & 0xFF] ^ (a0 >>>  8));
         out[j++] = (byte)(S[ t4         & 0xFF] ^  a0        );
         a1 = K.k121;
         out[j++] = (byte)(S[ t1 >>> 24        ] ^ (a1 >>> 24));
         out[j++] = (byte)(S[(t2 >>> 16) & 0xFF] ^ (a1 >>> 16));
         out[j++] = (byte)(S[(t4 >>>  8) & 0xFF] ^ (a1 >>>  8));
         out[j++] = (byte)(S[ t5         & 0xFF] ^  a1        );
         a2 = K.k122;
         out[j++] = (byte)(S[ t2 >>> 24        ] ^ (a2 >>> 24));
         out[j++] = (byte)(S[(t3 >>> 16) & 0xFF] ^ (a2 >>> 16));
         out[j++] = (byte)(S[(t5 >>>  8) & 0xFF] ^ (a2 >>>  8));
         out[j++] = (byte)(S[ t6         & 0xFF] ^  a2        );
         a3 = K.k123;
         out[j++] = (byte)(S[ t3 >>> 24        ] ^ (a3 >>> 24));
         out[j++] = (byte)(S[(t4 >>> 16) & 0xFF] ^ (a3 >>> 16));
         out[j++] = (byte)(S[(t6 >>>  8) & 0xFF] ^ (a3 >>>  8));
         out[j++] = (byte)(S[ t7         & 0xFF] ^  a3        );
         a4 = K.k124;
         out[j++] = (byte)(S[ t4 >>> 24        ] ^ (a4 >>> 24));
         out[j++] = (byte)(S[(t5 >>> 16) & 0xFF] ^ (a4 >>> 16));
         out[j++] = (byte)(S[(t7 >>>  8) & 0xFF] ^ (a4 >>>  8));
         out[j++] = (byte)(S[ t0         & 0xFF] ^  a4        );
         a5 = K.k125;
         out[j++] = (byte)(S[ t5 >>> 24        ] ^ (a5 >>> 24));
         out[j++] = (byte)(S[(t6 >>> 16) & 0xFF] ^ (a5 >>> 16));
         out[j++] = (byte)(S[(t0 >>>  8) & 0xFF] ^ (a5 >>>  8));
         out[j++] = (byte)(S[ t1         & 0xFF] ^  a5        );
         a6 = K.k126;
         out[j++] = (byte)(S[ t6 >>> 24        ] ^ (a6 >>> 24));
         out[j++] = (byte)(S[(t7 >>> 16) & 0xFF] ^ (a6 >>> 16));
         out[j++] = (byte)(S[(t1 >>>  8) & 0xFF] ^ (a6 >>>  8));
         out[j++] = (byte)(S[ t2         & 0xFF] ^  a6        );
         a7 = K.k127;
         out[j++] = (byte)(S[ t7 >>> 24        ] ^ (a7 >>> 24));
         out[j++] = (byte)(S[(t0 >>> 16) & 0xFF] ^ (a7 >>> 16));
         out[j++] = (byte)(S[(t2 >>>  8) & 0xFF] ^ (a7 >>>  8));
         out[j  ] = (byte)(S[ t3         & 0xFF] ^  a7        );

         return;
      }

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t6 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t6 >>> 8) & 0xFF] ^ T4[t7 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t7 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t6 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a6 = T1[t6 >>> 24] ^ T2[(t7 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      a7 = T1[t7 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      t0 = a0 ^ K.k120; t1 = a1 ^ K.k121; t2 = a2 ^ K.k122; t3 = a3 ^ K.k123;
      t4 = a4 ^ K.k124; t5 = a5 ^ K.k125; t6 = a6 ^ K.k126; t7 = a7 ^ K.k127;

      a0 = T1[t0 >>> 24] ^ T2[(t1 >>> 16) & 0xFF] ^ T3[(t3 >>> 8) & 0xFF] ^ T4[t4 & 0xFF];
      a1 = T1[t1 >>> 24] ^ T2[(t2 >>> 16) & 0xFF] ^ T3[(t4 >>> 8) & 0xFF] ^ T4[t5 & 0xFF];
      a2 = T1[t2 >>> 24] ^ T2[(t3 >>> 16) & 0xFF] ^ T3[(t5 >>> 8) & 0xFF] ^ T4[t6 & 0xFF];
      a3 = T1[t3 >>> 24] ^ T2[(t4 >>> 16) & 0xFF] ^ T3[(t6 >>> 8) & 0xFF] ^ T4[t7 & 0xFF];
      a4 = T1[t4 >>> 24] ^ T2[(t5 >>> 16) & 0xFF] ^ T3[(t7 >>> 8) & 0xFF] ^ T4[t0 & 0xFF];
      a5 = T1[t5 >>> 24] ^ T2[(t6 >>> 16) & 0xFF] ^ T3[(t0 >>> 8) & 0xFF] ^ T4[t1 & 0xFF];
      a6 = T1[t6 >>> 24] ^ T2[(t7 >>> 16) & 0xFF] ^ T3[(t1 >>> 8) & 0xFF] ^ T4[t2 & 0xFF];
      a7 = T1[t7 >>> 24] ^ T2[(t0 >>> 16) & 0xFF] ^ T3[(t2 >>> 8) & 0xFF] ^ T4[t3 & 0xFF];
      t0 = a0 ^ K.k130; t1 = a1 ^ K.k131; t2 = a2 ^ K.k132; t3 = a3 ^ K.k133;
      t4 = a4 ^ K.k134; t5 = a5 ^ K.k135; t6 = a6 ^ K.k136; t7 = a7 ^ K.k137;

      // last round is special
      a0 = K.k140;
      out[j++] = (byte)(S[ t0 >>> 24        ] ^ (a0 >>> 24));
      out[j++] = (byte)(S[(t1 >>> 16) & 0xFF] ^ (a0 >>> 16));
      out[j++] = (byte)(S[(t3 >>>  8) & 0xFF] ^ (a0 >>>  8));
      out[j++] = (byte)(S[ t4         & 0xFF] ^  a0        );
      a1 = K.k141;
      out[j++] = (byte)(S[ t1 >>> 24        ] ^ (a1 >>> 24));
      out[j++] = (byte)(S[(t2 >>> 16) & 0xFF] ^ (a1 >>> 16));
      out[j++] = (byte)(S[(t4 >>>  8) & 0xFF] ^ (a1 >>>  8));
      out[j++] = (byte)(S[ t5         & 0xFF] ^  a1        );
      a2 = K.k142;
      out[j++] = (byte)(S[ t2 >>> 24        ] ^ (a2 >>> 24));
      out[j++] = (byte)(S[(t3 >>> 16) & 0xFF] ^ (a2 >>> 16));
      out[j++] = (byte)(S[(t5 >>>  8) & 0xFF] ^ (a2 >>>  8));
      out[j++] = (byte)(S[ t6         & 0xFF] ^  a2        );
      a3 = K.k143;
      out[j++] = (byte)(S[ t3 >>> 24        ] ^ (a3 >>> 24));
      out[j++] = (byte)(S[(t4 >>> 16) & 0xFF] ^ (a3 >>> 16));
      out[j++] = (byte)(S[(t6 >>>  8) & 0xFF] ^ (a3 >>>  8));
      out[j++] = (byte)(S[ t7         & 0xFF] ^  a3        );
      a4 = K.k144;
      out[j++] = (byte)(S[ t4 >>> 24        ] ^ (a4 >>> 24));
      out[j++] = (byte)(S[(t5 >>> 16) & 0xFF] ^ (a4 >>> 16));
      out[j++] = (byte)(S[(t7 >>>  8) & 0xFF] ^ (a4 >>>  8));
      out[j++] = (byte)(S[ t0         & 0xFF] ^  a4        );
      a5 = K.k145;
      out[j++] = (byte)(S[ t5 >>> 24        ] ^ (a5 >>> 24));
      out[j++] = (byte)(S[(t6 >>> 16) & 0xFF] ^ (a5 >>> 16));
      out[j++] = (byte)(S[(t0 >>>  8) & 0xFF] ^ (a5 >>>  8));
      out[j++] = (byte)(S[ t1         & 0xFF] ^  a5        );
      a6 = K.k146;
      out[j++] = (byte)(S[ t6 >>> 24        ] ^ (a6 >>> 24));
      out[j++] = (byte)(S[(t7 >>> 16) & 0xFF] ^ (a6 >>> 16));
      out[j++] = (byte)(S[(t1 >>>  8) & 0xFF] ^ (a6 >>>  8));
      out[j++] = (byte)(S[ t2         & 0xFF] ^  a6        );
      a7 = K.k147;
      out[j++] = (byte)(S[ t7 >>> 24        ] ^ (a7 >>> 24));
      out[j++] = (byte)(S[(t0 >>> 16) & 0xFF] ^ (a7 >>> 16));
      out[j++] = (byte)(S[(t2 >>>  8) & 0xFF] ^ (a7 >>>  8));
      out[j  ] = (byte)(S[ t3         & 0xFF] ^  a7        );
   }

   private static final void
   rijndael256Decrypt(byte[] in, int i, byte[] out, int j, Object key) {
      Key K = (Key)((Object[]) key)[1]; // extract decryption round keys
      int t0, t1, t2, t3, t4, t5, t6, t7, a0, a1, a2, a3, a4, a5, a6, a7;

      // ciphertext to ints + key
      t0 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k00;
      t1 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k01;
      t2 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k02;
      t3 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k03;
      t4 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k04;
      t5 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k05;
      t6 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k06;
      t7 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i  ] & 0xFF)) ^ K.k07;

      // apply rounds-1 transforms
      a0 = T5[t0 >>> 24] ^ T6[(t7 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t6 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t7 >>> 8) & 0xFF] ^ T8[t6 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t7 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a6 = T5[t6 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a7 = T5[t7 >>> 24] ^ T6[(t6 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      t0 = a0 ^ K.k10; t1 = a1 ^ K.k11; t2 = a2 ^ K.k12; t3 = a3 ^ K.k13;
      t4 = a4 ^ K.k14; t5 = a5 ^ K.k15; t6 = a6 ^ K.k16; t7 = a7 ^ K.k17;

      a0 = T5[t0 >>> 24] ^ T6[(t7 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t6 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t7 >>> 8) & 0xFF] ^ T8[t6 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t7 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a6 = T5[t6 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a7 = T5[t7 >>> 24] ^ T6[(t6 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      t0 = a0 ^ K.k20; t1 = a1 ^ K.k21; t2 = a2 ^ K.k22; t3 = a3 ^ K.k23;
      t4 = a4 ^ K.k24; t5 = a5 ^ K.k25; t6 = a6 ^ K.k26; t7 = a7 ^ K.k27;

      a0 = T5[t0 >>> 24] ^ T6[(t7 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t6 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t7 >>> 8) & 0xFF] ^ T8[t6 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t7 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a6 = T5[t6 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a7 = T5[t7 >>> 24] ^ T6[(t6 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      t0 = a0 ^ K.k30; t1 = a1 ^ K.k31; t2 = a2 ^ K.k32; t3 = a3 ^ K.k33;
      t4 = a4 ^ K.k34; t5 = a5 ^ K.k35; t6 = a6 ^ K.k36; t7 = a7 ^ K.k37;

      a0 = T5[t0 >>> 24] ^ T6[(t7 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t6 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t7 >>> 8) & 0xFF] ^ T8[t6 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t7 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a6 = T5[t6 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a7 = T5[t7 >>> 24] ^ T6[(t6 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      t0 = a0 ^ K.k40; t1 = a1 ^ K.k41; t2 = a2 ^ K.k42; t3 = a3 ^ K.k43;
      t4 = a4 ^ K.k44; t5 = a5 ^ K.k45; t6 = a6 ^ K.k46; t7 = a7 ^ K.k47;

      a0 = T5[t0 >>> 24] ^ T6[(t7 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t6 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t7 >>> 8) & 0xFF] ^ T8[t6 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t7 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a6 = T5[t6 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a7 = T5[t7 >>> 24] ^ T6[(t6 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      t0 = a0 ^ K.k50; t1 = a1 ^ K.k51; t2 = a2 ^ K.k52; t3 = a3 ^ K.k53;
      t4 = a4 ^ K.k54; t5 = a5 ^ K.k55; t6 = a6 ^ K.k56; t7 = a7 ^ K.k57;

      a0 = T5[t0 >>> 24] ^ T6[(t7 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t6 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t7 >>> 8) & 0xFF] ^ T8[t6 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t7 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a6 = T5[t6 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a7 = T5[t7 >>> 24] ^ T6[(t6 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      t0 = a0 ^ K.k60; t1 = a1 ^ K.k61; t2 = a2 ^ K.k62; t3 = a3 ^ K.k63;
      t4 = a4 ^ K.k64; t5 = a5 ^ K.k65; t6 = a6 ^ K.k66; t7 = a7 ^ K.k67;

      a0 = T5[t0 >>> 24] ^ T6[(t7 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t6 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t7 >>> 8) & 0xFF] ^ T8[t6 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t7 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a6 = T5[t6 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a7 = T5[t7 >>> 24] ^ T6[(t6 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      t0 = a0 ^ K.k70; t1 = a1 ^ K.k71; t2 = a2 ^ K.k72; t3 = a3 ^ K.k73;
      t4 = a4 ^ K.k74; t5 = a5 ^ K.k75; t6 = a6 ^ K.k76; t7 = a7 ^ K.k77;

      a0 = T5[t0 >>> 24] ^ T6[(t7 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t6 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t7 >>> 8) & 0xFF] ^ T8[t6 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t7 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a6 = T5[t6 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a7 = T5[t7 >>> 24] ^ T6[(t6 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      t0 = a0 ^ K.k80; t1 = a1 ^ K.k81; t2 = a2 ^ K.k82; t3 = a3 ^ K.k83;
      t4 = a4 ^ K.k84; t5 = a5 ^ K.k85; t6 = a6 ^ K.k86; t7 = a7 ^ K.k87;

      a0 = T5[t0 >>> 24] ^ T6[(t7 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t6 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t7 >>> 8) & 0xFF] ^ T8[t6 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t7 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a6 = T5[t6 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a7 = T5[t7 >>> 24] ^ T6[(t6 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      t0 = a0 ^ K.k90; t1 = a1 ^ K.k91; t2 = a2 ^ K.k92; t3 = a3 ^ K.k93;
      t4 = a4 ^ K.k94; t5 = a5 ^ K.k95; t6 = a6 ^ K.k96; t7 = a7 ^ K.k97;

      if (K.rounds == 10) {
         a0 = K.k100;
         out[j++] = (byte)(Si[ t0 >>> 24        ] ^ (a0 >>> 24));
         out[j++] = (byte)(Si[(t7 >>> 16) & 0xFF] ^ (a0 >>> 16));
         out[j++] = (byte)(Si[(t5 >>>  8) & 0xFF] ^ (a0 >>>  8));
         out[j++] = (byte)(Si[ t4         & 0xFF] ^  a0        );
         a1 = K.k101;
         out[j++] = (byte)(Si[ t1 >>> 24        ] ^ (a1 >>> 24));
         out[j++] = (byte)(Si[(t0 >>> 16) & 0xFF] ^ (a1 >>> 16));
         out[j++] = (byte)(Si[(t6 >>>  8) & 0xFF] ^ (a1 >>>  8));
         out[j++] = (byte)(Si[ t5         & 0xFF] ^  a1        );
         a2 = K.k102;
         out[j++] = (byte)(Si[ t2 >>> 24        ] ^ (a2 >>> 24));
         out[j++] = (byte)(Si[(t1 >>> 16) & 0xFF] ^ (a2 >>> 16));
         out[j++] = (byte)(Si[(t7 >>>  8) & 0xFF] ^ (a2 >>>  8));
         out[j++] = (byte)(Si[ t6         & 0xFF] ^  a2        );
         a3 = K.k103;
         out[j++] = (byte)(Si[ t3 >>> 24        ] ^ (a3 >>> 24));
         out[j++] = (byte)(Si[(t2 >>> 16) & 0xFF] ^ (a3 >>> 16));
         out[j++] = (byte)(Si[(t0 >>>  8) & 0xFF] ^ (a3 >>>  8));
         out[j++] = (byte)(Si[ t7         & 0xFF] ^  a3        );
         a4 = K.k104;
         out[j++] = (byte)(Si[ t4 >>> 24        ] ^ (a4 >>> 24));
         out[j++] = (byte)(Si[(t3 >>> 16) & 0xFF] ^ (a4 >>> 16));
         out[j++] = (byte)(Si[(t1 >>>  8) & 0xFF] ^ (a4 >>>  8));
         out[j++] = (byte)(Si[ t0         & 0xFF] ^  a4        );
         a5 = K.k105;
         out[j++] = (byte)(Si[ t5 >>> 24        ] ^ (a5 >>> 24));
         out[j++] = (byte)(Si[(t4 >>> 16) & 0xFF] ^ (a5 >>> 16));
         out[j++] = (byte)(Si[(t2 >>>  8) & 0xFF] ^ (a5 >>>  8));
         out[j++] = (byte)(Si[ t1         & 0xFF] ^  a5        );
         a6 = K.k106;
         out[j++] = (byte)(Si[ t6 >>> 24        ] ^ (a6 >>> 24));
         out[j++] = (byte)(Si[(t5 >>> 16) & 0xFF] ^ (a6 >>> 16));
         out[j++] = (byte)(Si[(t3 >>>  8) & 0xFF] ^ (a6 >>>  8));
         out[j++] = (byte)(Si[ t2         & 0xFF] ^  a6        );
         a7 = K.k107;
         out[j++] = (byte)(Si[ t7 >>> 24        ] ^ (a7 >>> 24));
         out[j++] = (byte)(Si[(t6 >>> 16) & 0xFF] ^ (a7 >>> 16));
         out[j++] = (byte)(Si[(t4 >>>  8) & 0xFF] ^ (a7 >>>  8));
         out[j  ] = (byte)(Si[ t3         & 0xFF] ^  a7        );

         return;
      }

      a0 = T5[t0 >>> 24] ^ T6[(t7 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t6 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t7 >>> 8) & 0xFF] ^ T8[t6 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t7 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a6 = T5[t6 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a7 = T5[t7 >>> 24] ^ T6[(t6 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      t0 = a0 ^ K.k100; t1 = a1 ^ K.k101; t2 = a2 ^ K.k102; t3 = a3 ^ K.k103;
      t4 = a4 ^ K.k104; t5 = a5 ^ K.k105; t6 = a6 ^ K.k106; t7 = a7 ^ K.k107;

      a0 = T5[t0 >>> 24] ^ T6[(t7 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t6 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t7 >>> 8) & 0xFF] ^ T8[t6 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t7 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a6 = T5[t6 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a7 = T5[t7 >>> 24] ^ T6[(t6 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      t0 = a0 ^ K.k110; t1 = a1 ^ K.k111; t2 = a2 ^ K.k112; t3 = a3 ^ K.k113;
      t4 = a4 ^ K.k114; t5 = a5 ^ K.k115; t6 = a6 ^ K.k116; t7 = a7 ^ K.k117;

      if (K.rounds == 12) {
         a0 = K.k120;
         out[j++] = (byte)(Si[ t0 >>> 24        ] ^ (a0 >>> 24));
         out[j++] = (byte)(Si[(t7 >>> 16) & 0xFF] ^ (a0 >>> 16));
         out[j++] = (byte)(Si[(t5 >>>  8) & 0xFF] ^ (a0 >>>  8));
         out[j++] = (byte)(Si[ t4         & 0xFF] ^  a0        );
         a1 = K.k121;
         out[j++] = (byte)(Si[ t1 >>> 24        ] ^ (a1 >>> 24));
         out[j++] = (byte)(Si[(t0 >>> 16) & 0xFF] ^ (a1 >>> 16));
         out[j++] = (byte)(Si[(t6 >>>  8) & 0xFF] ^ (a1 >>>  8));
         out[j++] = (byte)(Si[ t5         & 0xFF] ^  a1        );
         a2 = K.k122;
         out[j++] = (byte)(Si[ t2 >>> 24        ] ^ (a2 >>> 24));
         out[j++] = (byte)(Si[(t1 >>> 16) & 0xFF] ^ (a2 >>> 16));
         out[j++] = (byte)(Si[(t7 >>>  8) & 0xFF] ^ (a2 >>>  8));
         out[j++] = (byte)(Si[ t6         & 0xFF] ^  a2        );
         a3 = K.k123;
         out[j++] = (byte)(Si[ t3 >>> 24        ] ^ (a3 >>> 24));
         out[j++] = (byte)(Si[(t2 >>> 16) & 0xFF] ^ (a3 >>> 16));
         out[j++] = (byte)(Si[(t0 >>>  8) & 0xFF] ^ (a3 >>>  8));
         out[j++] = (byte)(Si[ t7         & 0xFF] ^  a3        );
         a4 = K.k124;
         out[j++] = (byte)(Si[ t4 >>> 24        ] ^ (a4 >>> 24));
         out[j++] = (byte)(Si[(t3 >>> 16) & 0xFF] ^ (a4 >>> 16));
         out[j++] = (byte)(Si[(t1 >>>  8) & 0xFF] ^ (a4 >>>  8));
         out[j++] = (byte)(Si[ t0         & 0xFF] ^  a4        );
         a5 = K.k125;
         out[j++] = (byte)(Si[ t5 >>> 24        ] ^ (a5 >>> 24));
         out[j++] = (byte)(Si[(t4 >>> 16) & 0xFF] ^ (a5 >>> 16));
         out[j++] = (byte)(Si[(t2 >>>  8) & 0xFF] ^ (a5 >>>  8));
         out[j++] = (byte)(Si[ t1         & 0xFF] ^  a5        );
         a6 = K.k126;
         out[j++] = (byte)(Si[ t6 >>> 24        ] ^ (a6 >>> 24));
         out[j++] = (byte)(Si[(t5 >>> 16) & 0xFF] ^ (a6 >>> 16));
         out[j++] = (byte)(Si[(t3 >>>  8) & 0xFF] ^ (a6 >>>  8));
         out[j++] = (byte)(Si[ t2         & 0xFF] ^  a6        );
         a7 = K.k127;
         out[j++] = (byte)(Si[ t7 >>> 24        ] ^ (a7 >>> 24));
         out[j++] = (byte)(Si[(t6 >>> 16) & 0xFF] ^ (a7 >>> 16));
         out[j++] = (byte)(Si[(t4 >>>  8) & 0xFF] ^ (a7 >>>  8));
         out[j  ] = (byte)(Si[ t3         & 0xFF] ^  a7        );

         return;
      }

      a0 = T5[t0 >>> 24] ^ T6[(t7 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t6 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t7 >>> 8) & 0xFF] ^ T8[t6 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t7 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a6 = T5[t6 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a7 = T5[t7 >>> 24] ^ T6[(t6 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      t0 = a0 ^ K.k120; t1 = a1 ^ K.k121; t2 = a2 ^ K.k122; t3 = a3 ^ K.k123;
      t4 = a4 ^ K.k124; t5 = a5 ^ K.k125; t6 = a6 ^ K.k126; t7 = a7 ^ K.k127;

      a0 = T5[t0 >>> 24] ^ T6[(t7 >>> 16) & 0xFF] ^ T7[(t5 >>> 8) & 0xFF] ^ T8[t4 & 0xFF];
      a1 = T5[t1 >>> 24] ^ T6[(t0 >>> 16) & 0xFF] ^ T7[(t6 >>> 8) & 0xFF] ^ T8[t5 & 0xFF];
      a2 = T5[t2 >>> 24] ^ T6[(t1 >>> 16) & 0xFF] ^ T7[(t7 >>> 8) & 0xFF] ^ T8[t6 & 0xFF];
      a3 = T5[t3 >>> 24] ^ T6[(t2 >>> 16) & 0xFF] ^ T7[(t0 >>> 8) & 0xFF] ^ T8[t7 & 0xFF];
      a4 = T5[t4 >>> 24] ^ T6[(t3 >>> 16) & 0xFF] ^ T7[(t1 >>> 8) & 0xFF] ^ T8[t0 & 0xFF];
      a5 = T5[t5 >>> 24] ^ T6[(t4 >>> 16) & 0xFF] ^ T7[(t2 >>> 8) & 0xFF] ^ T8[t1 & 0xFF];
      a6 = T5[t6 >>> 24] ^ T6[(t5 >>> 16) & 0xFF] ^ T7[(t3 >>> 8) & 0xFF] ^ T8[t2 & 0xFF];
      a7 = T5[t7 >>> 24] ^ T6[(t6 >>> 16) & 0xFF] ^ T7[(t4 >>> 8) & 0xFF] ^ T8[t3 & 0xFF];
      t0 = a0 ^ K.k130; t1 = a1 ^ K.k131; t2 = a2 ^ K.k132; t3 = a3 ^ K.k133;
      t4 = a4 ^ K.k134; t5 = a5 ^ K.k135; t6 = a6 ^ K.k136; t7 = a7 ^ K.k137;

      a0 = K.k140;
      out[j++] = (byte)(Si[ t0 >>> 24        ] ^ (a0 >>> 24));
      out[j++] = (byte)(Si[(t7 >>> 16) & 0xFF] ^ (a0 >>> 16));
      out[j++] = (byte)(Si[(t5 >>>  8) & 0xFF] ^ (a0 >>>  8));
      out[j++] = (byte)(Si[ t4         & 0xFF] ^  a0        );
      a1 = K.k141;
      out[j++] = (byte)(Si[ t1 >>> 24        ] ^ (a1 >>> 24));
      out[j++] = (byte)(Si[(t0 >>> 16) & 0xFF] ^ (a1 >>> 16));
      out[j++] = (byte)(Si[(t6 >>>  8) & 0xFF] ^ (a1 >>>  8));
      out[j++] = (byte)(Si[ t5         & 0xFF] ^  a1        );
      a2 = K.k142;
      out[j++] = (byte)(Si[ t2 >>> 24        ] ^ (a2 >>> 24));
      out[j++] = (byte)(Si[(t1 >>> 16) & 0xFF] ^ (a2 >>> 16));
      out[j++] = (byte)(Si[(t7 >>>  8) & 0xFF] ^ (a2 >>>  8));
      out[j++] = (byte)(Si[ t6         & 0xFF] ^  a2        );
      a3 = K.k143;
      out[j++] = (byte)(Si[ t3 >>> 24        ] ^ (a3 >>> 24));
      out[j++] = (byte)(Si[(t2 >>> 16) & 0xFF] ^ (a3 >>> 16));
      out[j++] = (byte)(Si[(t0 >>>  8) & 0xFF] ^ (a3 >>>  8));
      out[j++] = (byte)(Si[ t7         & 0xFF] ^  a3        );
      a4 = K.k144;
      out[j++] = (byte)(Si[ t4 >>> 24        ] ^ (a4 >>> 24));
      out[j++] = (byte)(Si[(t3 >>> 16) & 0xFF] ^ (a4 >>> 16));
      out[j++] = (byte)(Si[(t1 >>>  8) & 0xFF] ^ (a4 >>>  8));
      out[j++] = (byte)(Si[ t0         & 0xFF] ^  a4        );
      a5 = K.k145;
      out[j++] = (byte)(Si[ t5 >>> 24        ] ^ (a5 >>> 24));
      out[j++] = (byte)(Si[(t4 >>> 16) & 0xFF] ^ (a5 >>> 16));
      out[j++] = (byte)(Si[(t2 >>>  8) & 0xFF] ^ (a5 >>>  8));
      out[j++] = (byte)(Si[ t1         & 0xFF] ^  a5        );
      a6 = K.k146;
      out[j++] = (byte)(Si[ t6 >>> 24        ] ^ (a6 >>> 24));
      out[j++] = (byte)(Si[(t5 >>> 16) & 0xFF] ^ (a6 >>> 16));
      out[j++] = (byte)(Si[(t3 >>>  8) & 0xFF] ^ (a6 >>>  8));
      out[j++] = (byte)(Si[ t2         & 0xFF] ^  a6        );
      a7 = K.k147;
      out[j++] = (byte)(Si[ t7 >>> 24        ] ^ (a7 >>> 24));
      out[j++] = (byte)(Si[(t6 >>> 16) & 0xFF] ^ (a7 >>> 16));
      out[j++] = (byte)(Si[(t4 >>>  8) & 0xFF] ^ (a7 >>>  8));
      out[j  ] = (byte)(Si[ t3         & 0xFF] ^  a7        );
   }

   // Instance methods
   // -------------------------------------------------------------------------

   // java.lang.Cloneable interface implementation ----------------------------

   public Object clone() {
      Rijndael result = new Rijndael();
      result.currentBlockSize = this.currentBlockSize;

      return result;
   }

   // IBlockCipherSpi interface implementation --------------------------------

   public Iterator blockSizes() {
      ArrayList al = new ArrayList();
      al.add(new Integer(128 / 8));
      al.add(new Integer(192 / 8));
      al.add(new Integer(256 / 8));

      return Collections.unmodifiableList(al).iterator();
   }

   public Iterator keySizes() {
      ArrayList al = new ArrayList();
      al.add(new Integer(128 / 8));
      al.add(new Integer(192 / 8));
      al.add(new Integer(256 / 8));

      return Collections.unmodifiableList(al).iterator();
   }

   /**
    * Expands a user-supplied key material into a session key for a designated
    * <i>block size</i>.
    *
    * @param k the 128/192/256-bit user-key to use.
    * @param bs the block size in bytes of this Rijndael.
    * @return an Object encapsulating the session key.
    * @exception IllegalArgumentException if the block size is not 16, 24 or 32.
    * @exception InvalidKeyException if the key data is invalid.
    */
   public Object makeKey(byte[] k, int bs) throws InvalidKeyException {
      if (k == null) {
         throw new InvalidKeyException("Empty key");
      }
      if (!(k.length == 16 || k.length == 24 || k.length == 32)) {
         throw new InvalidKeyException("Incorrect key length");
      }
      if (!(bs == 16 || bs == 24 || bs == 32)) {
         throw new IllegalArgumentException();
      }

      int ROUNDS = getRounds(k.length, bs);
      int BC = bs / 4;
      int[][] ke = new int[ROUNDS + 1][BC]; // encryption round keys
      int[][] kd = new int[ROUNDS + 1][BC]; // decryption round keys
      int ROUND_KEY_COUNT = (ROUNDS + 1) * BC;
      int KC = k.length / 4;
      int[] tk = new int[KC];
      int i, j;

      // copy user material bytes into temporary ints
      for (i = 0, j = 0; i < KC; ) {
         tk[i++] = k[j++] << 24 | (k[j++] & 0xFF) << 16 | (k[j++] & 0xFF) << 8 | (k[j++] & 0xFF);
      }
      // copy values into round key arrays
      int t = 0;
      for (j = 0; (j < KC) && (t < ROUND_KEY_COUNT); j++, t++) {
         ke[t / BC][t % BC] = tk[j];
         kd[ROUNDS - (t / BC)][t % BC] = tk[j];
      }
      int tt, rconpointer = 0;
      while (t < ROUND_KEY_COUNT) {
         // extrapolate using phi (the round key evolution function)
         tt = tk[KC - 1];
         tk[0] ^=  S[(tt >>> 16) & 0xFF]         << 24 ^
                  (S[(tt >>>  8) & 0xFF] & 0xFF) << 16 ^
                  (S[ tt         & 0xFF] & 0xFF) <<  8 ^
                  (S[ tt >>> 24        ] & 0xFF)       ^
                   rcon[rconpointer++]           << 24;
         if (KC != 8) {
            for (i = 1, j = 0; i < KC; ) {
               tk[i++] ^= tk[j++];
            }
         } else {
            for (i = 1, j = 0; i < KC / 2; ) {
               tk[i++] ^= tk[j++];
            }
            tt = tk[KC / 2 - 1];
            tk[KC / 2] ^= (S[ tt         & 0xFF] & 0xFF)       ^
                          (S[(tt >>>  8) & 0xFF] & 0xFF) <<  8 ^
                          (S[(tt >>> 16) & 0xFF] & 0xFF) << 16 ^
                           S[ tt >>> 24        ]         << 24;
            for (j = KC / 2, i = j + 1; i < KC; ) {
               tk[i++] ^= tk[j++];
            }
         }
         // copy values into round key arrays
         for (j = 0; (j < KC) && (t < ROUND_KEY_COUNT); j++, t++) {
            ke[t / BC][t % BC] = tk[j];
            kd[ROUNDS - (t / BC)][t % BC] = tk[j];
         }
      }

      Key Ke = new Key(ke);
      Key Kd = new Key(kd);

      // inverse MixColumn where needed
      // r = 1
      i = Kd.k10; Kd.k10 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k11; Kd.k11 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k12; Kd.k12 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k13; Kd.k13 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      // r = 2
      i = Kd.k20; Kd.k20 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k21; Kd.k21 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k22; Kd.k22 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k23; Kd.k23 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      // r = 3
      i = Kd.k30; Kd.k30 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k31; Kd.k31 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k32; Kd.k32 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k33; Kd.k33 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      // r = 4
      i = Kd.k40; Kd.k40 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k41; Kd.k41 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k42; Kd.k42 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k43; Kd.k43 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      // r = 5
      i = Kd.k50; Kd.k50 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k51; Kd.k51 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k52; Kd.k52 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k53; Kd.k53 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      // r = 6
      i = Kd.k60; Kd.k60 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k61; Kd.k61 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k62; Kd.k62 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k63; Kd.k63 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      // r = 7
      i = Kd.k70; Kd.k70 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k71; Kd.k71 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k72; Kd.k72 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k73; Kd.k73 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      // r = 8
      i = Kd.k80; Kd.k80 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k81; Kd.k81 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k82; Kd.k82 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k83; Kd.k83 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      // r = 9
      i = Kd.k90; Kd.k90 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k91; Kd.k91 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k92; Kd.k92 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
      i = Kd.k93; Kd.k93 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];

      if (BC > 4) {
         i = Kd.k14; Kd.k14 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k15; Kd.k15 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k24; Kd.k24 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k25; Kd.k25 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k34; Kd.k34 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k35; Kd.k35 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k44; Kd.k44 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k45; Kd.k45 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k54; Kd.k54 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k55; Kd.k55 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k64; Kd.k64 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k65; Kd.k65 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k74; Kd.k74 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k75; Kd.k75 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k84; Kd.k84 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k85; Kd.k85 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k94; Kd.k94 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k95; Kd.k95 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         if (BC > 6) {
            i = Kd.k16; Kd.k16 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k17; Kd.k17 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k26; Kd.k26 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k27; Kd.k27 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k36; Kd.k36 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k37; Kd.k37 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k46; Kd.k46 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k47; Kd.k47 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k56; Kd.k56 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k57; Kd.k57 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k66; Kd.k66 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k67; Kd.k67 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k76; Kd.k76 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k77; Kd.k77 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k86; Kd.k86 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k87; Kd.k87 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k96; Kd.k96 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k97; Kd.k97 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         }
      }

      if (ROUNDS > 10) {
         // r = 10
         i = Kd.k100; Kd.k100 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k101; Kd.k101 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k102; Kd.k102 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k103; Kd.k103 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         // r = 11
         i = Kd.k110; Kd.k110 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k111; Kd.k111 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k112; Kd.k112 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
         i = Kd.k113; Kd.k113 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];

         if (BC > 4) {
            i = Kd.k104; Kd.k104 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k105; Kd.k105 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k114; Kd.k114 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k115; Kd.k115 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            if (BC > 6) {
               i = Kd.k106; Kd.k106 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
               i = Kd.k107; Kd.k107 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
               i = Kd.k116; Kd.k116 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
               i = Kd.k117; Kd.k117 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            }
         }

         if (ROUNDS > 12) {
            // r = 12
            i = Kd.k120; Kd.k120 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k121; Kd.k121 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k122; Kd.k122 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k123; Kd.k123 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            // r = 13
            i = Kd.k130; Kd.k130 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k131; Kd.k131 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k132; Kd.k132 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
            i = Kd.k133; Kd.k133 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];

            if (BC > 4) {
               i = Kd.k124; Kd.k124 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
               i = Kd.k125; Kd.k125 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
               i = Kd.k134; Kd.k134 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
               i = Kd.k135; Kd.k135 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
               if (BC > 6) {
                  i = Kd.k126; Kd.k126 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
                  i = Kd.k127; Kd.k127 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
                  i = Kd.k136; Kd.k136 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
                  i = Kd.k137; Kd.k137 = U1[i >>> 24] ^ U2[(i >>> 16) & 0xFF] ^ U3[(i >>> 8) & 0xFF] ^ U4[i & 0xFF];
               }
            }
         }
      }

      return new Object[] { Ke, Kd };
   }

   public void encrypt(byte[] in, int i, byte[] out, int j, Object k, int bs) {
      switch (bs) {
      case 16: aesEncrypt(in, i, out, j, k); break;
      case 24: rijndael192Encrypt(in, i, out, j, k); break;
      case 32: rijndael256Encrypt(in, i, out, j, k); break;
      default: throw new IllegalArgumentException();
      }
   }

   public void decrypt(byte[] in, int i, byte[] out, int j, Object k, int bs) {
      switch (bs) {
      case 16: aesDecrypt(in, i, out, j, k); break;
      case 24: rijndael192Decrypt(in, i, out, j, k); break;
      case 32: rijndael256Decrypt(in, i, out, j, k); break;
      default: throw new IllegalArgumentException();
      }
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

   // Inner classes
   // =========================================================================

   private class Key {
      int rounds, bc;
      int k00,  k01,  k02,  k03,  k04,  k05,  k06,  k07,  k08;
      int k10,  k11,  k12,  k13,  k14,  k15,  k16,  k17,  k18;
      int k20,  k21,  k22,  k23,  k24,  k25,  k26,  k27,  k28;
      int k30,  k31,  k32,  k33,  k34,  k35,  k36,  k37,  k38;
      int k40,  k41,  k42,  k43,  k44,  k45,  k46,  k47,  k48;
      int k50,  k51,  k52,  k53,  k54,  k55,  k56,  k57,  k58;
      int k60,  k61,  k62,  k63,  k64,  k65,  k66,  k67,  k68;
      int k70,  k71,  k72,  k73,  k74,  k75,  k76,  k77,  k78;
      int k80,  k81,  k82,  k83,  k84,  k85,  k86,  k87,  k88;
      int k90,  k91,  k92,  k93,  k94,  k95,  k96,  k97,  k98;
      int k100, k101, k102, k103, k104, k105, k106, k107, k108;
      int k110, k111, k112, k113, k114, k115, k116, k117, k118;
      int k120, k121, k122, k123, k124, k125, k126, k127, k128;
      int k130, k131, k132, k133, k134, k135, k136, k137, k138;
      int k140, k141, k142, k143, k144, k145, k146, k147, k148;

      Key(int[][] k) {
         super();

         rounds = k.length - 1;
         bc = k[0].length;
         k00 =  k[ 0][0]; k01 =  k[ 0][1]; k02 =  k[ 0][2]; k03 =  k[ 0][3];
         k10 =  k[ 1][0]; k11 =  k[ 1][1]; k12 =  k[ 1][2]; k13 =  k[ 1][3];
         k20 =  k[ 2][0]; k21 =  k[ 2][1]; k22 =  k[ 2][2]; k23 =  k[ 2][3];
         k30 =  k[ 3][0]; k31 =  k[ 3][1]; k32 =  k[ 3][2]; k33 =  k[ 3][3];
         k40 =  k[ 4][0]; k41 =  k[ 4][1]; k42 =  k[ 4][2]; k43 =  k[ 4][3];
         k50 =  k[ 5][0]; k51 =  k[ 5][1]; k52 =  k[ 5][2]; k53 =  k[ 5][3];
         k60 =  k[ 6][0]; k61 =  k[ 6][1]; k62 =  k[ 6][2]; k63 =  k[ 6][3];
         k70 =  k[ 7][0]; k71 =  k[ 7][1]; k72 =  k[ 7][2]; k73 =  k[ 7][3];
         k80 =  k[ 8][0]; k81 =  k[ 8][1]; k82 =  k[ 8][2]; k83 =  k[ 8][3];
         k90 =  k[ 9][0]; k91 =  k[ 9][1]; k92 =  k[ 9][2]; k93 =  k[ 9][3];
         k100 = k[10][0]; k101 = k[10][1]; k102 = k[10][2]; k103 = k[10][3];

         if (bc > 4) {
            k04 =  k[ 0][4]; k05 =  k[ 0][5];
            k14 =  k[ 1][4]; k15 =  k[ 1][5];
            k24 =  k[ 2][4]; k25 =  k[ 2][5];
            k34 =  k[ 3][4]; k35 =  k[ 3][5];
            k44 =  k[ 4][4]; k45 =  k[ 4][5];
            k54 =  k[ 5][4]; k55 =  k[ 5][5];
            k64 =  k[ 6][4]; k65 =  k[ 6][5];
            k74 =  k[ 7][4]; k75 =  k[ 7][5];
            k84 =  k[ 8][4]; k85 =  k[ 8][5];
            k94 =  k[ 9][4]; k95 =  k[ 9][5];
            k104 = k[10][4]; k105 = k[10][5];

            if (bc > 6) {
               k06 =  k[ 0][6]; k07 =  k[ 0][7];
               k16 =  k[ 1][6]; k17 =  k[ 1][7];
               k26 =  k[ 2][6]; k27 =  k[ 2][7];
               k36 =  k[ 3][6]; k37 =  k[ 3][7];
               k46 =  k[ 4][6]; k47 =  k[ 4][7];
               k56 =  k[ 5][6]; k57 =  k[ 5][7];
               k66 =  k[ 6][6]; k67 =  k[ 6][7];
               k76 =  k[ 7][6]; k77 =  k[ 7][7];
               k86 =  k[ 8][6]; k87 =  k[ 8][7];
               k96 =  k[ 9][6]; k97 =  k[ 9][7];
               k106 = k[10][6]; k107 = k[10][7];
            }
         }

         if (rounds > 10) {
            k110 = k[11][0]; k111 = k[11][1]; k112 = k[11][2]; k113 = k[11][3];
            k120 = k[12][0]; k121 = k[12][1]; k122 = k[12][2]; k123 = k[12][3];

            if (bc > 4) {
               k114 = k[11][4]; k115 = k[11][5];
               k124 = k[12][4]; k125 = k[12][5];

               if (bc > 6) {
                  k116 = k[11][6]; k117 = k[11][7];
                  k126 = k[12][6]; k127 = k[12][7];
               }
            }

            if (rounds > 12) {
               k130 = k[13][0]; k131 = k[13][1]; k132 = k[13][2]; k133 = k[13][3];
               k140 = k[14][0]; k141 = k[14][1]; k142 = k[14][2]; k143 = k[14][3];

               if (bc > 4) {
                  k134 = k[13][4]; k135 = k[13][5];
                  k144 = k[14][4]; k145 = k[14][5];

                  if (bc > 6) {
                     k136 = k[13][6]; k137 = k[13][7];
                     k146 = k[14][6]; k147 = k[14][7];
                  }
               }
            }
         }
      }
   }
}

