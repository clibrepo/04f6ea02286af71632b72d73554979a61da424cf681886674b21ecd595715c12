package gnu.crypto.cipher;

// ----------------------------------------------------------------------------
// $Id: Khazad.java,v 1.2 2002/12/10 13:23:50 raif Exp $
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

import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;

/**
 * <p>Khazad is a 64-bit (legacy-level) block cipher that accepts a 128-bit key.
 * The cipher is a uniform substitution-permutation network whose inverse only
 * differs from the forward operation in the key schedule. The overall cipher
 * design follows the Wide Trail strategy, favours component reuse, and permits
 * a wide variety of implementation trade-offs.</p>
 *
 * <p>References:</p>
 *
 * <ol>
 *    <li><a href="http://planeta.terra.com.br/informatica/paulobarreto/KhazadPage.html">The
 *    Khazad Block Cipher</a>.<br>
 *    <a href="mailto:paulo.barreto@terra.com.br">Paulo S.L.M. Barreto</a> and
 *    <a href="mailto:vincent.rijmen@esat.kuleuven.ac.be">Vincent Rijmen</a>.</li>
 * </ol>
 *
 * @version $Revision: 1.2 $
 */
public final class Khazad extends BaseCipher {

   // Constants and variables
   // -------------------------------------------------------------------------

   private static final int DEFAULT_BLOCK_SIZE = 8; // in bytes
   private static final int DEFAULT_KEY_SIZE = 16; // in bytes

   private static final String Sd = // p. 20 [KHAZAD]
      "\uBA54\u2F74\u53D3\uD24D\u50AC\u8DBF\u7052\u9A4C"+
      "\uEAD5\u97D1\u3351\u5BA6\uDE48\uA899\uDB32\uB7FC"+
      "\uE39E\u919B\uE2BB\u416E\uA5CB\u6B95\uA1F3\uB102"+
      "\uCCC4\u1D14\uC363\uDA5D\u5FDC\u7DCD\u7F5A\u6C5C"+
      "\uF726\uFFED\uE89D\u6F8E\u19A0\uF089\u0F07\uAFFB"+
      "\u0815\u0D04\u0164\uDF76\u79DD\u3D16\u3F37\u6D38"+
      "\uB973\uE935\u5571\u7B8C\u7288\uF62A\u3E5E\u2746"+
      "\u0C65\u6861\u03C1\u57D6\uD958\uD866\uD73A\uC83C"+
      "\uFA96\uA798\uECB8\uC7AE\u694B\uABA9\u670A\u47F2"+
      "\uB522\uE5EE\uBE2B\u8112\u831B\u0E23\uF545\u21CE"+
      "\u492C\uF9E6\uB628\u1782\u1A8B\uFE8A\u09C9\u874E"+
      "\uE12E\uE4E0\uEB90\uA41E\u8560\u0025\uF4F1\u940B"+
      "\uE775\uEF34\u31D4\uD086\u7EAD\uFD29\u303B\u9FF8"+
      "\uC613\u0605\uC511\u777C\u7A78\u361C\u3959\u1856"+
      "\uB3B0\u2420\uB292\uA3C0\u4462\u10B4\u8443\u93C2"+
      "\u4ABD\u8F2D\uBC9C\u6A40\uCFA2\u804F\u1FCA\uAA42";

   private static final byte[] S = new byte[256];

   private static final int[] T0 = new int[256];
   private static final int[] T1 = new int[256];
   private static final int[] T2 = new int[256];
   private static final int[] T3 = new int[256];
   private static final int[] T4 = new int[256];
   private static final int[] T5 = new int[256];
   private static final int[] T6 = new int[256];
   private static final int[] T7 = new int[256];

   // round constants
   private static final int
         rc00, rc01, rc10, rc11, rc20, rc21, rc30, rc31, rc40,
         rc41, rc50, rc51, rc60, rc61, rc70, rc71, rc80, rc81;

   /**
    * KAT vector (from ecb_vk):
    * I=120
    * KEY=00000000000000000000000000000100
    * CT=A0C86A1BBE2CBF4C
    */
   private static final byte[] KAT_KEY = Util.toBytesFromString("00000000000000000000000000000100");
   private static final byte[] KAT_CT =  Util.toBytesFromString("A0C86A1BBE2CBF4C");

   /** caches the result of the correctness test, once executed. */
   private static Boolean valid;

   // Static code - to intialise lookup tables --------------------------------

   static {
      long ROOT = 0x11D; // para. 2.1 [KHAZAD]
      int i, s, s2, s3, s4, s5, s6, s7, s8, sb;
      char c;
      for (i = 0; i < 256; i++) {
         c = Sd.charAt(i >>> 1);
         s = ((i & 1) == 0 ? c >>> 8 : c) & 0xFF;
         S[i] = (byte) s;

         s2 = s << 1;
         if (s2 > 0xFF)
            s2 ^= ROOT;

         s3 = s2 ^ s;
         s4 = s2 << 1;
         if (s4 > 0xFF)
            s4 ^= ROOT;

         s5 = s4 ^ s;
         s6 = s4 ^ s2;
         s7 = s6 ^ s;
         s8 = s4 << 1;
         if (s8 > 0xFF)
            s8 ^= ROOT;

         sb = s8 ^ s2 ^ s;

         T0[i] = s  << 24 | s3 << 16 | s4 << 8 | s5;
         T1[i] = s3 << 24 | s  << 16 | s5 << 8 | s4;
         T2[i] = s4 << 24 | s5 << 16 | s  << 8 | s3;
         T3[i] = s5 << 24 | s4 << 16 | s3 << 8 | s ;
         T4[i] = s6 << 24 | s8 << 16 | sb << 8 | s7;
         T5[i] = s8 << 24 | s6 << 16 | s7 << 8 | sb;
         T6[i] = sb << 24 | s7 << 16 | s6 << 8 | s8;
         T7[i] = s7 << 24 | sb << 16 | s8 << 8 | s6;
      }

      // compute round constant
      rc00 = S[ 0] << 24 | (S[ 1] & 0xFF) << 16 | (S[ 2] & 0xFF) << 8 | (S[ 3] & 0xFF);
      rc01 = S[ 4] << 24 | (S[ 5] & 0xFF) << 16 | (S[ 6] & 0xFF) << 8 | (S[ 7] & 0xFF);
      rc10 = S[ 8] << 24 | (S[ 9] & 0xFF) << 16 | (S[10] & 0xFF) << 8 | (S[11] & 0xFF);
      rc11 = S[12] << 24 | (S[13] & 0xFF) << 16 | (S[14] & 0xFF) << 8 | (S[15] & 0xFF);
      rc20 = S[16] << 24 | (S[17] & 0xFF) << 16 | (S[18] & 0xFF) << 8 | (S[19] & 0xFF);
      rc21 = S[20] << 24 | (S[21] & 0xFF) << 16 | (S[22] & 0xFF) << 8 | (S[23] & 0xFF);
      rc30 = S[24] << 24 | (S[25] & 0xFF) << 16 | (S[26] & 0xFF) << 8 | (S[27] & 0xFF);
      rc31 = S[28] << 24 | (S[29] & 0xFF) << 16 | (S[30] & 0xFF) << 8 | (S[31] & 0xFF);
      rc40 = S[32] << 24 | (S[33] & 0xFF) << 16 | (S[34] & 0xFF) << 8 | (S[35] & 0xFF);
      rc41 = S[36] << 24 | (S[37] & 0xFF) << 16 | (S[38] & 0xFF) << 8 | (S[39] & 0xFF);
      rc50 = S[40] << 24 | (S[41] & 0xFF) << 16 | (S[42] & 0xFF) << 8 | (S[43] & 0xFF);
      rc51 = S[44] << 24 | (S[45] & 0xFF) << 16 | (S[46] & 0xFF) << 8 | (S[47] & 0xFF);
      rc60 = S[48] << 24 | (S[49] & 0xFF) << 16 | (S[50] & 0xFF) << 8 | (S[51] & 0xFF);
      rc61 = S[52] << 24 | (S[53] & 0xFF) << 16 | (S[54] & 0xFF) << 8 | (S[55] & 0xFF);
      rc70 = S[56] << 24 | (S[57] & 0xFF) << 16 | (S[58] & 0xFF) << 8 | (S[59] & 0xFF);
      rc71 = S[60] << 24 | (S[61] & 0xFF) << 16 | (S[62] & 0xFF) << 8 | (S[63] & 0xFF);
      rc80 = S[64] << 24 | (S[65] & 0xFF) << 16 | (S[66] & 0xFF) << 8 | (S[67] & 0xFF);
      rc81 = S[68] << 24 | (S[69] & 0xFF) << 16 | (S[70] & 0xFF) << 8 | (S[71] & 0xFF);
   }

   // Constructor(s)
   // -------------------------------------------------------------------------

   /** Trivial 0-arguments constructor. */
   public Khazad() {
      super(Registry.KHAZAD_CIPHER, DEFAULT_BLOCK_SIZE, DEFAULT_KEY_SIZE);
   }

   // Class methods
   // -------------------------------------------------------------------------

   private static void khazad(byte[] in, int i, byte[] out, int j, Key K) {
      // sigma(K[0])
      int a0 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i++] & 0xFF)) ^ K.k00;
      int a1 = (in[i++] << 24 | (in[i++] & 0xFF) << 16 | (in[i++] & 0xFF) << 8 | (in[i  ] & 0xFF)) ^ K.k01;

      int b0, b1;
      // round function
      b0 = T0[a0 >>> 24] ^ T1[(a0 >>> 16) & 0xFF] ^ T2[(a0 >>> 8) & 0xFF] ^ T3[a0 & 0xFF] ^
           T4[a1 >>> 24] ^ T5[(a1 >>> 16) & 0xFF] ^ T6[(a1 >>> 8) & 0xFF] ^ T7[a1 & 0xFF] ^ K.k10;
      b1 = T0[a1 >>> 24] ^ T1[(a1 >>> 16) & 0xFF] ^ T2[(a1 >>> 8) & 0xFF] ^ T3[a1 & 0xFF] ^
           T4[a0 >>> 24] ^ T5[(a0 >>> 16) & 0xFF] ^ T6[(a0 >>> 8) & 0xFF] ^ T7[a0 & 0xFF] ^ K.k11;

      a0 = T0[b0 >>> 24] ^ T1[(b0 >>> 16) & 0xFF] ^ T2[(b0 >>> 8) & 0xFF] ^ T3[b0 & 0xFF] ^
           T4[b1 >>> 24] ^ T5[(b1 >>> 16) & 0xFF] ^ T6[(b1 >>> 8) & 0xFF] ^ T7[b1 & 0xFF] ^ K.k20;
      a1 = T0[b1 >>> 24] ^ T1[(b1 >>> 16) & 0xFF] ^ T2[(b1 >>> 8) & 0xFF] ^ T3[b1 & 0xFF] ^
           T4[b0 >>> 24] ^ T5[(b0 >>> 16) & 0xFF] ^ T6[(b0 >>> 8) & 0xFF] ^ T7[b0 & 0xFF] ^ K.k21;

      b0 = T0[a0 >>> 24] ^ T1[(a0 >>> 16) & 0xFF] ^ T2[(a0 >>> 8) & 0xFF] ^ T3[a0 & 0xFF] ^
           T4[a1 >>> 24] ^ T5[(a1 >>> 16) & 0xFF] ^ T6[(a1 >>> 8) & 0xFF] ^ T7[a1 & 0xFF] ^ K.k30;
      b1 = T0[a1 >>> 24] ^ T1[(a1 >>> 16) & 0xFF] ^ T2[(a1 >>> 8) & 0xFF] ^ T3[a1 & 0xFF] ^
           T4[a0 >>> 24] ^ T5[(a0 >>> 16) & 0xFF] ^ T6[(a0 >>> 8) & 0xFF] ^ T7[a0 & 0xFF] ^ K.k31;

      a0 = T0[b0 >>> 24] ^ T1[(b0 >>> 16) & 0xFF] ^ T2[(b0 >>> 8) & 0xFF] ^ T3[b0 & 0xFF] ^
           T4[b1 >>> 24] ^ T5[(b1 >>> 16) & 0xFF] ^ T6[(b1 >>> 8) & 0xFF] ^ T7[b1 & 0xFF] ^ K.k40;
      a1 = T0[b1 >>> 24] ^ T1[(b1 >>> 16) & 0xFF] ^ T2[(b1 >>> 8) & 0xFF] ^ T3[b1 & 0xFF] ^
           T4[b0 >>> 24] ^ T5[(b0 >>> 16) & 0xFF] ^ T6[(b0 >>> 8) & 0xFF] ^ T7[b0 & 0xFF] ^ K.k41;

      b0 = T0[a0 >>> 24] ^ T1[(a0 >>> 16) & 0xFF] ^ T2[(a0 >>> 8) & 0xFF] ^ T3[a0 & 0xFF] ^
           T4[a1 >>> 24] ^ T5[(a1 >>> 16) & 0xFF] ^ T6[(a1 >>> 8) & 0xFF] ^ T7[a1 & 0xFF] ^ K.k50;
      b1 = T0[a1 >>> 24] ^ T1[(a1 >>> 16) & 0xFF] ^ T2[(a1 >>> 8) & 0xFF] ^ T3[a1 & 0xFF] ^
           T4[a0 >>> 24] ^ T5[(a0 >>> 16) & 0xFF] ^ T6[(a0 >>> 8) & 0xFF] ^ T7[a0 & 0xFF] ^ K.k51;

      a0 = T0[b0 >>> 24] ^ T1[(b0 >>> 16) & 0xFF] ^ T2[(b0 >>> 8) & 0xFF] ^ T3[b0 & 0xFF] ^
           T4[b1 >>> 24] ^ T5[(b1 >>> 16) & 0xFF] ^ T6[(b1 >>> 8) & 0xFF] ^ T7[b1 & 0xFF] ^ K.k60;
      a1 = T0[b1 >>> 24] ^ T1[(b1 >>> 16) & 0xFF] ^ T2[(b1 >>> 8) & 0xFF] ^ T3[b1 & 0xFF] ^
           T4[b0 >>> 24] ^ T5[(b0 >>> 16) & 0xFF] ^ T6[(b0 >>> 8) & 0xFF] ^ T7[b0 & 0xFF] ^ K.k61;

      b0 = T0[a0 >>> 24] ^ T1[(a0 >>> 16) & 0xFF] ^ T2[(a0 >>> 8) & 0xFF] ^ T3[a0 & 0xFF] ^
           T4[a1 >>> 24] ^ T5[(a1 >>> 16) & 0xFF] ^ T6[(a1 >>> 8) & 0xFF] ^ T7[a1 & 0xFF] ^ K.k70;
      b1 = T0[a1 >>> 24] ^ T1[(a1 >>> 16) & 0xFF] ^ T2[(a1 >>> 8) & 0xFF] ^ T3[a1 & 0xFF] ^
           T4[a0 >>> 24] ^ T5[(a0 >>> 16) & 0xFF] ^ T6[(a0 >>> 8) & 0xFF] ^ T7[a0 & 0xFF] ^ K.k71;

      // sigma(K.kR]) o gamma applied to previous output
      int k0 = K.k80;
      int k1 = K.k81;
      out[j++] = (byte)(S[ b0 >>> 24        ] ^ (k0 >>> 24));
      out[j++] = (byte)(S[(b0 >>> 16) & 0xFF] ^ (k0 >>> 16));
      out[j++] = (byte)(S[(b0 >>>  8) & 0xFF] ^ (k0 >>>  8));
      out[j++] = (byte)(S[ b0         & 0xFF] ^  k0        );
      out[j++] = (byte)(S[ b1 >>> 24        ] ^ (k1 >>> 24));
      out[j++] = (byte)(S[(b1 >>> 16) & 0xFF] ^ (k1 >>> 16));
      out[j++] = (byte)(S[(b1 >>>  8) & 0xFF] ^ (k1 >>>  8));
      out[j  ] = (byte)(S[ b1         & 0xFF] ^  k1        );
   }

   // Instance methods
   // -------------------------------------------------------------------------

   // java.lang.Cloneable interface implementation ----------------------------

   public Object clone() {
      Khazad result = new Khazad();
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

   /**
    * <p>Expands a user-supplied key material into a session key for a
    * designated <i>block size</i>.</p>
    *
    * @param uk the 128-bit user-supplied key material.
    * @param bs the desired block size in bytes.
    * @return an Object encapsulating the session key.
    * @exception IllegalArgumentException if the block size is not 16 (128-bit).
    * @exception InvalidKeyException if the key data is invalid.
    */
   public Object makeKey(byte[] uk, int bs) throws InvalidKeyException {
      if (bs != DEFAULT_BLOCK_SIZE) {
         throw new IllegalArgumentException();
      }
      if (uk == null) {
         throw new InvalidKeyException("Empty key");
      }
      if (uk.length != 16) {
         throw new InvalidKeyException("Key is not 128-bit.");
      }
      Key Ke = new Key(); // encryption round keys
      Key Kd = new Key(); // decryption round keys
      int k20, k21, k10, k11, rc0, rc1, kr0, kr1;

      k20 = uk[ 0] << 24 | (uk[ 1] & 0xFF) << 16 | (uk[ 2] & 0xFF) << 8 | (uk[ 3] & 0xFF);
      k21 = uk[ 4] << 24 | (uk[ 5] & 0xFF) << 16 | (uk[ 6] & 0xFF) << 8 | (uk[ 7] & 0xFF);
      k10 = uk[ 8] << 24 | (uk[ 9] & 0xFF) << 16 | (uk[10] & 0xFF) << 8 | (uk[11] & 0xFF);
      k11 = uk[12] << 24 | (uk[13] & 0xFF) << 16 | (uk[14] & 0xFF) << 8 | (uk[15] & 0xFF);

      // r = 0
      rc0 = rc00; rc1 = rc01;
      kr0 = T0[k10 >>> 24] ^ T1[(k10 >>> 16) & 0xFF] ^ T2[(k10 >>> 8) & 0xFF] ^ T3[k10 & 0xFF] ^
            T4[k11 >>> 24] ^ T5[(k11 >>> 16) & 0xFF] ^ T6[(k11 >>> 8) & 0xFF] ^ T7[k11 & 0xFF] ^ rc0 ^ k20;
      kr1 = T0[k11 >>> 24] ^ T1[(k11 >>> 16) & 0xFF] ^ T2[(k11 >>> 8) & 0xFF] ^ T3[k11 & 0xFF] ^
            T4[k10 >>> 24] ^ T5[(k10 >>> 16) & 0xFF] ^ T6[(k10 >>> 8) & 0xFF] ^ T7[k10 & 0xFF] ^ rc1 ^ k21;

      Ke.k00 = kr0;
      Ke.k01 = kr1; k20 = k10; k21 = k11; k10 = kr0; k11 = kr1;
      Kd.k80 = kr0;
      Kd.k81 = kr1;

      // r = 1
      kr0 = T0[k10 >>> 24] ^ T1[(k10 >>> 16) & 0xFF] ^ T2[(k10 >>> 8) & 0xFF] ^ T3[k10 & 0xFF] ^
            T4[k11 >>> 24] ^ T5[(k11 >>> 16) & 0xFF] ^ T6[(k11 >>> 8) & 0xFF] ^ T7[k11 & 0xFF] ^ rc10 ^ k20;
      kr1 = T0[k11 >>> 24] ^ T1[(k11 >>> 16) & 0xFF] ^ T2[(k11 >>> 8) & 0xFF] ^ T3[k11 & 0xFF] ^
            T4[k10 >>> 24] ^ T5[(k10 >>> 16) & 0xFF] ^ T6[(k10 >>> 8) & 0xFF] ^ T7[k10 & 0xFF] ^ rc11 ^ k21;

      Ke.k10 = kr0;
      Ke.k11 = kr1; k20 = k10; k21 = k11; k10 = kr0; k11 = kr1;
      Kd.k70 = T0[S[kr0 >>> 24] & 0xFF] ^ T1[S[(kr0 >>> 16) & 0xFF] & 0xFF] ^ T2[S[(kr0 >>> 8) & 0xFF] & 0xFF] ^ T3[S[kr0 & 0xFF] & 0xFF] ^
               T4[S[kr1 >>> 24] & 0xFF] ^ T5[S[(kr1 >>> 16) & 0xFF] & 0xFF] ^ T6[S[(kr1 >>> 8) & 0xFF] & 0xFF] ^ T7[S[kr1 & 0xFF] & 0xFF];
      Kd.k71 = T0[S[kr1 >>> 24] & 0xFF] ^ T1[S[(kr1 >>> 16) & 0xFF] & 0xFF] ^ T2[S[(kr1 >>> 8) & 0xFF] & 0xFF] ^ T3[S[kr1 & 0xFF] & 0xFF] ^
               T4[S[kr0 >>> 24] & 0xFF] ^ T5[S[(kr0 >>> 16) & 0xFF] & 0xFF] ^ T6[S[(kr0 >>> 8) & 0xFF] & 0xFF] ^ T7[S[kr0 & 0xFF] & 0xFF];

      // r = 2
      kr0 = T0[k10 >>> 24] ^ T1[(k10 >>> 16) & 0xFF] ^ T2[(k10 >>> 8) & 0xFF] ^ T3[k10 & 0xFF] ^
            T4[k11 >>> 24] ^ T5[(k11 >>> 16) & 0xFF] ^ T6[(k11 >>> 8) & 0xFF] ^ T7[k11 & 0xFF] ^ rc20 ^ k20;
      kr1 = T0[k11 >>> 24] ^ T1[(k11 >>> 16) & 0xFF] ^ T2[(k11 >>> 8) & 0xFF] ^ T3[k11 & 0xFF] ^
            T4[k10 >>> 24] ^ T5[(k10 >>> 16) & 0xFF] ^ T6[(k10 >>> 8) & 0xFF] ^ T7[k10 & 0xFF] ^ rc21 ^ k21;

      Ke.k20 = kr0;
      Ke.k21 = kr1; k20 = k10; k21 = k11; k10 = kr0; k11 = kr1;
      Kd.k60 = T0[S[kr0 >>> 24] & 0xFF] ^ T1[S[(kr0 >>> 16) & 0xFF] & 0xFF] ^ T2[S[(kr0 >>> 8) & 0xFF] & 0xFF] ^ T3[S[kr0 & 0xFF] & 0xFF] ^
               T4[S[kr1 >>> 24] & 0xFF] ^ T5[S[(kr1 >>> 16) & 0xFF] & 0xFF] ^ T6[S[(kr1 >>> 8) & 0xFF] & 0xFF] ^ T7[S[kr1 & 0xFF] & 0xFF];
      Kd.k61 = T0[S[kr1 >>> 24] & 0xFF] ^ T1[S[(kr1 >>> 16) & 0xFF] & 0xFF] ^ T2[S[(kr1 >>> 8) & 0xFF] & 0xFF] ^ T3[S[kr1 & 0xFF] & 0xFF] ^
               T4[S[kr0 >>> 24] & 0xFF] ^ T5[S[(kr0 >>> 16) & 0xFF] & 0xFF] ^ T6[S[(kr0 >>> 8) & 0xFF] & 0xFF] ^ T7[S[kr0 & 0xFF] & 0xFF];

      // r = 3
      kr0 = T0[k10 >>> 24] ^ T1[(k10 >>> 16) & 0xFF] ^ T2[(k10 >>> 8) & 0xFF] ^ T3[k10 & 0xFF] ^
            T4[k11 >>> 24] ^ T5[(k11 >>> 16) & 0xFF] ^ T6[(k11 >>> 8) & 0xFF] ^ T7[k11 & 0xFF] ^ rc30 ^ k20;
      kr1 = T0[k11 >>> 24] ^ T1[(k11 >>> 16) & 0xFF] ^ T2[(k11 >>> 8) & 0xFF] ^ T3[k11 & 0xFF] ^
            T4[k10 >>> 24] ^ T5[(k10 >>> 16) & 0xFF] ^ T6[(k10 >>> 8) & 0xFF] ^ T7[k10 & 0xFF] ^ rc31 ^ k21;

      Ke.k30 = kr0;
      Ke.k31 = kr1; k20 = k10; k21 = k11; k10 = kr0; k11 = kr1;
      Kd.k50 = T0[S[kr0 >>> 24] & 0xFF] ^ T1[S[(kr0 >>> 16) & 0xFF] & 0xFF] ^ T2[S[(kr0 >>> 8) & 0xFF] & 0xFF] ^ T3[S[kr0 & 0xFF] & 0xFF] ^
               T4[S[kr1 >>> 24] & 0xFF] ^ T5[S[(kr1 >>> 16) & 0xFF] & 0xFF] ^ T6[S[(kr1 >>> 8) & 0xFF] & 0xFF] ^ T7[S[kr1 & 0xFF] & 0xFF];
      Kd.k51 = T0[S[kr1 >>> 24] & 0xFF] ^ T1[S[(kr1 >>> 16) & 0xFF] & 0xFF] ^ T2[S[(kr1 >>> 8) & 0xFF] & 0xFF] ^ T3[S[kr1 & 0xFF] & 0xFF] ^
               T4[S[kr0 >>> 24] & 0xFF] ^ T5[S[(kr0 >>> 16) & 0xFF] & 0xFF] ^ T6[S[(kr0 >>> 8) & 0xFF] & 0xFF] ^ T7[S[kr0 & 0xFF] & 0xFF];

      // r = 4
      kr0 = T0[k10 >>> 24] ^ T1[(k10 >>> 16) & 0xFF] ^ T2[(k10 >>> 8) & 0xFF] ^ T3[k10 & 0xFF] ^
            T4[k11 >>> 24] ^ T5[(k11 >>> 16) & 0xFF] ^ T6[(k11 >>> 8) & 0xFF] ^ T7[k11 & 0xFF] ^ rc40 ^ k20;
      kr1 = T0[k11 >>> 24] ^ T1[(k11 >>> 16) & 0xFF] ^ T2[(k11 >>> 8) & 0xFF] ^ T3[k11 & 0xFF] ^
            T4[k10 >>> 24] ^ T5[(k10 >>> 16) & 0xFF] ^ T6[(k10 >>> 8) & 0xFF] ^ T7[k10 & 0xFF] ^ rc41 ^ k21;

      Ke.k40 = kr0;
      Ke.k41 = kr1; k20 = k10; k21 = k11; k10 = kr0; k11 = kr1;
      Kd.k40 = T0[S[kr0 >>> 24] & 0xFF] ^ T1[S[(kr0 >>> 16) & 0xFF] & 0xFF] ^ T2[S[(kr0 >>> 8) & 0xFF] & 0xFF] ^ T3[S[kr0 & 0xFF] & 0xFF] ^
               T4[S[kr1 >>> 24] & 0xFF] ^ T5[S[(kr1 >>> 16) & 0xFF] & 0xFF] ^ T6[S[(kr1 >>> 8) & 0xFF] & 0xFF] ^ T7[S[kr1 & 0xFF] & 0xFF];
      Kd.k41 = T0[S[kr1 >>> 24] & 0xFF] ^ T1[S[(kr1 >>> 16) & 0xFF] & 0xFF] ^ T2[S[(kr1 >>> 8) & 0xFF] & 0xFF] ^ T3[S[kr1 & 0xFF] & 0xFF] ^
               T4[S[kr0 >>> 24] & 0xFF] ^ T5[S[(kr0 >>> 16) & 0xFF] & 0xFF] ^ T6[S[(kr0 >>> 8) & 0xFF] & 0xFF] ^ T7[S[kr0 & 0xFF] & 0xFF];

      // r = 5
      kr0 = T0[k10 >>> 24] ^ T1[(k10 >>> 16) & 0xFF] ^ T2[(k10 >>> 8) & 0xFF] ^ T3[k10 & 0xFF] ^
            T4[k11 >>> 24] ^ T5[(k11 >>> 16) & 0xFF] ^ T6[(k11 >>> 8) & 0xFF] ^ T7[k11 & 0xFF] ^ rc50 ^ k20;
      kr1 = T0[k11 >>> 24] ^ T1[(k11 >>> 16) & 0xFF] ^ T2[(k11 >>> 8) & 0xFF] ^ T3[k11 & 0xFF] ^
            T4[k10 >>> 24] ^ T5[(k10 >>> 16) & 0xFF] ^ T6[(k10 >>> 8) & 0xFF] ^ T7[k10 & 0xFF] ^ rc51 ^ k21;

      Ke.k50 = kr0;
      Ke.k51 = kr1; k20 = k10; k21 = k11; k10 = kr0; k11 = kr1;
      Kd.k30 = T0[S[kr0 >>> 24] & 0xFF] ^ T1[S[(kr0 >>> 16) & 0xFF] & 0xFF] ^ T2[S[(kr0 >>> 8) & 0xFF] & 0xFF] ^ T3[S[kr0 & 0xFF] & 0xFF] ^
               T4[S[kr1 >>> 24] & 0xFF] ^ T5[S[(kr1 >>> 16) & 0xFF] & 0xFF] ^ T6[S[(kr1 >>> 8) & 0xFF] & 0xFF] ^ T7[S[kr1 & 0xFF] & 0xFF];
      Kd.k31 = T0[S[kr1 >>> 24] & 0xFF] ^ T1[S[(kr1 >>> 16) & 0xFF] & 0xFF] ^ T2[S[(kr1 >>> 8) & 0xFF] & 0xFF] ^ T3[S[kr1 & 0xFF] & 0xFF] ^
               T4[S[kr0 >>> 24] & 0xFF] ^ T5[S[(kr0 >>> 16) & 0xFF] & 0xFF] ^ T6[S[(kr0 >>> 8) & 0xFF] & 0xFF] ^ T7[S[kr0 & 0xFF] & 0xFF];

      // r = 6
      kr0 = T0[k10 >>> 24] ^ T1[(k10 >>> 16) & 0xFF] ^ T2[(k10 >>> 8) & 0xFF] ^ T3[k10 & 0xFF] ^
            T4[k11 >>> 24] ^ T5[(k11 >>> 16) & 0xFF] ^ T6[(k11 >>> 8) & 0xFF] ^ T7[k11 & 0xFF] ^ rc60 ^ k20;
      kr1 = T0[k11 >>> 24] ^ T1[(k11 >>> 16) & 0xFF] ^ T2[(k11 >>> 8) & 0xFF] ^ T3[k11 & 0xFF] ^
            T4[k10 >>> 24] ^ T5[(k10 >>> 16) & 0xFF] ^ T6[(k10 >>> 8) & 0xFF] ^ T7[k10 & 0xFF] ^ rc61 ^ k21;

      Ke.k60 = kr0;
      Ke.k61 = kr1; k20 = k10; k21 = k11; k10 = kr0; k11 = kr1;
      Kd.k20 = T0[S[kr0 >>> 24] & 0xFF] ^ T1[S[(kr0 >>> 16) & 0xFF] & 0xFF] ^ T2[S[(kr0 >>> 8) & 0xFF] & 0xFF] ^ T3[S[kr0 & 0xFF] & 0xFF] ^
               T4[S[kr1 >>> 24] & 0xFF] ^ T5[S[(kr1 >>> 16) & 0xFF] & 0xFF] ^ T6[S[(kr1 >>> 8) & 0xFF] & 0xFF] ^ T7[S[kr1 & 0xFF] & 0xFF];
      Kd.k21 = T0[S[kr1 >>> 24] & 0xFF] ^ T1[S[(kr1 >>> 16) & 0xFF] & 0xFF] ^ T2[S[(kr1 >>> 8) & 0xFF] & 0xFF] ^ T3[S[kr1 & 0xFF] & 0xFF] ^
               T4[S[kr0 >>> 24] & 0xFF] ^ T5[S[(kr0 >>> 16) & 0xFF] & 0xFF] ^ T6[S[(kr0 >>> 8) & 0xFF] & 0xFF] ^ T7[S[kr0 & 0xFF] & 0xFF];

      // r = 7
      kr0 = T0[k10 >>> 24] ^ T1[(k10 >>> 16) & 0xFF] ^ T2[(k10 >>> 8) & 0xFF] ^ T3[k10 & 0xFF] ^
            T4[k11 >>> 24] ^ T5[(k11 >>> 16) & 0xFF] ^ T6[(k11 >>> 8) & 0xFF] ^ T7[k11 & 0xFF] ^ rc70 ^ k20;
      kr1 = T0[k11 >>> 24] ^ T1[(k11 >>> 16) & 0xFF] ^ T2[(k11 >>> 8) & 0xFF] ^ T3[k11 & 0xFF] ^
            T4[k10 >>> 24] ^ T5[(k10 >>> 16) & 0xFF] ^ T6[(k10 >>> 8) & 0xFF] ^ T7[k10 & 0xFF] ^ rc71 ^ k21;

      Ke.k70 = kr0;
      Ke.k71 = kr1; k20 = k10; k21 = k11; k10 = kr0; k11 = kr1;
      Kd.k10 = T0[S[kr0 >>> 24] & 0xFF] ^ T1[S[(kr0 >>> 16) & 0xFF] & 0xFF] ^ T2[S[(kr0 >>> 8) & 0xFF] & 0xFF] ^ T3[S[kr0 & 0xFF] & 0xFF] ^
               T4[S[kr1 >>> 24] & 0xFF] ^ T5[S[(kr1 >>> 16) & 0xFF] & 0xFF] ^ T6[S[(kr1 >>> 8) & 0xFF] & 0xFF] ^ T7[S[kr1 & 0xFF] & 0xFF];
      Kd.k11 = T0[S[kr1 >>> 24] & 0xFF] ^ T1[S[(kr1 >>> 16) & 0xFF] & 0xFF] ^ T2[S[(kr1 >>> 8) & 0xFF] & 0xFF] ^ T3[S[kr1 & 0xFF] & 0xFF] ^
               T4[S[kr0 >>> 24] & 0xFF] ^ T5[S[(kr0 >>> 16) & 0xFF] & 0xFF] ^ T6[S[(kr0 >>> 8) & 0xFF] & 0xFF] ^ T7[S[kr0 & 0xFF] & 0xFF];

      // r = 8
      kr0 = T0[k10 >>> 24] ^ T1[(k10 >>> 16) & 0xFF] ^ T2[(k10 >>> 8) & 0xFF] ^ T3[k10 & 0xFF] ^
            T4[k11 >>> 24] ^ T5[(k11 >>> 16) & 0xFF] ^ T6[(k11 >>> 8) & 0xFF] ^ T7[k11 & 0xFF] ^ rc80 ^ k20;
      kr1 = T0[k11 >>> 24] ^ T1[(k11 >>> 16) & 0xFF] ^ T2[(k11 >>> 8) & 0xFF] ^ T3[k11 & 0xFF] ^
            T4[k10 >>> 24] ^ T5[(k10 >>> 16) & 0xFF] ^ T6[(k10 >>> 8) & 0xFF] ^ T7[k10 & 0xFF] ^ rc81 ^ k21;

      Ke.k80 = kr0;
      Ke.k81 = kr1;
      Kd.k00 = kr0;
      Kd.k01 = kr1;

      return new Object[] { Ke, Kd };
   }

   public void encrypt(byte[] in, int i, byte[] out, int j, Object k, int bs) {
      if (bs != DEFAULT_BLOCK_SIZE) {
         throw new IllegalArgumentException();
      }
      khazad(in, i, out, j, (Key) ((Object[]) k)[0]);
   }

   public void decrypt(byte[] in, int i, byte[] out, int j, Object k, int bs) {
      if (bs != DEFAULT_BLOCK_SIZE) {
         throw new IllegalArgumentException();
      }
      khazad(in, i, out, j, (Key) ((Object[]) k)[1]);
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

   // Inner class(es)
   // =========================================================================

   /** A trivial class to eliminate array index range-checking at runtime. */
   private class Key {
      int k00, k01, k10, k11, k20, k21, k30, k31, k40,
          k41, k50, k51, k60, k61, k70, k71, k80, k81;

      Key() {
         super();
      }

      /** Cloning constructor. */
      private Key(Key that) {
         this();

         this.k00 = that.k00; this.k01 = that.k01; this.k10 = that.k10;
         this.k11 = that.k11; this.k20 = that.k20; this.k21 = that.k21;
         this.k30 = that.k30; this.k31 = that.k31; this.k40 = that.k40;
         this.k41 = that.k41; this.k50 = that.k50; this.k51 = that.k51;
         this.k60 = that.k60; this.k61 = that.k61; this.k70 = that.k70;
         this.k71 = that.k71; this.k80 = that.k80; this.k81 = that.k81;
      }

      // Cloneable interface implementation.
      // --------------------------------------------------------------------

      public Object clone() {
         return new Key(this);
      }
   }
}

