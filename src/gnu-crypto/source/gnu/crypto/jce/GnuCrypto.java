package gnu.crypto.jce;

// --------------------------------------------------------------------------
// $Id: GnuCrypto.java,v 1.20 2003/12/25 02:17:15 uid66198 Exp $
//
// Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
//
// This file is part of GNU Crypto.
//
// GNU Crypto is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or (at
// your option) any later version.
//
// GNU Crypto is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the
//
//    Free Software Foundation, Inc.,
//    59 Temple Place, Suite 330,
//    Boston, MA  02111-1307
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
//
// --------------------------------------------------------------------------

import gnu.crypto.Registry;
import gnu.crypto.cipher.CipherFactory;
import gnu.crypto.hash.HashFactory;
import gnu.crypto.mac.MacFactory;
import gnu.crypto.sasl.ClientFactory;
import gnu.crypto.sasl.ServerFactory;
import gnu.crypto.key.KeyPairGeneratorFactory;
import gnu.crypto.sig.SignatureFactory;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * <p>The GNU Crypto implementation of the Java Cryptographic Extension (JCE)
 * Provider.</p>
 *
 * @version $Revision: 1.20 $
 * @see java.security.Provider
 */
public final class GnuCrypto extends Provider {

   // Constants and variables
   // -------------------------------------------------------------------------

   // Constructor(s)
   // -------------------------------------------------------------------------

   /**
    * <p>The <a href="http://www.gnu.org/software/gnu-crypto/">GNU Crypto</a>
    * Provider.</p>
    */
   public GnuCrypto() {
      super(Registry.GNU_CRYPTO, 2.0, "GNU Crypto JCE Provider");

      AccessController.doPrivileged(
         new PrivilegedAction() {
            public Object run() {
               // MessageDigest
               put("MessageDigest.HAVAL", "gnu.crypto.jce.hash.HavalSpi");
               put("MessageDigest.HAVAL ImplementedIn", "Software");
               put("MessageDigest.MD2", "gnu.crypto.jce.hash.MD2Spi");
               put("MessageDigest.MD2 ImplementedIn", "Software");
               put("MessageDigest.MD4", "gnu.crypto.jce.hash.MD4Spi");
               put("MessageDigest.MD4 ImplementedIn", "Software");
               put("MessageDigest.MD5", "gnu.crypto.jce.hash.MD5Spi");
               put("MessageDigest.MD5 ImplementedIn", "Software");
               put("MessageDigest.RIPEMD128", "gnu.crypto.jce.hash.RipeMD128Spi");
               put("MessageDigest.RIPEMD128 ImplementedIn", "Software");
               put("MessageDigest.RIPEMD160", "gnu.crypto.jce.hash.RipeMD160Spi");
               put("MessageDigest.RIPEMD160 ImplementedIn", "Software");
               put("MessageDigest.SHA-160", "gnu.crypto.jce.hash.Sha160Spi");
               put("MessageDigest.SHA-160 ImplementedIn", "Software");
               put("MessageDigest.SHA-256", "gnu.crypto.jce.hash.Sha256Spi");
               put("MessageDigest.SHA-256 ImplementedIn", "Software");
               put("MessageDigest.SHA-384", "gnu.crypto.jce.hash.Sha384Spi");
               put("MessageDigest.SHA-384 ImplementedIn", "Software");
               put("MessageDigest.SHA-512", "gnu.crypto.jce.hash.Sha512Spi");
               put("MessageDigest.SHA-512 ImplementedIn", "Software");
               put("MessageDigest.TIGER", "gnu.crypto.jce.hash.TigerSpi");
               put("MessageDigest.TIGER ImplementedIn", "Software");
               put("MessageDigest.WHIRLPOOL", "gnu.crypto.jce.hash.WhirlpoolSpi");
               put("MessageDigest.WHIRLPOOL ImplementedIn", "Software");

               // SecureRandom
               put("SecureRandom.ARCFOUR", "gnu.crypto.jce.prng.ARCFourRandomSpi");
               put("SecureRandom.MD2PRNG", "gnu.crypto.jce.prng.MD2RandomSpi");
               put("SecureRandom.MD2PRNG ImplementedIn", "Software");
               put("SecureRandom.MD4PRNG", "gnu.crypto.jce.prng.MD4RandomSpi");
               put("SecureRandom.MD4PRNG ImplementedIn", "Software");
               put("SecureRandom.MD5PRNG", "gnu.crypto.jce.prng.MD5RandomSpi");
               put("SecureRandom.MD5PRNG ImplementedIn", "Software");
               put("SecureRandom.RIPEMD128PRNG", "gnu.crypto.jce.prng.RipeMD128RandomSpi");
               put("SecureRandom.RIPEMD128PRNG ImplementedIn", "Software");
               put("SecureRandom.RIPEMD160PRNG", "gnu.crypto.jce.prng.RipeMD160RandomSpi");
               put("SecureRandom.RIPEMD160PRNG ImplementedIn", "Software");
               put("SecureRandom.SHA-160PRNG", "gnu.crypto.jce.prng.Sha160RandomSpi");
               put("SecureRandom.SHA-160PRNG ImplementedIn", "Software");
               put("SecureRandom.SHA-256PRNG", "gnu.crypto.jce.prng.Sha256RandomSpi");
               put("SecureRandom.SHA-256PRNG ImplementedIn", "Software");
               put("SecureRandom.SHA-384PRNG", "gnu.crypto.jce.prng.Sha384RandomSpi");
               put("SecureRandom.SHA-384PRNG ImplementedIn", "Software");
               put("SecureRandom.SHA-512PRNG", "gnu.crypto.jce.prng.Sha512RandomSpi");
               put("SecureRandom.SHA-512PRNG ImplementedIn", "Software");
               put("SecureRandom.TIGERPRNG", "gnu.crypto.jce.prng.TigerRandomSpi");
               put("SecureRandom.TIGERPRNG ImplementedIn", "Software");
               put("SecureRandom.HAVALPRNG", "gnu.crypto.jce.prng.HavalRandomSpi");
               put("SecureRandom.HAVALPRNG ImplementedIn", "Software");
               put("SecureRandom.WHIRLPOOLPRNG", "gnu.crypto.jce.prng.WhirlpoolRandomSpi");
               put("SecureRandom.WHIRLPOOLPRNG ImplementedIn", "Software");
               put("SecureRandom.ICM", "gnu.crypto.jce.prng.ICMRandomSpi");
               put("SecureRandom.ICM ImplementedIn", "Software");
               put("SecureRandom.UMAC-KDF", "gnu.crypto.jce.prng.UMacRandomSpi");
               put("SecureRandom.UMAC-KDF ImplementedIn", "Software");

               // KeyPairGenerator
               put("KeyPairGenerator.DSS", "gnu.crypto.jce.sig.DSSKeyPairGeneratorSpi");
               put("KeyPairGenerator.DSS KeySize", "1024");
               put("KeyPairGenerator.DSS ImplementedIn", "Software");
               put("KeyPairGenerator.RSA", "gnu.crypto.jce.sig.RSAKeyPairGeneratorSpi");
               put("KeyPairGenerator.RSA KeySize", "1024");
               put("KeyPairGenerator.RSA ImplementedIn", "Software");

               // Signature
               put("Signature.DSS/RAW", "gnu.crypto.jce.sig.DSSRawSignatureSpi");
               put("Signature.DSS/RAW KeySize", "1024");
               put("Signature.DSS/RAW ImplementedIn", "Software");
               put("Signature.RSA-PSS/RAW", "gnu.crypto.jce.sig.RSAPSSRawSignatureSpi");
               put("Signature.RSA-PSS/RAW KeySize", "1024");
               put("Signature.RSA-PSS/RAW ImplementedIn", "Software");

               // Cipher
               put("Cipher.ANUBIS", "gnu.crypto.jce.cipher.AnubisSpi");
               put("Cipher.ANUBIS ImplementedIn", "Software");
               put("Cipher.ARCFOUR", "gnu.crypto.jce.cipher.ARCFourSpi");
               put("Cipher.ARCFOUR ImplementedIn", "Software");
               put("Cipher.BLOWFISH", "gnu.crypto.jce.cipher.BlowfishSpi");
               put("Cipher.BLOWFISH ImplementedIn", "Software");
               put("Cipher.DES", "gnu.crypto.jce.cipher.DESSpi");
               put("Cipher.DES ImplementedIn", "Software");
               put("Cipher.KHAZAD", "gnu.crypto.jce.cipher.KhazadSpi");
               put("Cipher.KHAZAD ImplementedIn", "Software");
               put("Cipher.NULL", "gnu.crypto.jce.cipher.NullCipherSpi");
               put("Cipher.NULL ImplementedIn", "Software");
               put("Cipher.AES", "gnu.crypto.jce.cipher.RijndaelSpi");
               put("Cipher.AES ImplementedIn", "Software");
               put("Cipher.RIJNDAEL", "gnu.crypto.jce.cipher.RijndaelSpi");
               put("Cipher.RIJNDAEL ImplementedIn", "Software");
               put("Cipher.SERPENT", "gnu.crypto.jce.cipher.SerpentSpi");
               put("Cipher.SERPENT ImplementedIn", "Software");
               put("Cipher.SQUARE", "gnu.crypto.jce.cipher.SquareSpi");
               put("Cipher.SQUARE ImplementedIn", "Software");
               put("Cipher.TRIPLEDES", "gnu.crypto.jce.cipher.TripleDESSpi");
               put("Cipher.TRIPLEDES ImplementedIn", "Software");
               put("Cipher.TWOFISH", "gnu.crypto.jce.cipher.TwofishSpi");
               put("Cipher.TWOFISH ImplementedIn", "Software");
               put("Cipher.CAST5", "gnu.crypto.jce.cipher.Cast5Spi");
               put("Cipher.CAST5 ImplementedIn", "Software");

               // PBES2 ciphers.
               put("Cipher.PBEWithHMacHavalAndAES",
                   "gnu.crypto.jce.cipher.PBES2$HMacHaval$AES");
               put("Cipher.PBEWithHMacHavalAndAnubis",
                   "gnu.crypto.jce.cipher.PBES2$HMacHaval$Anubis");
               put("Cipher.PBEWithHMacHavalAndBlowfish",
                   "gnu.crypto.jce.cipher.PBES2$HMacHaval$Blowfish");
               put("Cipher.PBEWithHMacHavalAndCast5",
                   "gnu.crypto.jce.cipher.PBES2$HMacHaval$Cast5");
               put("Cipher.PBEWithHMacHavalAndDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacHaval$DES");
               put("Cipher.PBEWithHMacHavalAndKhazad",
                   "gnu.crypto.jce.cipher.PBES2$HMacHaval$Khazad");
               put("Cipher.PBEWithHMacHavalAndSerpent",
                   "gnu.crypto.jce.cipher.PBES2$HMacHaval$Serpent");
               put("Cipher.PBEWithHMacHavalAndSquare",
                   "gnu.crypto.jce.cipher.PBES2$HMacHaval$Square");
               put("Cipher.PBEWithHMacHavalAndTripleDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacHaval$TripleDES");
               put("Cipher.PBEWithHMacHavalAndTwofish",
                   "gnu.crypto.jce.cipher.PBES2$HMacHaval$Twofish");

               put("Cipher.PBEWithHMacMD2AndAES",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD2$AES");
               put("Cipher.PBEWithHMacMD2AndAnubis",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD2$Anubis");
               put("Cipher.PBEWithHMacMD2AndBlowfish",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD2$Blowfish");
               put("Cipher.PBEWithHMacMD2AndCast5",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD2$Cast5");
               put("Cipher.PBEWithHMacMD2AndDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD2$DES");
               put("Cipher.PBEWithHMacMD2AndKhazad",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD2$Khazad");
               put("Cipher.PBEWithHMacMD2AndSerpent",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD2$Serpent");
               put("Cipher.PBEWithHMacMD2AndSquare",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD2$Square");
               put("Cipher.PBEWithHMacMD2AndTripleDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD2$TripleDES");
               put("Cipher.PBEWithHMacMD2AndTwofish",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD2$Twofish");

               put("Cipher.PBEWithHMacMD4AndAES",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD4$AES");
               put("Cipher.PBEWithHMacMD4AndAnubis",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD4$Anubis");
               put("Cipher.PBEWithHMacMD4AndBlowfish",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD4$Blowfish");
               put("Cipher.PBEWithHMacMD4AndCast5",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD4$Cast5");
               put("Cipher.PBEWithHMacMD4AndDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD4$DES");
               put("Cipher.PBEWithHMacMD4AndKhazad",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD4$Khazad");
               put("Cipher.PBEWithHMacMD4AndSerpent",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD4$Serpent");
               put("Cipher.PBEWithHMacMD4AndSquare",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD4$Square");
               put("Cipher.PBEWithHMacMD4AndTripleDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD4$TripleDES");
               put("Cipher.PBEWithHMacMD4AndTwofish",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD4$Twofish");

               put("Cipher.PBEWithHMacMD5AndAES",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD5$AES");
               put("Cipher.PBEWithHMacMD5AndAnubis",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD5$Anubis");
               put("Cipher.PBEWithHMacMD5AndBlowfish",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD5$Blowfish");
               put("Cipher.PBEWithHMacMD5AndCast5",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD5$Cast5");
               put("Cipher.PBEWithHMacMD5AndDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD5$DES");
               put("Cipher.PBEWithHMacMD5AndKhazad",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD5$Khazad");
               put("Cipher.PBEWithHMacMD5AndSerpent",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD5$Serpent");
               put("Cipher.PBEWithHMacMD5AndSquare",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD5$Square");
               put("Cipher.PBEWithHMacMD5AndTripleDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD5$TripleDES");
               put("Cipher.PBEWithHMacMD5AndTwofish",
                   "gnu.crypto.jce.cipher.PBES2$HMacMD5$Twofish");

               put("Cipher.PBEWithHMacSHA1AndAES",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA1$AES");
               put("Cipher.PBEWithHMacSHA1AndAnubis",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA1$Anubis");
               put("Cipher.PBEWithHMacSHA1AndBlowfish",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA1$Blowfish");
               put("Cipher.PBEWithHMacSHA1AndCast5",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA1$Cast5");
               put("Cipher.PBEWithHMacSHA1AndDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA1$DES");
               put("Cipher.PBEWithHMacSHA1AndKhazad",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA1$Khazad");
               put("Cipher.PBEWithHMacSHA1AndSerpent",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA1$Serpent");
               put("Cipher.PBEWithHMacSHA1AndSquare",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA1$Square");
               put("Cipher.PBEWithHMacSHA1AndTripleDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA1$TripleDES");
               put("Cipher.PBEWithHMacSHA1AndTwofish",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA1$Twofish");

               put("Cipher.PBEWithHMacSHA256AndAES",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA256$AES");
               put("Cipher.PBEWithHMacSHA256AndAnubis",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA256$Anubis");
               put("Cipher.PBEWithHMacSHA256AndBlowfish",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA256$Blowfish");
               put("Cipher.PBEWithHMacSHA256AndCast5",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA256$Cast5");
               put("Cipher.PBEWithHMacSHA256AndDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA256$DES");
               put("Cipher.PBEWithHMacSHA256AndKhazad",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA256$Khazad");
               put("Cipher.PBEWithHMacSHA256AndSerpent",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA256$Serpent");
               put("Cipher.PBEWithHMacSHA256AndSquare",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA256$Square");
               put("Cipher.PBEWithHMacSHA256AndTripleDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA256$TripleDES");
               put("Cipher.PBEWithHMacSHA256AndTwofish",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA256$Twofish");

               put("Cipher.PBEWithHMacSHA384AndAES",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA384$AES");
               put("Cipher.PBEWithHMacSHA384AndAnubis",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA384$Anubis");
               put("Cipher.PBEWithHMacSHA384AndBlowfish",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA384$Blowfish");
               put("Cipher.PBEWithHMacSHA384AndCast5",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA384$Cast5");
               put("Cipher.PBEWithHMacSHA384AndDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA384$DES");
               put("Cipher.PBEWithHMacSHA384AndKhazad",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA384$Khazad");
               put("Cipher.PBEWithHMacSHA384AndSerpent",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA384$Serpent");
               put("Cipher.PBEWithHMacSHA384AndSquare",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA384$Square");
               put("Cipher.PBEWithHMacSHA384AndTripleDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA384$TripleDES");
               put("Cipher.PBEWithHMacSHA384AndTwofish",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA384$Twofish");

               put("Cipher.PBEWithHMacSHA512AndAES",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA512$AES");
               put("Cipher.PBEWithHMacSHA512AndAnubis",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA512$Anubis");
               put("Cipher.PBEWithHMacSHA512AndBlowfish",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA512$Blowfish");
               put("Cipher.PBEWithHMacSHA512AndCast5",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA512$Cast5");
               put("Cipher.PBEWithHMacSHA512AndDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA512$DES");
               put("Cipher.PBEWithHMacSHA512AndKhazad",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA512$Khazad");
               put("Cipher.PBEWithHMacSHA512AndSerpent",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA512$Serpent");
               put("Cipher.PBEWithHMacSHA512AndSquare",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA512$Square");
               put("Cipher.PBEWithHMacSHA512AndTripleDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA512$TripleDES");
               put("Cipher.PBEWithHMacSHA512AndTwofish",
                   "gnu.crypto.jce.cipher.PBES2$HMacSHA512$Twofish");

               put("Cipher.PBEWithHMacTigerAndAES",
                   "gnu.crypto.jce.cipher.PBES2$HMacTiger$AES");
               put("Cipher.PBEWithHMacTigerAndAnubis",
                   "gnu.crypto.jce.cipher.PBES2$HMacTiger$Anubis");
               put("Cipher.PBEWithHMacTigerAndBlowfish",
                   "gnu.crypto.jce.cipher.PBES2$HMacTiger$Blowfish");
               put("Cipher.PBEWithHMacTigerAndCast5",
                   "gnu.crypto.jce.cipher.PBES2$HMacTiger$Cast5");
               put("Cipher.PBEWithHMacTigerAndDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacTiger$DES");
               put("Cipher.PBEWithHMacTigerAndKhazad",
                   "gnu.crypto.jce.cipher.PBES2$HMacTiger$Khazad");
               put("Cipher.PBEWithHMacTigerAndSerpent",
                   "gnu.crypto.jce.cipher.PBES2$HMacTiger$Serpent");
               put("Cipher.PBEWithHMacTigerAndSquare",
                   "gnu.crypto.jce.cipher.PBES2$HMacTiger$Square");
               put("Cipher.PBEWithHMacTigerAndTripleDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacTiger$TripleDES");
               put("Cipher.PBEWithHMacTigerAndTwofish",
                   "gnu.crypto.jce.cipher.PBES2$HMacTiger$Twofish");

               put("Cipher.PBEWithHMacWhirlpoolAndAES",
                   "gnu.crypto.jce.cipher.PBES2$HMacWhirlpool$AES");
               put("Cipher.PBEWithHMacWhirlpoolAndAnubis",
                   "gnu.crypto.jce.cipher.PBES2$HMacWhirlpool$Anubis");
               put("Cipher.PBEWithHMacWhirlpoolAndBlowfish",
                   "gnu.crypto.jce.cipher.PBES2$HMacWhirlpool$Blowfish");
               put("Cipher.PBEWithHMacWhirlpoolAndCast5",
                   "gnu.crypto.jce.cipher.PBES2$HMacWhirlpool$Cast5");
               put("Cipher.PBEWithHMacWhirlpoolAndDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacWhirlpool$DES");
               put("Cipher.PBEWithHMacWhirlpoolAndKhazad",
                   "gnu.crypto.jce.cipher.PBES2$HMacWhirlpool$Khazad");
               put("Cipher.PBEWithHMacWhirlpoolAndSerpent",
                   "gnu.crypto.jce.cipher.PBES2$HMacWhirlpool$Serpent");
               put("Cipher.PBEWithHMacWhirlpoolAndSquare",
                   "gnu.crypto.jce.cipher.PBES2$HMacWhirlpool$Square");
               put("Cipher.PBEWithHMacWhirlpoolAndTripleDES",
                   "gnu.crypto.jce.cipher.PBES2$HMacWhirlpool$TripleDES");
               put("Cipher.PBEWithHMacWhirlpoolAndTwofish",
                   "gnu.crypto.jce.cipher.PBES2$HMacWhirlpool$Twofish");

               // SecretKeyFactory interface to PBKDF2.
               put("SecretKeyFactory.PBKDF2WithHMacHaval",
                   "gnu.crypto.jce.PBKDF2SecretKeyFactory$HMacHaval");
               put("SecretKeyFactory.PBKDF2WithHMacMD2",
                   "gnu.crypto.jce.PBKDF2SecretKeyFactory$HMacMD2");
               put("SecretKeyFactory.PBKDF2WithHMacMD4",
                   "gnu.crypto.jce.PBKDF2SecretKeyFactory$HMacMD4");
               put("SecretKeyFactory.PBKDF2WithHMacMD5",
                   "gnu.crypto.jce.PBKDF2SecretKeyFactory$HMacMD5");
               put("SecretKeyFactory.PBKDF2WithHMacSHA1",
                   "gnu.crypto.jce.PBKDF2SecretKeyFactory$HMacSHA1");
               put("SecretKeyFactory.PBKDF2WithHMacSHA256",
                   "gnu.crypto.jce.PBKDF2SecretKeyFactory$HMacSHA256");
               put("SecretKeyFactory.PBKDF2WithHMacSHA384",
                   "gnu.crypto.jce.PBKDF2SecretKeyFactory$HMacSHA384");
               put("SecretKeyFactory.PBKDF2WithHMacSHA512",
                   "gnu.crypto.jce.PBKDF2SecretKeyFactory$HMacSHA512");
               put("SecretKeyFactory.PBKDF2WithHMacTiger",
                   "gnu.crypto.jce.PBKDF2SecretKeyFactory$HMacTiger");
               put("SecretKeyFactory.PBKDF2WithHMacWhirlpool",
                   "gnu.crypto.jce.PBKDF2SecretKeyFactory$HMacWhirlpool");

               put("AlgorithmParameters.BlockCipherParameters",
                   "gnu.crypto.jce.params.BlockCipherParameters");

               // MAC
               put("Mac.HMAC-MD2", "gnu.crypto.jce.mac.HMacMD2Spi");
               put("Mac.HMAC-MD4", "gnu.crypto.jce.mac.HMacMD4Spi");
               put("Mac.HMAC-MD5", "gnu.crypto.jce.mac.HMacMD5Spi");
               put("Mac.HMAC-RIPEMD128", "gnu.crypto.jce.mac.HMacRipeMD128Spi");
               put("Mac.HMAC-RIPEMD160", "gnu.crypto.jce.mac.HMacRipeMD160Spi");
               put("Mac.HMAC-SHA160", "gnu.crypto.jce.mac.HMacSHA160Spi");
               put("Mac.HMAC-SHA256", "gnu.crypto.jce.mac.HMacSHA256Spi");
               put("Mac.HMAC-SHA384", "gnu.crypto.jce.mac.HMacSHA384Spi");
               put("Mac.HMAC-SHA512", "gnu.crypto.jce.mac.HMacSHA512Spi");
               put("Mac.HMAC-TIGER", "gnu.crypto.jce.mac.HMacTigerSpi");
               put("Mac.HMAC-HAVAL", "gnu.crypto.jce.mac.HMacHavalSpi");
               put("Mac.HMAC-WHIRLPOOL", "gnu.crypto.jce.mac.HMacWhirlpoolSpi");
               put("Mac.TMMH16", "gnu.crypto.jce.mac.TMMH16Spi");
               put("Mac.UHASH32", "gnu.crypto.jce.mac.UHash32Spi");
               put("Mac.UMAC32", "gnu.crypto.jce.mac.UMac32Spi");

               // KeyStore
               //      put("KeyStore.GKR", gnu.crypto.jce.keyring.GnuKeyring.class.getName());
               put("KeyStore.GKR", "gnu.crypto.jce.keyring.GnuKeyring");

               // Aliases
               put("Alg.Alias.AlgorithmParameters.AES", "BlockCipherParameters");
               put("Alg.Alias.AlgorithmParameters.BLOWFISH", "BlockCipherParameters");
               put("Alg.Alias.AlgorithmParameters.ANUBIS", "BlockCipherParameters");
               put("Alg.Alias.AlgorithmParameters.KHAZAD", "BlockCipherParameters");
               put("Alg.Alias.AlgorithmParameters.NULL", "BlockCipherParameters");
               put("Alg.Alias.AlgorithmParameters.RIJNDAEL", "BlockCipherParameters");
               put("Alg.Alias.AlgorithmParameters.SERPENT", "BlockCipherParameters");
               put("Alg.Alias.AlgorithmParameters.SQUARE", "BlockCipherParameters");
               put("Alg.Alias.AlgorithmParameters.TWOFISH", "BlockCipherParameters");
               put("Alg.Alias.Cipher.RC4", "ARCFOUR");
               put("Alg.Alias.Cipher.3-DES", "TRIPLEDES");
               put("Alg.Alias.Cipher.3DES", "TRIPLEDES");
               put("Alg.Alias.Cipher.DES-EDE", "TRIPLEDES");
               put("Alg.Alias.Cipher.DESede", "TRIPLEDES");
               put("Alg.Alias.Cipher.CAST128", "CAST5");
               put("Alg.Alias.Cipher.CAST-128", "CAST5");
               put("Alg.Alias.MessageDigest.SHS", "SHA-160");
               put("Alg.Alias.MessageDigest.SHA", "SHA-160");
               put("Alg.Alias.MessageDigest.SHA1", "SHA-160");
               put("Alg.Alias.MessageDigest.SHA-1", "SHA-160");
               put("Alg.Alias.MessageDigest.SHA2-256", "SHA-256");
               put("Alg.Alias.MessageDigest.SHA2-384", "SHA-384");
               put("Alg.Alias.MessageDigest.SHA2-512", "SHA-512");
               put("Alg.Alias.MessageDigest.SHA256", "SHA-256");
               put("Alg.Alias.MessageDigest.SHA384", "SHA-384");
               put("Alg.Alias.MessageDigest.SHA512", "SHA-512");
               put("Alg.Alias.MessageDigest.RIPEMD-160", "RIPEMD160");
               put("Alg.Alias.MessageDigest.RIPEMD-128", "RIPEMD128");
               put("Alg.Alias.Mac.HMAC-SHS", "HMAC-SHA160");
               put("Alg.Alias.Mac.HMAC-SHA", "HMAC-SHA160");
               put("Alg.Alias.Mac.HMAC-SHA1", "HMAC-SHA160");
               put("Alg.Alias.Mac.HMAC-SHA-160", "HMAC-SHA160");
               put("Alg.Alias.Mac.HMAC-SHA-256", "HMAC-SHA256");
               put("Alg.Alias.Mac.HMAC-SHA-384", "HMAC-SHA384");
               put("Alg.Alias.Mac.HMAC-SHA-512", "HMAC-SHA512");
               put("Alg.Alias.Mac.HMAC-RIPEMD-160", "HMAC-RIPEMD160");
               put("Alg.Alias.Mac.HMAC-RIPEMD-128", "HMAC-RIPEMD128");
               put("Alg.Alias.SecureRandom.RC4", "ARCFOUR");
               put("Alg.Alias.SecureRandom.SHA-1PRNG", "SHA-160PRNG");
               put("Alg.Alias.SecureRandom.SHA1PRNG", "SHA-160PRNG");
               put("Alg.Alias.SecureRandom.SHAPRNG", "SHA-160PRNG");
               put("Alg.Alias.SecureRandom.SHA-256PRNG", "SHA-256PRNG");
               put("Alg.Alias.SecureRandom.SHA-2-1PRNG", "SHA-256PRNG");
               put("Alg.Alias.SecureRandom.SHA-384PRNG", "SHA-384PRNG");
               put("Alg.Alias.SecureRandom.SHA-2-2PRNG", "SHA-384PRNG");
               put("Alg.Alias.SecureRandom.SHA-512PRNG", "SHA-512PRNG");
               put("Alg.Alias.SecureRandom.SHA-2-3PRNG", "SHA-512PRNG");
               put("Alg.Alias.KeyPairGenerator.DSA", "DSS");
               put("Alg.Alias.Signature.DSA", "DSS/RAW");
               put("Alg.Alias.Signature.SHAwithDSA", "DSS/RAW");
               put("Alg.Alias.Signature.SHA1withDSA", "DSS/RAW");
               put("Alg.Alias.Signature.SHA160withDSA", "DSS/RAW");
               put("Alg.Alias.Signature.SHA/DSA", "DSS/RAW");
               put("Alg.Alias.Signature.SHA1/DSA", "DSS/RAW");
               put("Alg.Alias.Signature.SHA-1/DSA", "DSS/RAW");
               put("Alg.Alias.Signature.SHA-160/DSA", "DSS/RAW");
               put("Alg.Alias.Signature.DSAwithSHA", "DSS/RAW");
               put("Alg.Alias.Signature.DSAwithSHA1", "DSS/RAW");
               put("Alg.Alias.Signature.DSAwithSHA160", "DSS/RAW");
               put("Alg.Alias.Signature.RSA-PSS", "RSA-PSS/RAW");
               put("Alg.Alias.Signature.RSAPSS", "RSA-PSS/RAW");
               put("Alg.Alias.KeyStore.GnuKeyring", "GKR");

               //      put("Alg.Alias.Signature.OID.1.2.840.10040.4.3", "DSS");
               //      put("Alg.Alias.Signature.1.2.840.10040.4.3",     "DSS");
               //      put("Alg.Alias.Signature.1.3.14.3.2.13",         "DSS");
               //      put("Alg.Alias.Signature.1.3.14.3.2.27",         "DSS");

               // SASL Client and Server mechanisms
               put("SaslClientFactory.ANONYMOUS", "gnu.crypto.sasl.ClientFactory");
               put("SaslClientFactory.PLAIN", "gnu.crypto.sasl.ClientFactory");
               put("SaslClientFactory.CRAM-MD5", "gnu.crypto.sasl.ClientFactory");
               put("SaslClientFactory.SRP", "gnu.crypto.sasl.ClientFactory");

               put("SaslServerFactory.ANONYMOUS", "gnu.crypto.sasl.ServerFactory");
               put("SaslServerFactory.PLAIN", "gnu.crypto.sasl.ServerFactory");
               put("SaslServerFactory.CRAM-MD5", "gnu.crypto.sasl.ServerFactory");
               put("SaslServerFactory.SRP-MD5", "gnu.crypto.sasl.ServerFactory");
               put("SaslServerFactory.SRP-SHA-160", "gnu.crypto.sasl.ServerFactory");
               put("SaslServerFactory.SRP-RIPEMD128", "gnu.crypto.sasl.ServerFactory");
               put("SaslServerFactory.SRP-RIPEMD160", "gnu.crypto.sasl.ServerFactory");
               put("SaslServerFactory.SRP-TIGER", "gnu.crypto.sasl.ServerFactory");
               put("SaslServerFactory.SRP-WHIRLPOOL", "gnu.crypto.sasl.ServerFactory");

               put("Alg.Alias.SaslServerFactory.SRP-SHS", "SRP-SHA-160");
               put("Alg.Alias.SaslServerFactory.SRP-SHA", "SRP-SHA-160");
               put("Alg.Alias.SaslServerFactory.SRP-SHA1", "SRP-SHA-160");
               put("Alg.Alias.SaslServerFactory.SRP-SHA-1", "SRP-SHA-160");
               put("Alg.Alias.SaslServerFactory.SRP-SHA160", "SRP-SHA-160");
               put("Alg.Alias.SaslServerFactory.SRP-RIPEMD-128", "SRP-RIPEMD128");
               put("Alg.Alias.SaslServerFactory.SRP-RIPEMD-160", "SRP-RIPEMD160");

               return null;
            }
         }
      );
   }

   // Class methods
   // -------------------------------------------------------------------------

   /**
    * <p>Returns a {@link Set} of names of message digest algorithms available
    * from this {@link Provider}.</p>
    *
    * @return a {@link Set} of hash names (Strings).
    */
   public static final Set getMessageDigestNames() {
      return HashFactory.getNames();
   }

   /**
    * <p>Returns a {@link Set} of names of secure random implementations
    * available from this {@link Provider}.</p>
    *
    * @return a {@link Set} of secure random names (Strings).
    */
   public static final Set getSecureRandomNames() {
      Set result = new HashSet();
      // do all the hash-based prng algorithms
      Set md = gnu.crypto.hash.HashFactory.getNames();
      for (Iterator it = md.iterator(); it.hasNext();) {
         result.add(((String) it.next()).toUpperCase() + "PRNG");
      }
      // add ICM and UMAC based generators
      result.add(Registry.ICM_PRNG.toUpperCase());
      result.add(Registry.UMAC_PRNG.toUpperCase());
      result.add(Registry.ARCFOUR_PRNG.toUpperCase());

      return Collections.unmodifiableSet(result);
   }

   /**
    * <p>Returns a {@link Set} of names of keypair generator implementations
    * available from this {@link Provider}.</p>
    *
    * @return a {@link Set} of key pair generator names (Strings).
    */
   public static final Set getKeyPairGeneratorNames() {
      return KeyPairGeneratorFactory.getNames();
   }

   /**
    * <p>Returns a {@link Set} of names of signature scheme implementations
    * available from this {@link Provider}.</p>
    *
    * @return a {@link Set} of signature names (Strings).
    */
   public static final Set getSignatureNames() {
      return SignatureFactory.getNames();
   }

   /**
    * <p>Returns a {@link Set} of names of symmetric key block cipher algorithms
    * available from this {@link Provider}.</p>
    *
    * @return a {@link Set} of cipher names (Strings).
    */
   public static final Set getCipherNames() {
      HashSet s = new HashSet();
      s.addAll(CipherFactory.getNames());
      s.add(Registry.ARCFOUR_PRNG);
      return s;
   }

   /**
    * <p>Returns a {@link Set} of names of MAC algorithms available from
    * this {@link Provider}.</p>
    *
    * @return a {@link Set} of MAC names (Strings).
    */
   public static final Set getMacNames() {
      return MacFactory.getNames();
   }

   /**
    * <p>Returns a {@link Set} of names of SASL Client mechanisms available from
    * this {@link Provider}.</p>
    *
    * @return a {@link Set} of SASL Client mechanisms (Strings).
    */
   public static final Set getSaslClientMechanismNames() {
      return ClientFactory.getNames();
   }

   /**
    * <p>Returns a {@link Set} of names of SASL Server mechanisms available from
    * this {@link Provider}.</p>
    *
    * @return a {@link Set} of SASL Server mechanisms (Strings).
    */
   public static final Set getSaslServerMechanismNames() {
      return ServerFactory.getNames();
   }

   // Instance methods
   // -------------------------------------------------------------------------
}
