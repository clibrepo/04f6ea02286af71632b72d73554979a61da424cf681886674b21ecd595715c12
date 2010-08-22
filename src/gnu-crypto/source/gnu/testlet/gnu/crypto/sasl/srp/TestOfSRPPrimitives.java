package gnu.testlet.gnu.crypto.sasl.srp;

// ----------------------------------------------------------------------------
// $Id: TestOfSRPPrimitives.java,v 1.6 2003/12/25 02:19:39 uid66198 Exp $
//
// Copyright (C) 2003 Free Software Foundation, Inc.
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

// Tags: GNU-CRYPTO

import gnu.crypto.hash.IMessageDigest;
import gnu.crypto.key.IKeyPairGenerator;
import gnu.crypto.key.srp6.SRPKeyPairGenerator;
import gnu.crypto.key.srp6.SRPPrivateKey;
import gnu.crypto.key.srp6.SRPPublicKey;
import gnu.crypto.sasl.srp.PasswordFile;
import gnu.crypto.sasl.srp.SRP;
import gnu.crypto.sasl.srp.SRPRegistry;
import gnu.crypto.util.PRNG;
import gnu.crypto.util.Util;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.HashMap;

/**
 * <p>Regression tests for SRP cryptographic primitives.</p>
 *
 * @version $Revision: 1.6 $
 */
public class TestOfSRPPrimitives implements Testlet {

   // Constants and variables
   // -------------------------------------------------------------------------

   private String user = "TestOfSRPPrimitives";
   private String password = "secret";
   private String pFile = "./test";
   private String p2File = pFile + "2";
   private String cFile = pFile + ".conf";
   private PasswordFile tpasswd;

   // Constructor(s)
   // -------------------------------------------------------------------------

   // default 0-arguments ctor

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   public void test(TestHarness harness) {
      try {
         File f = new File(pFile);
         if (!f.exists()) {
            if (f.createNewFile()) {
               f.deleteOnExit();
            }
         } else if (!f.isFile()) {
            throw new RuntimeException("File object ./test exists but is not a file");
         } else if (!f.canRead() || !f.canWrite()) {
            throw new RuntimeException("File ./test exists but is not accessible");
         }
         tpasswd = new PasswordFile(pFile, p2File, cFile);
         if (!tpasswd.contains(user)) {
            byte[] testSalt = new byte[10];
            PRNG.nextBytes(testSalt);
            tpasswd.add(user, password, testSalt, "1");
         } else {
            tpasswd.changePasswd(user, password);
         }

         for (int i = 0; i < SRPRegistry.SRP_ALGORITHMS.length; i++ ) {
            exerciseAlgorithm(harness, SRP.instance(SRPRegistry.SRP_ALGORITHMS[i]));
         }

      } catch (IOException x) {
         harness.debug(x);
         harness.fail("TestOfSRPPrimitives");
      } finally {
         try {
            new File(pFile).delete(); // remove test file
         } catch (Exception ignored) {
         }
         try {
            new File(p2File).delete(); // remove test2 file
         } catch (Exception ignored) {
         }
         try {
            new File(cFile).delete(); // remove test.conf file
         } catch (Exception ignored) {
         }
      }
   }

   private void exerciseAlgorithm(TestHarness harness, SRP srp) {
      harness.checkPoint("TestOfSRPPrimitives.exerciseAlgorithm("+srp.getAlgorithm()+")");
      try {
         String[] entry = tpasswd.lookup(user, srp.getAlgorithm());
         BigInteger v = new BigInteger(1, Util.fromBase64(entry[0]));
         byte[] s = Util.fromBase64(entry[1]);

         String[] mpi = tpasswd.lookupConfig(entry[2]);
         BigInteger N = new BigInteger(1, Util.fromBase64(mpi[0]));
         BigInteger g = new BigInteger(1, Util.fromBase64(mpi[1]));

         IKeyPairGenerator kpg = new SRPKeyPairGenerator();
         HashMap attributes = new HashMap();
         attributes.put(SRPKeyPairGenerator.SHARED_MODULUS, N);
         attributes.put(SRPKeyPairGenerator.GENERATOR,      g);
         kpg.setup(attributes);

         KeyPair clientKP = kpg.generate();
         BigInteger A = ((SRPPublicKey)  clientKP.getPublic() ).getY();
         BigInteger a = ((SRPPrivateKey) clientKP.getPrivate()).getX();

         attributes.put(SRPKeyPairGenerator.USER_VERIFIER, v);
         kpg.setup(attributes);

         KeyPair serverKP = kpg.generate();
         BigInteger B = ((SRPPublicKey)  serverKP.getPublic() ).getY();
         BigInteger b = ((SRPPrivateKey) serverKP.getPrivate()).getX();

         // compute u = H(A | B)
         IMessageDigest hash = srp.newDigest();
         byte[] buffy;
         buffy = Util.trim(A);
         hash.update(buffy, 0, buffy.length);
         buffy = Util.trim(B);
         hash.update(buffy, 0, buffy.length);

         BigInteger u = new BigInteger(1, hash.digest());

         // compute S = ((A * (v ** u)) ** b) % N
         BigInteger S1 = A.multiply(v.modPow(u, N)).modPow(b, N);

         // compute K = H(S) (as of rev 08)
         byte[] s1Bytes = Util.trim(S1);
         hash.update(s1Bytes, 0, s1Bytes.length);

         byte[] K1 = hash.digest();

         
         BigInteger x = new BigInteger(1, srp.computeX(s, user, password));

         // compute S = ((B - (3 * (g ** x))) ** (a + (u * x))) % N
         // compute S = ((B - (3 * v)) ** (a + (u * x))) % N
         BigInteger S2 = B.subtract(BigInteger.valueOf(3L).multiply(v))
               .modPow(a.add(u.multiply(x)), N);

         // compute K = H(S) (as of rev 08)
         byte[] s2Bytes = Util.trim(S2);
         hash.update(s2Bytes, 0, s2Bytes.length);

         byte[] K2 = hash.digest();

         harness.check(Arrays.equals(K1, K2)); // #1,4,7,10

         // ===================================================================

         String L = "ALSM=IE,Slsd=fi4fg_;asdg_gsdfmof"; // available options
         String o = "KLK=FSOIIOAS,Oiasf,oaa=sdin_;asd"; // chosen options
         byte[] sid = "abc".getBytes();
         int ttl = 23;
         byte[] cIV = new byte[16];
         byte[] sIV = new byte[16];
         byte[] sCB = "host.acme.com".getBytes();
         byte[] cCB = "user@acme.com".getBytes();
         byte[] cn = "client".getBytes();
         byte[] sn = "server".getBytes();
         PRNG.nextBytes(cIV);
         PRNG.nextBytes(sIV);
         byte[] cM1 = srp.generateM1(
               N, g, user, s, A, B, K1, user, L, cn, cCB);
         byte[] cM2 = srp.generateM2(
               A, cM1, K1, user, user, o, sid, ttl, cIV, sIV, sCB);
         byte[] sM1 =  srp.generateM1(
               N, g, user, s, A, B, K2, user, L, cn, cCB);
         byte[] sM2 = srp.generateM2(
               A, sM1, K2, user, user, o, sid, ttl, cIV, sIV, sCB);

         harness.check(Arrays.equals(cM1, sM1)); // #2,5,8,11
         harness.check(Arrays.equals(cM2, sM2)); // #3,6,9,12

      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfSRPPrimitives.exerciseAlgorithm("+srp.getAlgorithm()+")");
      }
   }
}
