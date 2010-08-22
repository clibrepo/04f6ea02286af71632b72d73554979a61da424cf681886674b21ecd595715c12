package gnu.testlet.gnu.crypto.sasl.srp;

// ----------------------------------------------------------------------------
// $Id: TestOfSRPPasswordFile.java,v 1.3 2003/12/25 02:19:39 uid66198 Exp $
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

import gnu.crypto.Registry;
import gnu.crypto.hash.IMessageDigest;
import gnu.crypto.key.srp6.SRPKeyPairGenerator;
import gnu.crypto.key.srp6.SRPPrivateKey;
import gnu.crypto.key.srp6.SRPPublicKey;
import gnu.crypto.key.IKeyPairGenerator;
import gnu.crypto.sasl.srp.PasswordFile;
import gnu.crypto.sasl.srp.SRP;
import gnu.crypto.sasl.srp.SRPRegistry;
import gnu.crypto.util.Util;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Random;

/**
 * <p>Regression tests for SRP password file operations.</p>
 *
 * @version $Revision: 1.3 $
 */
public class TestOfSRPPasswordFile implements Testlet {

	// Constants and variables
	// -------------------------------------------------------------------------

   private Random prng = new Random();

	// Constructor(s)
	// -------------------------------------------------------------------------

   // default 0-arguments ctor

	// Class methods
	// -------------------------------------------------------------------------

	// Instance methods
	// -------------------------------------------------------------------------

   public void test(final TestHarness harness) {
      harness.checkPoint("TestOfSRPPasswordFile");
      try {
   	   exerciseFile(harness, Registry.SHA160_HASH);
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("exerciseFile()");
      }
      try {
   	   exerciseFile(harness, Registry.MD5_HASH);
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("exerciseFile(\"MD5\")");
      }
   }

//   private void exerciseFile(TestHarness harness, SRP srp) throws IOException {
   private void exerciseFile(final TestHarness harness, final String md)
   throws IOException {
      final String user = "test";
      final String password = "test";
      final String pFile = "./test";
      final String p2File = pFile + "2"; // ./test2
      final String cFile = pFile + ".conf"; // ./test.conf

		final File f = new File(pFile);
		if (!f.exists()) {
		   if (f.createNewFile()) {
		      f.deleteOnExit();
         }
		} else if (!f.isFile()) {
		   throw new RuntimeException("File object (./test) exists but is not a file");
      } else if (!f.canRead() || !f.canWrite()) {
		   throw new RuntimeException("File (./test) exists but is not accessible");
      }
		final PasswordFile tpasswd = new PasswordFile(pFile, p2File, cFile);
		if (!tpasswd.contains(user)) {
		   final byte[] testSalt = new byte[10];
		   prng.nextBytes(testSalt);
		   tpasswd.add(user, password, testSalt, SRPRegistry.N_2048_BITS);
		} else {
		   tpasswd.changePasswd(user, password);
      }

		final String[] entry = tpasswd.lookup(user, md);
		final BigInteger v = new BigInteger(1, Util.fromBase64(entry[0]));
		final byte[] salt = Util.fromBase64(entry[1]);

		final String[] mpi = tpasswd.lookupConfig(entry[2]);
		final BigInteger N = new BigInteger(1, Util.fromBase64(mpi[0]));
		final BigInteger g = new BigInteger(1, Util.fromBase64(mpi[1]));

      final IKeyPairGenerator kpg = new SRPKeyPairGenerator();
      final HashMap attributes = new HashMap();
      attributes.put(SRPKeyPairGenerator.SHARED_MODULUS, N);
      attributes.put(SRPKeyPairGenerator.GENERATOR,      g);
      kpg.setup(attributes);

      final KeyPair clientKP = kpg.generate();
      final BigInteger A = ((SRPPublicKey)  clientKP.getPublic() ).getY();
      final BigInteger a = ((SRPPrivateKey) clientKP.getPrivate()).getX();

      attributes.put(SRPKeyPairGenerator.USER_VERIFIER, v);
      kpg.setup(attributes);

		final KeyPair serverKP = kpg.generate();
      final BigInteger B = ((SRPPublicKey)  serverKP.getPublic() ).getY();
      final BigInteger b = ((SRPPrivateKey) serverKP.getPrivate()).getX();

      // compute u = H(A | B)
//      IMessageDigest hash = srp.newDigest();
//      IMessageDigest hash = HashFactory.getInstance(md);
      final SRP srp = SRP.instance(md);
      final IMessageDigest hash = srp.newDigest();
      byte[] buffy;
      buffy = Util.trim(A);
      hash.update(buffy, 0, buffy.length);
      buffy = Util.trim(B);
      hash.update(buffy, 0, buffy.length);

      final BigInteger u = new BigInteger(1, hash.digest());

      // compute S = ((A * (v ** u)) ** b) % N
      final BigInteger S1 = A.multiply(v.modPow(u, N)).modPow(b, N);

      // compute K = H(S) (as of rev 08)
      final byte[] s1Bytes = Util.trim(S1);
      hash.update(s1Bytes, 0, s1Bytes.length);

		final byte[] K1 = hash.digest();


		final BigInteger x = new BigInteger(1, srp.computeX(salt, user, password));

      // compute S = ((B - (3 * (g ** x))) ** (a + (u * x))) % N
      // compute S = ((B - (3 * v)) ** (a + (u * x))) % N
      final BigInteger S2 = B.subtract(BigInteger.valueOf(3L).multiply(v))
            .modPow(a.add(u.multiply(x)), N);

      // compute K = H(S) (as of rev 08)
      final byte[] s2Bytes = Util.trim(S2);
      hash.update(s2Bytes, 0, s2Bytes.length);

		final byte[] K2 = hash.digest();

		harness.check(S1.equals(S2));
		harness.check(Arrays.equals(K1, K2));

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