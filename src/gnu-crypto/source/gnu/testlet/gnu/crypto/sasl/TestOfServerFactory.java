package gnu.testlet.gnu.crypto.sasl;

// ----------------------------------------------------------------------------
// $Id: TestOfServerFactory.java,v 1.3 2003/05/30 13:07:23 raif Exp $
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
import gnu.crypto.sasl.ServerFactory;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;

import java.util.HashMap;

import javax.security.sasl.Sasl;

/**
 * Regression tests for SASL Server factories.
 *
 * @version $Revision: 1.3 $
 */
public class TestOfServerFactory implements Testlet {

	// Constants and variables
	// -------------------------------------------------------------------------

	// Constructor(s)
	// -------------------------------------------------------------------------

   // default 0-arguments ctor

	// Class methods
	// -------------------------------------------------------------------------

   private static boolean includes(String[] sa, String n) {
      for (int i = 0; i < sa.length; i++) {
         if (n.equals(sa[i])) {
            return true;
         }
      }
      return false;
   }

	// Instance methods
	// -------------------------------------------------------------------------

   public void test(TestHarness harness) {
      harness.checkPoint("TestOfServerFactory:null");

      ServerFactory factory = new ServerFactory();
	   String[] mechanisms = factory.getMechanismNames(null);

	   // should see all mechanisms
      harness.check(includes(mechanisms, Registry.SASL_SRP_MECHANISM), Registry.SASL_SRP_MECHANISM);
      harness.check(includes(mechanisms, Registry.SASL_CRAM_MD5_MECHANISM), Registry.SASL_CRAM_MD5_MECHANISM);
      harness.check(includes(mechanisms, Registry.SASL_PLAIN_MECHANISM), Registry.SASL_PLAIN_MECHANISM);
      harness.check(includes(mechanisms, Registry.SASL_ANONYMOUS_MECHANISM), Registry.SASL_ANONYMOUS_MECHANISM);

      harness.checkPoint("TestOfServerFactory:"+Sasl.POLICY_NOPLAINTEXT);
	   HashMap p = new HashMap();
	   p.put(Sasl.POLICY_NOPLAINTEXT, "true");
	   mechanisms = factory.getMechanismNames(p);

	   // should see all mechanisms except PLAIN
      harness.check(includes(mechanisms, Registry.SASL_SRP_MECHANISM), Registry.SASL_SRP_MECHANISM);
      harness.check(includes(mechanisms, Registry.SASL_CRAM_MD5_MECHANISM), Registry.SASL_CRAM_MD5_MECHANISM);
      harness.check(!includes(mechanisms, Registry.SASL_PLAIN_MECHANISM), Registry.SASL_PLAIN_MECHANISM);
      harness.check(includes(mechanisms, Registry.SASL_ANONYMOUS_MECHANISM), Registry.SASL_ANONYMOUS_MECHANISM);

      harness.checkPoint("TestOfServerFactory:"+Sasl.POLICY_NOACTIVE);
	   p.clear();
	   p.put(Sasl.POLICY_NOACTIVE, "true");
	   mechanisms = factory.getMechanismNames(p);

	   // should see all mechanisms except PLAIN & CRAM-MD5
      harness.check(includes(mechanisms, Registry.SASL_SRP_MECHANISM), Registry.SASL_SRP_MECHANISM);
      harness.check(!includes(mechanisms, Registry.SASL_CRAM_MD5_MECHANISM), Registry.SASL_CRAM_MD5_MECHANISM);
      harness.check(!includes(mechanisms, Registry.SASL_PLAIN_MECHANISM), Registry.SASL_PLAIN_MECHANISM);
      harness.check(includes(mechanisms, Registry.SASL_ANONYMOUS_MECHANISM), Registry.SASL_ANONYMOUS_MECHANISM);

      harness.checkPoint("TestOfServerFactory:"+Sasl.POLICY_NODICTIONARY);
	   p.clear();
	   p.put(Sasl.POLICY_NODICTIONARY, "true");
	   mechanisms = factory.getMechanismNames(p);

	   // should see all mechanisms except PLAIN & CRAM-MD5
      harness.check(includes(mechanisms, Registry.SASL_SRP_MECHANISM), Registry.SASL_SRP_MECHANISM);
      harness.check(!includes(mechanisms, Registry.SASL_CRAM_MD5_MECHANISM), Registry.SASL_CRAM_MD5_MECHANISM);
      harness.check(!includes(mechanisms, Registry.SASL_PLAIN_MECHANISM), Registry.SASL_PLAIN_MECHANISM);
      harness.check(includes(mechanisms, Registry.SASL_ANONYMOUS_MECHANISM), Registry.SASL_ANONYMOUS_MECHANISM);

      harness.checkPoint("TestOfServerFactory:"+Sasl.POLICY_NOANONYMOUS);
	   p.clear();
	   p.put(Sasl.POLICY_NOANONYMOUS, "true");
	   mechanisms = factory.getMechanismNames(p);

	   // should see all mechanisms except ANONYMOUS
      harness.check(includes(mechanisms, Registry.SASL_SRP_MECHANISM), Registry.SASL_SRP_MECHANISM);
      harness.check(includes(mechanisms, Registry.SASL_CRAM_MD5_MECHANISM), Registry.SASL_CRAM_MD5_MECHANISM);
      harness.check(includes(mechanisms, Registry.SASL_PLAIN_MECHANISM), Registry.SASL_PLAIN_MECHANISM);
      harness.check(!includes(mechanisms, Registry.SASL_ANONYMOUS_MECHANISM), Registry.SASL_ANONYMOUS_MECHANISM);

      harness.checkPoint("TestOfServerFactory:"+Sasl.POLICY_FORWARD_SECRECY);
	   p.clear();
	   p.put(Sasl.POLICY_FORWARD_SECRECY, "true");
	   mechanisms = factory.getMechanismNames(p);

	   // should see all mechanisms except ANONYMOUS,PLAIN & CRAM-MD5
      harness.check(includes(mechanisms, Registry.SASL_SRP_MECHANISM), Registry.SASL_SRP_MECHANISM);
      harness.check(!includes(mechanisms, Registry.SASL_CRAM_MD5_MECHANISM), Registry.SASL_CRAM_MD5_MECHANISM);
      harness.check(!includes(mechanisms, Registry.SASL_PLAIN_MECHANISM), Registry.SASL_PLAIN_MECHANISM);
      harness.check(!includes(mechanisms, Registry.SASL_ANONYMOUS_MECHANISM), Registry.SASL_ANONYMOUS_MECHANISM);

      harness.checkPoint("TestOfServerFactory:"+Sasl.POLICY_PASS_CREDENTIALS);
	   p.clear();
	   p.put(Sasl.POLICY_PASS_CREDENTIALS, "true");
	   mechanisms = factory.getMechanismNames(p);
	   // should see none
      harness.check(!includes(mechanisms, Registry.SASL_SRP_MECHANISM), Registry.SASL_SRP_MECHANISM);
	   harness.check(!includes(mechanisms, Registry.SASL_SRP_MECHANISM), Registry.SASL_SRP_MECHANISM);
      harness.check(!includes(mechanisms, Registry.SASL_CRAM_MD5_MECHANISM), Registry.SASL_CRAM_MD5_MECHANISM);
      harness.check(!includes(mechanisms, Registry.SASL_PLAIN_MECHANISM), Registry.SASL_PLAIN_MECHANISM);
      harness.check(!includes(mechanisms, Registry.SASL_ANONYMOUS_MECHANISM), Registry.SASL_ANONYMOUS_MECHANISM);
	}
}
