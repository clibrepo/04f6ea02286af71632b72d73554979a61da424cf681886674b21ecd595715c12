package gnu.testlet.gnu.crypto.cipher;

// ----------------------------------------------------------------------------
// $Id: TestOfCipherFactory.java,v 1.1 2002/12/19 09:29:55 raif Exp $
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

// Tags: GNU-CRYPTO

import gnu.crypto.cipher.CipherFactory;
import gnu.crypto.cipher.IBlockCipher;
import gnu.testlet.TestHarness;
import gnu.testlet.Testlet;
import java.util.Iterator;

/**
 * Conformance tests for the CipherFactory implementation.
 *
 * @version $Revision: 1.1 $
 */
public class TestOfCipherFactory implements Testlet {

   // Constants and variables
   // -------------------------------------------------------------------------

   // Constructor(s)
   // -------------------------------------------------------------------------

   // default 0-arguments constructor

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   public void test(TestHarness harness) {
      harness.checkPoint("TestOfCipherFactory");
      String cipher;
      IBlockCipher algorithm;
      for (Iterator it = CipherFactory.getNames().iterator(); it.hasNext(); ) {
         cipher = (String) it.next();
         try {
            algorithm = null;
            algorithm = CipherFactory.getInstance(cipher);
            harness.check(algorithm != null, "getInstance("+String.valueOf(cipher)+")");
         } catch (InternalError x) {
            harness.debug(x);
            harness.fail("TestOfCipherFactory.getInstance("+String.valueOf(cipher)+")");
         }
      }
   }
}
