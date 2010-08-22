package gnu.testlet.gnu.crypto.cipher;

// ----------------------------------------------------------------------------
// $Id: TestOfSquare.java,v 1.2 2003/04/28 11:14:18 raif Exp $
//
// Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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
// Uses: BaseCipherTestCase

import gnu.crypto.cipher.IBlockCipher;
import gnu.crypto.cipher.Square;
import gnu.testlet.TestHarness;
import java.util.HashMap;

/**
 * <p>Conformance tests for the {@link Square} implementation.</p>
 *
 * @version $Revision: 1.2 $
 */
public class TestOfSquare extends BaseCipherTestCase {

   // Constants and variables
   // -------------------------------------------------------------------------

   // KAT and MCT vectors used in this test case
   private static final String[] vk_128;
   private static final String[] vt_128;
   private static final String[] mct_ecb_e_128;
   private static final String[] mct_ecb_d_128;
   private static final String[] mct_cbc_e_128;
   private static final String[] mct_cbc_d_128;

   // static initialiser
   static {
      vk_128 = new String[] {
         "05F8AAFDEFB4F5F9C751E5B36C8A37D8", "60AFFC9B2312B1397177251CC9296391",
         "D67B7E07C38F311446E16DDD9EA96EBE", "39207579067031706FAB8C3A5C6E5524",
         "FC4F2602A3F6AC34F56906C2EEEE40C5"};

      vt_128 = new String[] {
         "C17B878EAF7D8CA82414E6E4C4A95149", "0A5C0887A1402D3C1A1F00298FD4F65D",
         "B5CD1003E2234CACB6E0F8124671FC46", "422BC7FBD31D4DBB445065C0B96250FD",
         "E528EB4AAED24077717DE65E2A934757"};

      mct_ecb_e_128 = new String[] {
         "04623E016479F2AF395F6BE61CF9E797", "68ABB73D5E60834F47974BE90D412556",
         "9137BB63EF3F92EB04E189BA95D3DF37", "C0143A7B13DF13BFF3350861EC20D25B",
         "AF0E869F42E3E14ADF0A5B04110B3AE5"};

      mct_ecb_d_128 = new String[] {
         "F064F8B9F358306CB8849C8194A468FC", "7DAE38E143FE19A07A23F0E303AB0CE5",
         "F8DFB20ABE6CFA2D9EC2EB9B7547B44B", "FDCCAF31173676F01F81283B809097D1",
         "75EB0C8884DE3DB0FC92695047E8AAC8"};

      mct_cbc_e_128 = new String[] {
         "36987073BCE283781E6E1EF0433DA1DD", "5433C261BEB31FEEDA016F6964BADB30",
         "7AA8B93ECFAB1A27ACD0A8B74D5D1AE7", "3AF465A0FB987C80879FACA8D26D5FEE",
         "2100C9742DE65007D3524DEC7A9858BB"};

      mct_cbc_d_128 = new String[] {
         "8FE89D15BE002BCA733E2A69C7D49AB5", "FCBE647F166FCD6C5C8C6741608E62DB",
         "B6F3BD29C2D260D5C0E223C54B9D877D", "4179351A962BAC5639D95B46DCB768C8",
         "71A450A6B86A2D25BB0177E0AEAFBB93"};
   }

   // Constructor(s)
   // -------------------------------------------------------------------------

   // default 0-arguments constructor

   // Class methods
   // -------------------------------------------------------------------------

   // Instance methods
   // -------------------------------------------------------------------------

   public void test(TestHarness harness) {
      harness.checkPoint("TestOfSquare");
      cipher = new Square();
      HashMap attrib = new HashMap();
      attrib.put(IBlockCipher.CIPHER_BLOCK_SIZE, new Integer(16));
      attrib.put(IBlockCipher.KEY_MATERIAL, new byte[16]);
      try {
         cipher.init(attrib);
         String algorithm = cipher.name();
         harness.check(validityTest(), "validityTest("+algorithm+")");
         harness.check(cloneabilityTest(), "cloneabilityTest("+algorithm+")");
         harness.check(katVK(vk_128, cipher, 16), "KAT VK "+algorithm+"-128");
         harness.check(katVT(vt_128, cipher, 16), "KAT VT "+algorithm+"-128");
         harness.check(mctEncryptECB(mct_ecb_e_128, cipher, 16), "MCT ECB Encryption "+algorithm+"-128");
         harness.check(mctDecryptECB(mct_ecb_d_128, cipher, 16), "MCT ECB Decryption "+algorithm+"-128");
         harness.check(mctEncryptCBC(mct_cbc_e_128, cipher, 16), "MCT CBC Encryption "+algorithm+"-128");
         harness.check(mctDecryptCBC(mct_cbc_d_128, cipher, 16), "MCT CBC Decryption "+algorithm+"-128");
      } catch (Exception x) {
         harness.debug(x);
         harness.fail("TestOfSquare");
      }
   }
}
