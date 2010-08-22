## Process this file with automake to produce Makefile.in.
#
# -----------------------------------------------------------------------------
# $Id: Makefile.am,v 1.3 2003/05/10 18:31:12 raif Exp $
#
# Copyright (C) 2002, 2003 Free Software Foundation, Inc.
#
# This file is part of GNU Crypto.
#
# GNU Crypto is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# GNU Crypto is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to the
#
#    Free Software Foundation Inc.,
#    59 Temple Place - Suite 330,
#    Boston, MA 02111-1307
#    USA
#
# Linking this library statically or dynamically with other modules is
# making a combined work based on this library.  Thus, the terms and
# conditions of the GNU General Public License cover the whole
# combination.
#
# As a special exception, the copyright holders of this library give
# you permission to link this library with independent modules to
# produce an executable, regardless of the license terms of these
# independent modules, and to copy and distribute the resulting
# executable under terms of your choice, provided that you also meet,
# for each linked independent module, the terms and conditions of the
# license of that module.  An independent module is a module which is
# not derived from or based on this library.  If you modify this
# library, you may extend this exception to your version of the
# library, but you are not obligated to do so.  If you do not wish to
# do so, delete this exception statement from your version.
# -----------------------------------------------------------------------------
#
# $Revision: 1.3 $
#

JAVAX_CRYPTO_LIBVERSION="1:0"

# Variables -------------------------------------------------------------------
AM_GCJFLAGS=@AM_GCJFLAGS@
JAVAC_CMD=$(GCJ) $(AM_GCJFLAGS) $(GCJFLAGS) -C

main_jar = javax-crypto.jar

BUILT_SOURCES = $(main_jar)
data_DATA = $(main_jar)
EXTRA_DIST = LICENSE

# Libraries and executables to compile ----------------------------------------
lib_LTLIBRARIES = lib-javax-crypto.la

# JCE (javax.crypto) library config -------------------------------------------
lib_javax_crypto_la_SOURCES = $(main_sources)
lib_javax_crypto_la_LIBADD =
lib_javax_crypto_la_LDFLAGS = -version-info $(JAVAX_CRYPTO_LIBVERSION)

# library source files --------------------------------------------------------
main_sources = \
 javax/crypto/BadPaddingException.java \
 javax/crypto/Cipher.java \
 javax/crypto/CipherInputStream.java \
 javax/crypto/CipherOutputStream.java \
 javax/crypto/CipherSpi.java \
 javax/crypto/EncryptedPrivateKeyInfo.java \
 javax/crypto/ExemptionMechanism.java \
 javax/crypto/ExemptionMechanismException.java \
 javax/crypto/ExemptionMechanismSpi.java \
 javax/crypto/IllegalBlockSizeException.java \
 javax/crypto/JCEUtil.java \
 javax/crypto/KeyAgreement.java \
 javax/crypto/KeyAgreementSpi.java \
 javax/crypto/KeyGenerator.java \
 javax/crypto/KeyGeneratorSpi.java \
 javax/crypto/Mac.java \
 javax/crypto/MacSpi.java \
 javax/crypto/NoSuchPaddingException.java \
 javax/crypto/NullCipher.java \
 javax/crypto/SealedObject.java \
 javax/crypto/SecretKey.java \
 javax/crypto/SecretKeyFactory.java \
 javax/crypto/SecretKeyFactorySpi.java \
 javax/crypto/ShortBufferException.java \
 \
 javax/crypto/interfaces/DHKey.java \
 javax/crypto/interfaces/DHPrivateKey.java \
 javax/crypto/interfaces/DHPublicKey.java \
 javax/crypto/interfaces/PBEKey.java \
 \
 javax/crypto/spec/DESedeKeySpec.java \
 javax/crypto/spec/DESKeySpec.java \
 javax/crypto/spec/DHGenParameterSpec.java \
 javax/crypto/spec/DHParameterSpec.java \
 javax/crypto/spec/DHPrivateKeySpec.java \
 javax/crypto/spec/DHPublicKeySpec.java \
 javax/crypto/spec/IvParameterSpec.java \
 javax/crypto/spec/PBEParameterSpec.java \
 javax/crypto/spec/PBEKeySpec.java \
 javax/crypto/spec/RC2ParameterSpec.java \
 javax/crypto/spec/RC5ParameterSpec.java \
 javax/crypto/spec/SecretKeySpec.java \
 \
 org/bouncycastle/asn1/ASN1OctetString.java \
 org/bouncycastle/asn1/ASN1OutputStream.java \
 org/bouncycastle/asn1/ASN1Sequence.java \
 org/bouncycastle/asn1/ASN1Set.java \
 org/bouncycastle/asn1/ASN1TaggedObject.java \
 org/bouncycastle/asn1/BERConstructedOctetString.java \
 org/bouncycastle/asn1/BERConstructedSequence.java \
 org/bouncycastle/asn1/BERInputStream.java \
 org/bouncycastle/asn1/BEROutputStream.java \
 org/bouncycastle/asn1/BERSet.java \
 org/bouncycastle/asn1/BERTaggedObject.java \
 org/bouncycastle/asn1/DERBMPString.java \
 org/bouncycastle/asn1/DERBitString.java \
 org/bouncycastle/asn1/DERBoolean.java \
 org/bouncycastle/asn1/DERConstructedSequence.java \
 org/bouncycastle/asn1/DERConstructedSet.java \
 org/bouncycastle/asn1/DEREncodable.java \
 org/bouncycastle/asn1/DEREncodableVector.java \
 org/bouncycastle/asn1/DEREnumerated.java \
 org/bouncycastle/asn1/DERGeneralizedTime.java \
 org/bouncycastle/asn1/DERIA5String.java \
 org/bouncycastle/asn1/DERInputStream.java \
 org/bouncycastle/asn1/DERInteger.java \
 org/bouncycastle/asn1/DERObject.java \
 org/bouncycastle/asn1/DERObjectIdentifier.java \
 org/bouncycastle/asn1/DEROctetString.java \
 org/bouncycastle/asn1/DEROutputStream.java \
 org/bouncycastle/asn1/DERPrintableString.java \
 org/bouncycastle/asn1/DERSequence.java \
 org/bouncycastle/asn1/DERSet.java \
 org/bouncycastle/asn1/DERString.java \
 org/bouncycastle/asn1/DERT61String.java \
 org/bouncycastle/asn1/DERTaggedObject.java \
 org/bouncycastle/asn1/DERTags.java \
 org/bouncycastle/asn1/DERUTCTime.java \
 org/bouncycastle/asn1/DERUTF8String.java \
 org/bouncycastle/asn1/DERUniversalString.java \
 org/bouncycastle/asn1/DERUnknownTag.java \
 org/bouncycastle/asn1/DERVisibleString.java \
 org/bouncycastle/asn1/OIDTokenizer.java \
 \
 org/bouncycastle/asn1/pkcs/EncryptedPrivateKeyInfo.java \
 org/bouncycastle/asn1/pkcs/PKCSObjectIdentifiers.java \
 \
 org/bouncycastle/asn1/x509/AlgorithmIdentifier.java

# .class files ----------------------------------------------------------------
main_classes = $(main_sources:.java=.class)

# Extra targets ---------------------------------------------------------------
SUFFIXES = .java .lo .o .obj .class .jar

%.class: %.java
	$(JAVAC_CMD) $<

$(main_jar): $(main_classes)
	@ jar cf $@ -C . javax/crypto/*.class javax/crypto/interfaces/*.class \
		javax/crypto/spec/*.class org/bouncycastle/asn1/*.class \
		org/bouncycastle/asn1/pkcs/*.class org/bouncycastle/asn1/x509/*.class

clean-local:
	find . -name '*.class' -exec rm -f '{}' ';'

MOSTLYCLEANFILES = $(main_jar) $(main_classes)

# -----------------------------------------------------------------------------
