## Process this file with automake to produce Makefile.in.
#
# -----------------------------------------------------------------------------
# $Id: Makefile.am,v 1.38 2003/12/25 02:57:05 uid66198 Exp $
#
# Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.
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
# $Revision: 1.38 $
#

# Variables -------------------------------------------------------------------
AM_GCJFLAGS=@AM_GCJFLAGS@
JAVAC_CMD=$(GCJ) $(AM_GCJFLAGS) $(GCJFLAGS) -C

main_jar = $(PACKAGE).jar

BUILT_SOURCES = $(main_jar)
data_DATA = $(main_jar)
EXTRA_DIST =

# Libraries and executables to compile ----------------------------------------
bin_PROGRAMS = nessieCipherTVEmitter nessieHashTVEmitter nistKat nistMCT cipherSpeed hashSpeed ent
if FOUND_SASL_JAR
bin_PROGRAMS += sasls saslc
endif # FOUND_SASL_JAR
check_PROGRAMS = mauveTest
lib_LTLIBRARIES = lib-gnu-crypto.la

# GNU Crypto library config ---------------------------------------------------
lib_gnu_crypto_la_SOURCES = $(main_sources)
if FOUND_JCE_JAR
if FOUND_SASL_JAR
lib_gnu_crypto_la_LIBADD = -l-javax-crypto -l-javax-security
lib_gnu_crypto_la_LDFLAGS = -L../jce -L../security -version-info $(LIBVERSION)
else
lib_gnu_crypto_la_LIBADD = -l-javax-security
lib_gnu_crypto_la_LDFLAGS = -L../security -version-info $(LIBVERSION)
endif # FOUND_SASL_JAR
else
if FOUND_SASL_JAR
lib_gnu_crypto_la_LIBADD = -l-javax-security
lib_gnu_crypto_la_LDFLAGS = -L../security -version-info $(LIBVERSION)
else
lib_gnu_crypto_la_LIBADD =
lib_gnu_crypto_la_LDFLAGS = -version-info $(LIBVERSION)
endif # FOUND_SASL_JAR
endif # FOUND_JCE_JAR

# NessieCipherTVEmitter executable --------------------------------------------
nessieCipherTVEmitter_SOURCES = gnu/crypto/tool/NessieCipherTVEmitter.java
nessieCipherTVEmitter_LDADD   = -l-$(PACKAGE)
nessieCipherTVEmitter_LDFLAGS = --main=gnu.crypto.tool.NessieCipherTVEmitter

# NessieHashTVEmitter executable ----------------------------------------------
nessieHashTVEmitter_SOURCES = gnu/crypto/tool/NessieHashTVEmitter.java
nessieHashTVEmitter_LDADD   = -l-$(PACKAGE)
nessieHashTVEmitter_LDFLAGS = --main=gnu.crypto.tool.NessieHashTVEmitter

# CipherSpeed executable ------------------------------------------------------
cipherSpeed_SOURCES = gnu/crypto/tool/CipherSpeed.java
cipherSpeed_LDADD   = -l-$(PACKAGE)
cipherSpeed_LDFLAGS = --main=gnu.crypto.tool.CipherSpeed

# HashSpeed executable --------------------------------------------------------
hashSpeed_SOURCES = gnu/crypto/tool/HashSpeed.java
hashSpeed_LDADD   = -l-$(PACKAGE)
hashSpeed_LDFLAGS = --main=gnu.crypto.tool.HashSpeed

# NistKat executable ----------------------------------------------------------
nistKat_SOURCES = gnu/crypto/tool/NistKat.java
nistKat_LDADD   = -l-$(PACKAGE)
nistKat_LDFLAGS = --main=gnu.crypto.tool.NistKat

# NistMCT executable ----------------------------------------------------------
nistMCT_SOURCES = gnu/crypto/tool/NistMCT.java
nistMCT_LDADD   = -l-$(PACKAGE)
nistMCT_LDFLAGS = --main=gnu.crypto.tool.NistMCT

# Ent executable --------------------------------------------------------------
ent_SOURCES = gnu/crypto/tool/Ent.java
ent_LDADD   = -l-$(PACKAGE)
ent_LDFLAGS = --main=gnu.crypto.tool.Ent

if FOUND_SASL_JAR

# SaslS executable ------------------------------------------------------------
sasls_SOURCES = gnu/crypto/tool/SaslS.java
sasls_LDADD   = -l-$(PACKAGE)
sasls_LDFLAGS = --main=gnu.crypto.tool.SaslS

# SaslC executable ------------------------------------------------------------
saslc_SOURCES = gnu/crypto/tool/SaslC.java
saslc_LDADD   = -l-$(PACKAGE)
saslc_LDFLAGS = --main=gnu.crypto.tool.SaslC

endif # FOUND_SASL_JAR

# mauve tests executable -------------------------------------------------------
mauveTest_SOURCES = $(mauve_sources)
mauveTest_LDADD   = -l-$(PACKAGE)
mauveTest_LDFLAGS = --main=gnu.testlet.SimpleTestHarness

# library source files --------------------------------------------------------
# JCE adapter and test classes; defined iff configured with-jce-jar
if FOUND_JCE_JAR
jce_sources = \
 gnu/crypto/jce/PBKDF2SecretKeyFactory.java \
 \
 gnu/crypto/jce/cipher/AESSpi.java \
 gnu/crypto/jce/cipher/ARCFourSpi.java \
 gnu/crypto/jce/cipher/AnubisSpi.java \
 gnu/crypto/jce/cipher/BlowfishSpi.java \
 gnu/crypto/jce/cipher/Cast5Spi.java \
 gnu/crypto/jce/cipher/CipherAdapter.java \
 gnu/crypto/jce/cipher/DESSpi.java \
 gnu/crypto/jce/cipher/KhazadSpi.java \
 gnu/crypto/jce/cipher/NullCipherSpi.java \
 gnu/crypto/jce/cipher/PBES2.java \
 gnu/crypto/jce/cipher/RijndaelSpi.java \
 gnu/crypto/jce/cipher/SerpentSpi.java \
 gnu/crypto/jce/cipher/SquareSpi.java \
 gnu/crypto/jce/cipher/TripleDESSpi.java \
 gnu/crypto/jce/cipher/TwofishSpi.java \
 \
 gnu/crypto/jce/mac/HMacHavalSpi.java \
 gnu/crypto/jce/mac/HMacMD2Spi.java \
 gnu/crypto/jce/mac/HMacMD4Spi.java \
 gnu/crypto/jce/mac/HMacMD5Spi.java \
 gnu/crypto/jce/mac/HMacRipeMD128Spi.java \
 gnu/crypto/jce/mac/HMacRipeMD160Spi.java \
 gnu/crypto/jce/mac/HMacSHA160Spi.java \
 gnu/crypto/jce/mac/HMacSHA256Spi.java \
 gnu/crypto/jce/mac/HMacSHA384Spi.java \
 gnu/crypto/jce/mac/HMacSHA512Spi.java \
 gnu/crypto/jce/mac/HMacTigerSpi.java \
 gnu/crypto/jce/mac/HMacWhirlpoolSpi.java \
 gnu/crypto/jce/mac/MacAdapter.java \
 gnu/crypto/jce/mac/TMMH16Spi.java \
 gnu/crypto/jce/mac/UHash32Spi.java \
 gnu/crypto/jce/mac/UMac32Spi.java \
 \
 gnu/crypto/jce/params/BlockCipherParameters.java \
 gnu/crypto/jce/params/DEREncodingException.java \
 gnu/crypto/jce/params/DERReader.java \
 gnu/crypto/jce/params/DERWriter.java \
 \
 gnu/crypto/jce/spec/BlockCipherParameterSpec.java \
 gnu/crypto/jce/spec/TMMHParameterSpec.java \
 gnu/crypto/jce/spec/UMac32ParameterSpec.java

jce_mauve_sources = \
 gnu/testlet/gnu/crypto/jce/TestOfCipher.java \
 gnu/testlet/gnu/crypto/jce/TestOfMac.java
else # no JCE framework available or needed
jce_sources =
jce_mauve_sources =
endif # FOUND_JCE_JAR

if FOUND_SASL_JAR
sasl_sources = \
 gnu/crypto/sasl/AuthInfo.java \
 gnu/crypto/sasl/AuthInfoProviderFactory.java \
 gnu/crypto/sasl/ClientFactory.java \
 gnu/crypto/sasl/ClientMechanism.java \
 gnu/crypto/sasl/ConfidentialityException.java \
 gnu/crypto/sasl/IAuthInfoProvider.java \
 gnu/crypto/sasl/IAuthInfoProviderFactory.java \
 gnu/crypto/sasl/IllegalMechanismStateException.java \
 gnu/crypto/sasl/InputBuffer.java \
 gnu/crypto/sasl/IntegrityException.java \
 gnu/crypto/sasl/NoSuchMechanismException.java \
 gnu/crypto/sasl/NoSuchUserException.java \
 gnu/crypto/sasl/OutputBuffer.java \
 gnu/crypto/sasl/SaslEncodingException.java \
 gnu/crypto/sasl/SaslInputStream.java \
 gnu/crypto/sasl/SaslOutputStream.java \
 gnu/crypto/sasl/SaslUtil.java \
 gnu/crypto/sasl/ServerFactory.java \
 gnu/crypto/sasl/ServerMechanism.java \
 gnu/crypto/sasl/UserAlreadyExistsException.java \
 \
 gnu/crypto/sasl/anonymous/AnonymousClient.java \
 gnu/crypto/sasl/anonymous/AnonymousServer.java \
 gnu/crypto/sasl/anonymous/AnonymousUtil.java \
 \
 gnu/crypto/sasl/crammd5/CramMD5AuthInfoProvider.java \
 gnu/crypto/sasl/crammd5/CramMD5Client.java \
 gnu/crypto/sasl/crammd5/CramMD5Registry.java \
 gnu/crypto/sasl/crammd5/CramMD5Server.java \
 gnu/crypto/sasl/crammd5/CramMD5Util.java \
 gnu/crypto/sasl/crammd5/PasswordFile.java \
 \
 gnu/crypto/sasl/plain/PasswordFile.java \
 gnu/crypto/sasl/plain/PlainAuthInfoProvider.java \
 gnu/crypto/sasl/plain/PlainClient.java \
 gnu/crypto/sasl/plain/PlainRegistry.java \
 gnu/crypto/sasl/plain/PlainServer.java \
 \
 gnu/crypto/sasl/srp/CALG.java \
 gnu/crypto/sasl/srp/ClientStore.java \
 gnu/crypto/sasl/srp/IALG.java \
 gnu/crypto/sasl/srp/KDF.java \
 gnu/crypto/sasl/srp/PasswordFile.java \
 gnu/crypto/sasl/srp/SecurityContext.java \
 gnu/crypto/sasl/srp/ServerStore.java \
 gnu/crypto/sasl/srp/SRP.java \
 gnu/crypto/sasl/srp/SRPAuthInfoProvider.java \
 gnu/crypto/sasl/srp/SRPClient.java \
 gnu/crypto/sasl/srp/SRPRegistry.java \
 gnu/crypto/sasl/srp/SRPServer.java \
 gnu/crypto/sasl/srp/StoreEntry.java \
 \
 gnu/crypto/tool/SaslConnection.java \
 gnu/crypto/tool/SimpleCallbackHandler.java

sasl_mauve_sources = \
 gnu/testlet/gnu/crypto/sasl/TestOfClientFactory.java \
 gnu/testlet/gnu/crypto/sasl/TestOfServerFactory.java \
 \
 gnu/testlet/gnu/crypto/sasl/srp/TestOfSRPAuthInfoProvider.java \
 gnu/testlet/gnu/crypto/sasl/srp/TestOfSRPPasswordFile.java \
 gnu/testlet/gnu/crypto/sasl/srp/TestOfSRPPrimitives.java
else # no javax.security.sasl found or needed
sasl_sources =
sasl_mauve_sources =
endif # FOUND_SASL_JAR

main_sources = \
 gnu/crypto/Properties.java \
 gnu/crypto/Registry.java \
 \
 gnu/crypto/assembly/Assembly.java \
 gnu/crypto/assembly/Cascade.java \
 gnu/crypto/assembly/CascadeStage.java \
 gnu/crypto/assembly/CascadeTransformer.java \
 gnu/crypto/assembly/DeflateTransformer.java \
 gnu/crypto/assembly/Direction.java \
 gnu/crypto/assembly/LoopbackTransformer.java \
 gnu/crypto/assembly/ModeStage.java \
 gnu/crypto/assembly/Operation.java \
 gnu/crypto/assembly/PaddingTransformer.java \
 gnu/crypto/assembly/Stage.java \
 gnu/crypto/assembly/Transformer.java \
 gnu/crypto/assembly/TransformerException.java \
 \
 gnu/crypto/cipher/Anubis.java \
 gnu/crypto/cipher/BaseCipher.java \
 gnu/crypto/cipher/Blowfish.java \
 gnu/crypto/cipher/Cast5.java \
 gnu/crypto/cipher/CipherFactory.java \
 gnu/crypto/cipher/DES.java \
 gnu/crypto/cipher/IBlockCipher.java \
 gnu/crypto/cipher/IBlockCipherSpi.java \
 gnu/crypto/cipher/Khazad.java \
 gnu/crypto/cipher/NullCipher.java \
 gnu/crypto/cipher/Rijndael.java \
 gnu/crypto/cipher/Serpent.java \
 gnu/crypto/cipher/Square.java \
 gnu/crypto/cipher/TripleDES.java \
 gnu/crypto/cipher/Twofish.java \
 gnu/crypto/cipher/WeakKeyException.java \
 \
 gnu/crypto/exp/ust/UST.java \
 \
 gnu/crypto/hash/BaseHash.java \
 gnu/crypto/hash/HashFactory.java \
 gnu/crypto/hash/Haval.java \
 gnu/crypto/hash/IMessageDigest.java \
 gnu/crypto/hash/MD2.java \
 gnu/crypto/hash/MD4.java \
 gnu/crypto/hash/MD5.java \
 gnu/crypto/hash/RipeMD128.java \
 gnu/crypto/hash/RipeMD160.java \
 gnu/crypto/hash/Sha160.java \
 gnu/crypto/hash/Sha256.java \
 gnu/crypto/hash/Sha384.java \
 gnu/crypto/hash/Sha512.java \
 gnu/crypto/hash/Tiger.java \
 gnu/crypto/hash/Whirlpool.java \
 \
 gnu/crypto/jce/GnuCrypto.java \
 \
 gnu/crypto/jce/hash/HavalSpi.java \
 gnu/crypto/jce/hash/MD2Spi.java \
 gnu/crypto/jce/hash/MD4Spi.java \
 gnu/crypto/jce/hash/MD5Spi.java \
 gnu/crypto/jce/hash/MessageDigestAdapter.java \
 gnu/crypto/jce/hash/RipeMD128Spi.java \
 gnu/crypto/jce/hash/RipeMD160Spi.java \
 gnu/crypto/jce/hash/Sha160Spi.java \
 gnu/crypto/jce/hash/Sha256Spi.java \
 gnu/crypto/jce/hash/Sha384Spi.java \
 gnu/crypto/jce/hash/Sha512Spi.java \
 gnu/crypto/jce/hash/TigerSpi.java \
 gnu/crypto/jce/hash/WhirlpoolSpi.java \
 \
 gnu/crypto/jce/keyring/GnuKeyring.java \
 \
 gnu/crypto/jce/prng/ARCFourRandomSpi.java \
 gnu/crypto/jce/prng/HavalRandomSpi.java \
 gnu/crypto/jce/prng/ICMRandomSpi.java \
 gnu/crypto/jce/prng/MD2RandomSpi.java \
 gnu/crypto/jce/prng/MD4RandomSpi.java \
 gnu/crypto/jce/prng/MD5RandomSpi.java \
 gnu/crypto/jce/prng/RipeMD128RandomSpi.java \
 gnu/crypto/jce/prng/RipeMD160RandomSpi.java \
 gnu/crypto/jce/prng/SecureRandomAdapter.java \
 gnu/crypto/jce/prng/Sha160RandomSpi.java \
 gnu/crypto/jce/prng/Sha256RandomSpi.java \
 gnu/crypto/jce/prng/Sha384RandomSpi.java \
 gnu/crypto/jce/prng/Sha512RandomSpi.java \
 gnu/crypto/jce/prng/TigerRandomSpi.java \
 gnu/crypto/jce/prng/UMacRandomSpi.java \
 gnu/crypto/jce/prng/WhirlpoolRandomSpi.java \
 \
 gnu/crypto/jce/sig/DSSKeyPairGeneratorSpi.java \
 gnu/crypto/jce/sig/DSSRawSignatureSpi.java \
 gnu/crypto/jce/sig/KeyPairGeneratorAdapter.java \
 gnu/crypto/jce/sig/RSAKeyPairGeneratorSpi.java \
 gnu/crypto/jce/sig/RSAPSSRawSignatureSpi.java \
 gnu/crypto/jce/sig/SignatureAdapter.java \
 \
 gnu/crypto/key/BaseKeyAgreementParty.java \
 gnu/crypto/key/GnuSecretKey.java \
 gnu/crypto/key/IKeyAgreementParty.java \
 gnu/crypto/key/IKeyPairCodec.java \
 gnu/crypto/key/IKeyPairGenerator.java \
 gnu/crypto/key/IncomingMessage.java \
 gnu/crypto/key/KeyAgreementException.java \
 gnu/crypto/key/KeyAgreementFactory.java \
 gnu/crypto/key/KeyPairCodecFactory.java \
 gnu/crypto/key/KeyPairGeneratorFactory.java \
 gnu/crypto/key/OutgoingMessage.java \
 \
 gnu/crypto/key/dh/DHKeyPairRawCodec.java \
 gnu/crypto/key/dh/DiffieHellmanKeyAgreement.java \
 gnu/crypto/key/dh/DiffieHellmanReceiver.java \
 gnu/crypto/key/dh/DiffieHellmanSender.java \
 gnu/crypto/key/dh/ElGamalKeyAgreement.java \
 gnu/crypto/key/dh/ElGamalReceiver.java \
 gnu/crypto/key/dh/ElGamalSender.java \
 gnu/crypto/key/dh/GnuDHKey.java \
 gnu/crypto/key/dh/GnuDHKeyPairGenerator.java \
 gnu/crypto/key/dh/GnuDHPrivateKey.java \
 gnu/crypto/key/dh/GnuDHPublicKey.java \
 gnu/crypto/key/dh/RFC2631.java \
 \
 gnu/crypto/key/dss/DSSKey.java \
 gnu/crypto/key/dss/DSSKeyPairGenerator.java \
 gnu/crypto/key/dss/DSSKeyPairRawCodec.java \
 gnu/crypto/key/dss/DSSPrivateKey.java \
 gnu/crypto/key/dss/DSSPublicKey.java \
 gnu/crypto/key/dss/FIPS186.java \
 \
 gnu/crypto/key/rsa/GnuRSAKey.java \
 gnu/crypto/key/rsa/GnuRSAPrivateKey.java \
 gnu/crypto/key/rsa/GnuRSAPublicKey.java \
 gnu/crypto/key/rsa/RSAKeyPairGenerator.java \
 gnu/crypto/key/rsa/RSAKeyPairRawCodec.java \
 \
 gnu/crypto/key/srp6/SRP6Host.java \
 gnu/crypto/key/srp6/SRP6KeyAgreement.java \
 gnu/crypto/key/srp6/SRP6SaslClient.java \
 gnu/crypto/key/srp6/SRP6SaslServer.java \
 gnu/crypto/key/srp6/SRP6TLSClient.java \
 gnu/crypto/key/srp6/SRP6TLSServer.java \
 gnu/crypto/key/srp6/SRP6User.java \
 gnu/crypto/key/srp6/SRPAlgorithm.java \
 gnu/crypto/key/srp6/SRPKey.java \
 gnu/crypto/key/srp6/SRPKeyPairGenerator.java \
 gnu/crypto/key/srp6/SRPKeyPairRawCodec.java \
 gnu/crypto/key/srp6/SRPPrivateKey.java \
 gnu/crypto/key/srp6/SRPPublicKey.java \
 \
 gnu/crypto/keyring/AuthenticatedEntry.java \
 gnu/crypto/keyring/BaseKeyring.java \
 gnu/crypto/keyring/BinaryDataEntry.java \
 gnu/crypto/keyring/CertPathEntry.java \
 gnu/crypto/keyring/CertificateEntry.java \
 gnu/crypto/keyring/CompressedEntry.java \
 gnu/crypto/keyring/EncryptedEntry.java \
 gnu/crypto/keyring/Entry.java \
 gnu/crypto/keyring/EnvelopeEntry.java \
 gnu/crypto/keyring/GnuPrivateKeyring.java \
 gnu/crypto/keyring/GnuPublicKeyring.java \
 gnu/crypto/keyring/IKeyring.java \
 gnu/crypto/keyring/IPrivateKeyring.java \
 gnu/crypto/keyring/IPublicKeyring.java \
 gnu/crypto/keyring/MalformedKeyringException.java \
 gnu/crypto/keyring/MaskableEnvelopeEntry.java \
 gnu/crypto/keyring/MeteredInputStream.java \
 gnu/crypto/keyring/PasswordAuthenticatedEntry.java \
 gnu/crypto/keyring/PasswordEncryptedEntry.java \
 gnu/crypto/keyring/PasswordProtectedEntry.java \
 gnu/crypto/keyring/PrimitiveEntry.java \
 gnu/crypto/keyring/PrivateKeyEntry.java \
 gnu/crypto/keyring/Properties.java \
 gnu/crypto/keyring/PublicKeyEntry.java \
 \
 gnu/crypto/mac/BaseMac.java \
 gnu/crypto/mac/HMac.java \
 gnu/crypto/mac/HMacFactory.java \
 gnu/crypto/mac/IMac.java \
 gnu/crypto/mac/MacFactory.java \
 gnu/crypto/mac/MacInputStream.java \
 gnu/crypto/mac/MacOutputStream.java \
 gnu/crypto/mac/TMMH16.java \
 gnu/crypto/mac/UHash32.java \
 gnu/crypto/mac/UMac32.java \
 \
 gnu/crypto/mode/BaseMode.java \
 gnu/crypto/mode/CBC.java \
 gnu/crypto/mode/CFB.java \
 gnu/crypto/mode/CTR.java \
 gnu/crypto/mode/ECB.java \
 gnu/crypto/mode/ICM.java \
 gnu/crypto/mode/IMode.java \
 gnu/crypto/mode/ModeFactory.java \
 gnu/crypto/mode/OFB.java \
 \
 gnu/crypto/pad/BasePad.java \
 gnu/crypto/pad/IPad.java \
 gnu/crypto/pad/PadFactory.java \
 gnu/crypto/pad/PKCS1_V1_5.java \
 gnu/crypto/pad/PKCS7.java \
 gnu/crypto/pad/TBC.java \
 gnu/crypto/pad/WrongPaddingException.java \
 \
 gnu/crypto/prng/ARCFour.java \
 gnu/crypto/prng/BasePRNG.java \
 gnu/crypto/prng/ICMGenerator.java \
 gnu/crypto/prng/IPBE.java \
 gnu/crypto/prng/IRandom.java \
 gnu/crypto/prng/LimitReachedException.java \
 gnu/crypto/prng/MDGenerator.java \
 gnu/crypto/prng/PBKDF2.java \
 gnu/crypto/prng/PRNGFactory.java \
 gnu/crypto/prng/UMacGenerator.java \
 \
 gnu/crypto/sig/BaseSignature.java \
 gnu/crypto/sig/ISignature.java \
 gnu/crypto/sig/ISignatureCodec.java \
 gnu/crypto/sig/SignatureFactory.java \
 \
 gnu/crypto/sig/dss/DSSSignature.java \
 gnu/crypto/sig/dss/DSSSignatureRawCodec.java \
 \
 gnu/crypto/sig/rsa/EME_PKCS1_V1_5.java \
 gnu/crypto/sig/rsa/EMSA_PKCS1_V1_5.java \
 gnu/crypto/sig/rsa/EMSA_PSS.java \
 gnu/crypto/sig/rsa/RSA.java \
 gnu/crypto/sig/rsa/RSAPKCS1V1_5Signature.java \
 gnu/crypto/sig/rsa/RSAPSSSignature.java \
 gnu/crypto/sig/rsa/RSAPSSSignatureRawCodec.java \
 \
 gnu/crypto/util/Base64.java \
 gnu/crypto/util/Prime.java \
 gnu/crypto/util/PRNG.java \
 gnu/crypto/util/Util.java \
 \
 $(jce_sources) \
 $(sasl_sources)

mauve_sources = \
 gnu/testlet/config.java \
 gnu/testlet/ResourceNotFoundException.java \
 gnu/testlet/SimpleTestHarness.java \
 gnu/testlet/TestHarness.java \
 gnu/testlet/Testlet.java \
 \
 gnu/testlet/gnu/crypto/assembly/TestOfAssembly.java \
 gnu/testlet/gnu/crypto/assembly/TestOfCascade.java \
 \
 gnu/testlet/gnu/crypto/cipher/BaseCipherTestCase.java \
 gnu/testlet/gnu/crypto/cipher/TestOfAnubis.java \
 gnu/testlet/gnu/crypto/cipher/TestOfBlowfish.java \
 gnu/testlet/gnu/crypto/cipher/TestOfCast5.java \
 gnu/testlet/gnu/crypto/cipher/TestOfCipherFactory.java \
 gnu/testlet/gnu/crypto/cipher/TestOfDES.java \
 gnu/testlet/gnu/crypto/cipher/TestOfKhazad.java \
 gnu/testlet/gnu/crypto/cipher/TestOfNistVectors.java \
 gnu/testlet/gnu/crypto/cipher/TestOfNullCipher.java \
 gnu/testlet/gnu/crypto/cipher/TestOfRijndael.java \
 gnu/testlet/gnu/crypto/cipher/TestOfSerpent.java \
 gnu/testlet/gnu/crypto/cipher/TestOfSquare.java \
 gnu/testlet/gnu/crypto/cipher/TestOfTripleDES.java \
 gnu/testlet/gnu/crypto/cipher/TestOfTwofish.java \
 \
 gnu/testlet/gnu/crypto/exp/TestOfUST.java \
 \
 gnu/testlet/gnu/crypto/hash/TestOfHashFactory.java \
 gnu/testlet/gnu/crypto/hash/TestOfHaval.java \
 gnu/testlet/gnu/crypto/hash/TestOfMD2.java \
 gnu/testlet/gnu/crypto/hash/TestOfMD4.java \
 gnu/testlet/gnu/crypto/hash/TestOfMD5.java \
 gnu/testlet/gnu/crypto/hash/TestOfRipeMD128.java \
 gnu/testlet/gnu/crypto/hash/TestOfRipeMD160.java \
 gnu/testlet/gnu/crypto/hash/TestOfTiger.java \
 gnu/testlet/gnu/crypto/hash/TestOfSha160.java \
 gnu/testlet/gnu/crypto/hash/TestOfSha256.java \
 gnu/testlet/gnu/crypto/hash/TestOfSha384.java \
 gnu/testlet/gnu/crypto/hash/TestOfSha512.java \
 gnu/testlet/gnu/crypto/hash/TestOfWhirlpool.java \
 \
 gnu/testlet/gnu/crypto/jce/TestOfKeyPairGenerator.java \
 gnu/testlet/gnu/crypto/jce/TestOfMessageDigest.java \
 gnu/testlet/gnu/crypto/jce/TestOfProvider.java \
 gnu/testlet/gnu/crypto/jce/TestOfSignature.java \
 \
 gnu/testlet/gnu/crypto/key/TestOfKeyPairGeneratorFactory.java \
 \
 gnu/testlet/gnu/crypto/key/dh/TestOfDHCodec.java \
 gnu/testlet/gnu/crypto/key/dh/TestOfDHKeyAgreements.java \
 gnu/testlet/gnu/crypto/key/dh/TestOfDHKeyGeneration.java \
 \
 gnu/testlet/gnu/crypto/key/dss/TestOfDSSCodec.java \
 gnu/testlet/gnu/crypto/key/dss/TestOfDSSKeyGeneration.java \
 \
 gnu/testlet/gnu/crypto/key/rsa/TestOfRSACodec.java \
 gnu/testlet/gnu/crypto/key/rsa/TestOfRSAKeyGeneration.java \
 \
 gnu/testlet/gnu/crypto/key/srp6/TestOfSRP6KeyAgreements.java \
 gnu/testlet/gnu/crypto/key/srp6/TestOfSRPCodec.java \
 gnu/testlet/gnu/crypto/key/srp6/TestOfSRPKeyGeneration.java \
 \
 gnu/testlet/gnu/crypto/keyring/TestOfPrivateKeyring.java \
 gnu/testlet/gnu/crypto/keyring/TestOfPublicKeyring.java \
 \
 gnu/testlet/gnu/crypto/mac/TestOfHMac.java \
 gnu/testlet/gnu/crypto/mac/TestOfHMacFactory.java \
 gnu/testlet/gnu/crypto/mac/TestOfHMacMD5.java \
 gnu/testlet/gnu/crypto/mac/TestOfHMacSha1.java \
 gnu/testlet/gnu/crypto/mac/TestOfMacFactory.java \
 gnu/testlet/gnu/crypto/mac/TestOfTMMH16.java \
 \
 gnu/testlet/gnu/crypto/mode/TestOfCBC.java \
 gnu/testlet/gnu/crypto/mode/TestOfCFB.java \
 gnu/testlet/gnu/crypto/mode/TestOfECB.java \
 gnu/testlet/gnu/crypto/mode/TestOfModeFactory.java \
 gnu/testlet/gnu/crypto/mode/TestOfOFB.java \
 \
 gnu/testlet/gnu/crypto/pad/TestOfPadFactory.java \
 gnu/testlet/gnu/crypto/pad/TestOfPKCS7.java \
 gnu/testlet/gnu/crypto/pad/TestOfTBC.java \
 \
 gnu/testlet/gnu/crypto/prng/TestOfARCFour.java \
 gnu/testlet/gnu/crypto/prng/TestOfICMGenerator.java \
 gnu/testlet/gnu/crypto/prng/TestOfPBKDF2.java \
 gnu/testlet/gnu/crypto/prng/TestOfPRNGFactory.java \
 \
 gnu/testlet/gnu/crypto/sig/TestOfSignatureFactory.java \
 \
 gnu/testlet/gnu/crypto/sig/dss/TestOfDSSSignature.java \
 gnu/testlet/gnu/crypto/sig/dss/TestOfDSSSignatureCodec.java \
 \
 gnu/testlet/gnu/crypto/sig/rsa/TestOfRSAPKCS1V1_5Signature.java \
 gnu/testlet/gnu/crypto/sig/rsa/TestOfRSAPSSSignature.java \
 gnu/testlet/gnu/crypto/sig/rsa/TestOfRSASignatureCodec.java \
 \
 $(jce_mauve_sources) \
 $(sasl_mauve_sources)

# .class files ----------------------------------------------------------------
main_classes = $(main_sources:.java=.class)
mauve_classes = $(mauve_sources:.java=.class)

gnu/testlet/config.java: gnu/testlet/config.java.in
	cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@

# -----------------------------------------------------------------------------

check-local: $(check_PROGRAMS) mauve-$(PACKAGE) test_classes
	cat test_classes | ./mauveTest

test_classes: FORCE
	$(SHELL) ./choose-classes . $(PACKAGE)

FORCE:

# Extra targets ---------------------------------------------------------------
SUFFIXES = .java .lo .o .obj .class .jar

%.class: %.java
	$(JAVAC_CMD) $<

$(main_jar): $(main_classes)
if FOUND_JCE_JAR
	@ jar cf $@ -C . gnu/crypto/*.class gnu/crypto/assembly/*.class \
		gnu/crypto/cipher/*.class gnu/crypto/exp/ust/*.class \
		gnu/crypto/hash/*.class gnu/crypto/jce/*.class \
		gnu/crypto/jce/hash/*.class gnu/crypto/jce/keyring/*.class \
		gnu/crypto/jce/prng/*.class gnu/crypto/jce/sig/*.class \
		gnu/crypto/key/*.class gnu/crypto/key/dh/*.class \
		gnu/crypto/key/dss/*.class gnu/crypto/key/rsa/*.class \
		gnu/crypto/key/srp6/*.class gnu/crypto/keyring/*.class \
		gnu/crypto/mac/*.class gnu/crypto/mode/*.class \
		gnu/crypto/pad/*.class gnu/crypto/prng/*.class \
		gnu/crypto/sasl/*.class gnu/crypto/sasl/anonymous/*.class \
		gnu/crypto/sasl/crammd5/*.class gnu/crypto/sasl/plain/*.class \
		gnu/crypto/sasl/srp/*.class gnu/crypto/sig/*.class \
		gnu/crypto/sig/dss/*.class gnu/crypto/sig/rsa/*.class \
		gnu/crypto/util/*.class \
		gnu/crypto/jce/cipher/*.class gnu/crypto/jce/mac/*.class \
		gnu/crypto/jce/params/*.class gnu/crypto/jce/spec/*.class
else
	@ jar cf $@ -C . gnu/crypto/*.class gnu/crypto/assembly/*.class \
		gnu/crypto/cipher/*.class gnu/crypto/exp/ust/*.class \
		gnu/crypto/hash/*.class gnu/crypto/jce/*.class \
		gnu/crypto/jce/hash/*.class gnu/crypto/jce/keyring/*.class \
		gnu/crypto/jce/prng/*.class gnu/crypto/jce/sig/*.class \
		gnu/crypto/key/*.class gnu/crypto/key/dh/*.class \
		gnu/crypto/key/dss/*.class gnu/crypto/key/rsa/*.class \
		gnu/crypto/key/srp6/*.class gnu/crypto/keyring/*.class \
		gnu/crypto/mac/*.class gnu/crypto/mode/*.class \
		gnu/crypto/pad/*.class gnu/crypto/prng/*.class \
		gnu/crypto/sasl/*.class gnu/crypto/sasl/anonymous/*.class \
		gnu/crypto/sasl/crammd5/*.class gnu/crypto/sasl/plain/*.class \
		gnu/crypto/sasl/srp/*.class gnu/crypto/sig/*.class \
		gnu/crypto/sig/dss/*.class gnu/crypto/sig/rsa/*.class \
		gnu/crypto/util/*.class
endif # FOUND_JCE_JAR

MOSTLYCLEANFILES = $(main_jar) $(main_classes) $(mauve_classes) test_classes

clean-local:
	find gnu -name '*.class' -exec rm -f '{}' ';'

# -----------------------------------------------------------------------------
