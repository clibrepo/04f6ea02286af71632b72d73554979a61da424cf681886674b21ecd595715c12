## Process this file with automake to produce Makefile.in.
#
# -----------------------------------------------------------------------------
# $Id: Makefile.am,v 1.16.2.2 2004/01/24 04:30:30 rsdio Exp $
#
# Copyright (C) 2001, 2002, 2003, 2004 Free Software Foundation, Inc.
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
# $Revision: 1.16.2.2 $
#

DISTCHECK_CONFIGURE_FLAGS = --without-jce
EXTRA_DIST = \
	gcj/jce/Makefile.am gcj/jce/Makefile.in gcj/Makefile.in \
	gcj/aclocal.m4 gcj/autogen.sh gcj/config.guess gcj/config.sub \
	gcj/configure gcj/configure.ac gcj/depcomp gcj/init.sh gcj/install-sh \
	gcj/libtool gcj/libtool.m4 gcj/ltcf-c.sh gcj/ltcf-cxx.sh \
	gcj/ltcf-gcj.sh gcj/ltconfig gcj/ltmain.sh gcj/missing \
	gcj/mkinstalldirs gcj/security/Makefile.am gcj/security/Makefile.in \
	gcj/source/gnu/crypto/cipher/Blowfish.java \
	gcj/source/gnu/crypto/cipher/Khazad.java \
	gcj/source/gnu/crypto/cipher/Rijndael.java \
	gcj/source/gnu/crypto/cipher/Serpent.java.in \
	gcj/source/gnu/crypto/cipher/Square.java \
	gcj/source/gnu/crypto/hash/RipeMD128.java \
	gcj/source/gnu/crypto/hash/RipeMD160.java \
	gcj/source/gnu/crypto/hash/Sha160.java \
	gcj/source/gnu/crypto/hash/Whirlpool.java gcj/source/Makefile.am \
	gcj/source/Makefile.in gcj/README autogen.sh build.xml init.sh \
	etc/gnu-crypto-2.0.0-1-rh.spec etc/gnu-crypto.mf.in \
	.ant.properties gnu-crypto.m4 meta/serpent.m4

if WITH_JCE
if WITH_SASL
SUBDIRS = jce security source docs
else
SUBDIRS = jce source docs
endif # WITH_SASL
else
if WITH_SASL
SUBDIRS = security source docs
else
SUBDIRS = source docs
endif # WITH_SASL
endif # WITH_JCE

# test vector generation targets ----------------------------------------------

TV_DISTDIR = $(PACKAGE)-$(VERSION)-tv

test-vectors: 
	$(MAKE) -C source test-vectors

test-vectors-dist: test-vectors
	test -d $(TV_DISTDIR) || mkdir $(TV_DISTDIR)
	cp -R tv $(TV_DISTDIR)
	tar chof - $(TV_DISTDIR) | GZIP=$(GZIP_ENV) gzip -c >$(TV_DISTDIR).tar.gz
	tar chof - $(TV_DISTDIR) | bzip2 -9 -c >$(TV_DISTDIR).tar.bz2
	rm -f $(TV_DISTDIR).zip
	zip -rq $(TV_DISTDIR).zip $(TV_DISTDIR)
	rm -rf $(TV_DISTDIR)

# tools -----------------------------------------------------------------------
speed:
	$(MAKE) -C source speed

ent:
	$(MAKE) -C source ent

# binary distribution --------------------------------------------------------

BIN_DISTDIR = $(PACKAGE)-$(VERSION)-bin

bin-dist: all javadoc
	test -d $(BIN_DISTDIR) || mkdir $(BIN_DISTDIR)
	-mkdir $(BIN_DISTDIR)/lib
	-mkdir $(BIN_DISTDIR)/docs
	cp -f source/gnu-crypto.jar $(BIN_DISTDIR)/lib
	cp -f jce/javax-crypto.jar $(BIN_DISTDIR)/lib
	cp -f security/javax-security.jar $(BIN_DISTDIR)/lib
	cp -f docs/gnu-crypto.info* $(BIN_DISTDIR)/docs
	cp -Rf api $(BIN_DISTDIR)/docs
	cp README.bin $(BIN_DISTDIR)/README
	cp AUTHORS COPYING LICENSE README.bc THANKS $(BIN_DISTDIR)
	echo "Build date: `date`" >$(BIN_DISTDIR)/BUILD
	echo "Compiler:" >>$(BIN_DISTDIR)/BUILD
	$(JAVAC) --version >>$(BIN_DISTDIR)/BUILD
	echo "Comiler options: $(JAVACFLAGS)" >>$(BIN_DISTDIR)/BUILD
	echo "Build system: `uname -a`" >>$(BIN_DISTDIR)/BUILD
	tar chof - $(BIN_DISTDIR) | GZIP=$(GZIP_ENV) gzip -c >$(BIN_DISTDIR).tar.gz
	tar chof - $(BIN_DISTDIR) | bzip2 -9 -c >$(BIN_DISTDIR).tar.bz2
	rm -f $(BIN_DISTDIR).zip
	zip -rq $(BIN_DISTDIR).zip $(BIN_DISTDIR)
	rm -rf $(BIN_DISTDIR)

dist-local: test-vectors-dist bin-dist
	sha1sum -b $(PACKAGE)-$(VERSION).tar.bz2 $(PACKAGE)-$(VERSION).tar.gz \
	  $(PACKAGE)-$(VERSION).zip $(BIN_DISTDIR).tar.bz2 $(BIN_DISTDIR).tar.gz \
	  $(BIN_DISTDIR).zip $(TV_DISTDIR).tar.bz2 $(TV_DISTDIR).tar.gz \
	  $(TV_DISTDIR).zip >$(PACKAGE)-$(VERSION).sha

# generated documentation ----------------------------------------------------

PACKAGES = \
	gnu.crypto \
	gnu.crypto.assembly \
	gnu.crypto.cipher \
	gnu.crypto.exp.ust \
	gnu.crypto.hash \
	gnu.crypto.jce \
	gnu.crypto.jce.cipher \
	gnu.crypto.jce.hash \
	gnu.crypto.jce.keyring \
	gnu.crypto.jce.mac \
	gnu.crypto.jce.params \
	gnu.crypto.jce.prng \
	gnu.crypto.jce.sig \
	gnu.crypto.jce.spec \
	gnu.crypto.key \
	gnu.crypto.key.dh \
	gnu.crypto.key.dss \
	gnu.crypto.key.rsa \
	gnu.crypto.key.srp6 \
	gnu.crypto.keyring \
	gnu.crypto.mac \
	gnu.crypto.mode \
	gnu.crypto.pad \
	gnu.crypto.prng \
	gnu.crypto.sasl \
	gnu.crypto.sasl.anonymous \
	gnu.crypto.sasl.crammd5 \
	gnu.crypto.sasl.plain \
	gnu.crypto.sasl.srp \
	gnu.crypto.sig \
	gnu.crypto.sig.dss \
	gnu.crypto.sig.rsa \
	gnu.crypto.tool \
	gnu.crypto.util \
	javax.crypto \
	javax.crypto.interfaces \
	javax.crypto.spec \
	javax.security.auth.callback \
	javax.security.sasl

javadoc:
	-mkdir api
	javadoc $(JAVADOCFLAGS) -d api -sourcepath source:jce:security -overview source/overview.html \
	-group 'Algorithms' gnu.crypto:gnu.crypto.cipher:gnu.crypto.hash:gnu.crypto.mac:gnu.crypto.mode:gnu.crypto.pad:gnu.crypto.prng \
	-group 'High-Level API' gnu.crypto.assembly \
	-group 'Key Agreements and Key Pair Generation' gnu.crypto.key* \
	-group 'Signature Schemes' gnu.crypto.sig* \
	-group 'Java Cryptography Extension (JCE) Adapters' gnu.crypto.jce* \
	-group 'Experimental Algorithms' gnu.crypto.exp* \
	-group 'Simple Authentication and Security Layer' gnu.crypto.sasl* \
	-group 'Tools' gnu.crypto.tool -group 'Utilities' gnu.crypto.util \
	-group 'Standard APIs' javax.* \
	-header 'For the latest news and information visit<BR><A HREF="http://www.gnu.org/software/gnu-crypto">The GNU Crypto project</A>' \
	-footer 'For the latest news and information visit<BR><A HREF="http://www.gnu.org/software/gnu-crypto">The GNU Crypto project</A>' \
	-bottom 'Copyright &copy; 2001, 2002, 2003, 2004 Free Software Foundation, Inc.' \
	-windowtitle 'GNU cryptographic primitives and tools' \
	-doctitle '<H1>GNU cryptographic primitives and tools<BR>API Documentation, version $(VERSION)</H1>' \
	$(PACKAGES)
