## Process this file with automake to produce Makefile.in.
#
# -----------------------------------------------------------------------------
# $Id: Makefile.am,v 1.1 2003/05/10 18:32:06 raif Exp $
#
# Copyright (C) 2003 Free Software Foundation, Inc.
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
# $Revision: 1.1 $
#

JAVAX_SECURITY_LIBVERSION="1:0"

# Variables -------------------------------------------------------------------
AM_GCJFLAGS=@AM_GCJFLAGS@
JAVAC_CMD=$(GCJ) $(AM_GCJFLAGS) $(GCJFLAGS) -C

main_jar = javax-security.jar

BUILT_SOURCES = $(main_jar)
data_DATA = $(main_jar)
EXTRA_DIST =

# Libraries and executables to compile ----------------------------------------
lib_LTLIBRARIES = lib-javax-security.la

# javax.security library config -----------------------------------------------
lib_javax_security_la_SOURCES = $(main_sources)
lib_javax_security_la_LIBADD =
lib_javax_security_la_LDFLAGS = -version-info $(JAVAX_SECURITY_LIBVERSION)

# library source files --------------------------------------------------------
main_sources = \
 javax/security/auth/callback/Callback.java \
 javax/security/auth/callback/CallbackHandler.java \
 javax/security/auth/callback/ChoiceCallback.java \
 javax/security/auth/callback/ConfirmationCallback.java \
 javax/security/auth/callback/LanguageCallback.java \
 javax/security/auth/callback/NameCallback.java \
 javax/security/auth/callback/PasswordCallback.java \
 javax/security/auth/callback/TextInputCallback.java \
 javax/security/auth/callback/TextOutputCallback.java \
 javax/security/auth/callback/UnsupportedCallbackException.java \
 \
 javax/security/sasl/AuthenticationException.java \
 javax/security/sasl/AuthorizeCallback.java \
 javax/security/sasl/RealmCallback.java \
 javax/security/sasl/RealmChoiceCallback.java \
 javax/security/sasl/SaslClientFactory.java \
 javax/security/sasl/SaslClient.java \
 javax/security/sasl/SaslException.java \
 javax/security/sasl/Sasl.java \
 javax/security/sasl/SaslServerFactory.java \
 javax/security/sasl/SaslServer.java

# .class files ----------------------------------------------------------------
main_classes = $(main_sources:.java=.class)

# Extra targets ---------------------------------------------------------------
SUFFIXES = .java .lo .o .obj .class .jar

%.class: %.java
	$(JAVAC_CMD) $<

$(main_jar): $(main_classes)
	@ jar cf $@ -C . javax/security/auth/callback/*.class javax/security/sasl/*.class

clean-local:
	find . -name '*.class' -exec rm -f '{}' ';'

MOSTLYCLEANFILES = $(main_jar) $(main_classes)

# -----------------------------------------------------------------------------
