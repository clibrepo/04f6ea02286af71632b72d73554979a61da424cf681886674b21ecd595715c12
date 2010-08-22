# generated automatically by aclocal 1.7.7 -*- Autoconf -*-

# Copyright (C) 1996, 1997, 1998, 1999, 2000, 2001, 2002
# Free Software Foundation, Inc.
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

# ----------------------------------------------------------------------------
# $Id: acinclude.m4,v 1.11 2003/09/27 16:47:40 rsdio Exp $
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
# ----------------------------------------------------------------------------
#
# GNU Crypto m4 macros for auto-configuration
#
# This file is an input to aclocal which generates aclocal.m4, which in turn,
# is an input to autoconf which generates the ./configure script.
#
# $Revision: 1.11 $
#

# process --with-java configure option.
# test if a Java bytecode interpreter is available, and if yes set in
# JAVA_BIN_PATH the path to the executable, and in
# JAVA_RT_JAR   the path to the runtime jar (needed by jikes and similar).
# -----------------------------------------------------------------------------
AC_DEFUN([_GNU_CRYPTO_WHICH_JAVA],[
AC_ARG_WITH([java],
            AC_HELP_STRING([--with-java@<:@=ARG@:>@],
                           [use Java for bytecode interpretation, and optionally the path where to find it]),
            [if test "x${withval}" != x && test "x${withval}" != xyes && test "x${withval}" != xno; then
              _GNU_CRYPTO_CHECK_JAVA(${withval})
            elif test "x${withval}" != xno; then
              _GNU_CRYPTO_CHECK_JAVA
            fi],
            [_GNU_CRYPTO_CHECK_JAVA])
AM_CONDITIONAL(FOUND_JAVA, test "x${JAVA}" != x)
AC_SUBST(JAVA)
JAVA_BIN_PATH=`AS_DIRNAME([$JAVA])`
if test -r ${JAVA_BIN_PATH}/../jre/lib/rt.jar ; then
  JAVA_RT_JAR=${JAVA_BIN_PATH}/../jre/lib/rt.jar
  AC_SUBST(JAVA_RT_JAR)
fi
AC_SUBST(JAVA_BIN_PATH)
])# _GNU_CRYPTO_WHICH_JAVA


# a wrapper around AC_PATH_PROG to check for the accessibility of a Java
# bytecode interpreter.
# may be invoked without or with one argument.  when invoked with no arguments
# the executable 'java' (supposedly accessible from PATH directories) is used
# as the argument to AC_PATH_PROG.
# if the Java bytecode interpreter is found, this macro checks the version of
# that interpreter, in order to set the conditional WITH_BREAKITERATOR which
# needed to specify correct parameters to the 'javadoc' tool.  this assumes
# (a) the bytecode interpreter is the sun's one, or (b) the substitute tools
# closely mimic sun's tools behaviour.
# -----------------------------------------------------------------------------
AC_DEFUN([_GNU_CRYPTO_CHECK_JAVA],[
if test "x$1" != x; then
  if test -f "$1"; then
    JAVA="$1"
  else
    AC_PATH_PROG(JAVA, "$1")
  fi
else
  AC_PATH_PROG(JAVA, "java")
fi

if test "x$JAVA" != x; then
  AC_MSG_CHECKING(for java version)
  JAVA_VERSION=`$JAVA -version  2>&1 | head -1 | cut -d '"' -f 2`
  JAVA_VERSION_MAJOR=`echo $JAVA_VERSION | cut -d '.' -f 1`
  JAVA_VERSION_MINOR=`echo $JAVA_VERSION | cut -d '.' -f 2`
  AC_MSG_RESULT($JAVA_VERSION)

  AC_MSG_CHECKING(wether javadoc uses -breakiterator)
  if (expr "$JAVA_VERSION_MAJOR" \> 0 >/dev/null ) && (expr "$JAVA_VERSION_MINOR" \> 3 >/dev/null); then
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
  fi
fi
AM_CONDITIONAL(WITH_BREAKITERATOR, (expr "$JAVA_VERSION_MAJOR" \> 0 >/dev/null) && (expr "$JAVA_VERSION_MINOR" \> 3 >/dev/null))[]dnl
])# _GNU_CRYPTO_CHECK_JAVA

# =============================================================================

# process --with-classpath configure option.
# test if the GNU Classpath package is installed.  if no argument was specified
# with the option, this macro looks for a 'share/classpath/glibj.zip' file and
# a 'lib/classpath/libjavalang.so' in the following places, in this order:
# /usr/local/classpath, /usr/local, /usr, /opt/classpath, and /opt.  otherwise
# those two files are looked up under the designated location.
# if glibj.zip is found, GLIBJ_ZIP shall contain its path.
# -----------------------------------------------------------------------------
AC_DEFUN([_GNU_CRYPTO_WITH_CLASSPATH],[
AC_ARG_WITH([classpath],
            AC_HELP_STRING([--with-classpath],
                           [path to GNU Classpath install directory.  if unspecified, /usr/local/classpath, /usr/local, /usr, /opt/classpath, and /opt are considered, in that order]),

            [if test "x${withval}" != x && test "x${withval}" != xyes && test "x${withval}" != xno; then
              AC_MSG_CHECKING([${withval}])
              _GNU_CRYPTO_CHECK_CLASSPATH(${withval})
              if test x$GNU_CLASSPATH_INSTALL_DIR = x ; then
                AC_MSG_RESULT(no)
                AC_MSG_ERROR([cannot find designated GNU Classpath install directory])
              else
                AC_MSG_RESULT(yes)
                with_classpath=true
              fi
            elif test "x${withval}" != xno; then
              AC_MSG_NOTICE([no value supplied --with-classpath.  will look in default locations])
              _GNU_CRYPTO_FIND_GNU_CLASSPATH([/usr/local/classpath /usr/local /usr /opt/classpath /opt])
              if test x$GNU_CLASSPATH_INSTALL_DIR = x ; then
                AC_MSG_ERROR([cannot find GNU Classpath install directory: install it and/or specify its location using --with-classpath])
              fi
              with_classpath=true
            else
              with_classpath=false
            fi],
            [with_classpath=false])
GNU_CLASSPATH_INSTALL_DIR=`(cd ${GNU_CLASSPATH_INSTALL_DIR}; pwd)`
AC_SUBST(GNU_CLASSPATH_INSTALL_DIR)
if test -r ${GNU_CLASSPATH_INSTALL_DIR}/share/classpath/glibj.zip ; then
  GLIBJ_ZIP=${GNU_CLASSPATH_INSTALL_DIR}/share/classpath/glibj.zip
  AC_SUBST(GLIBJ_ZIP)
fi
AM_CONDITIONAL(USER_WANT_CLASSPATH, test "x${with_classpath}" = xtrue)
])# _GNU_CRYPTO_WITH_CLASSPATH


# given a list of arguments, this macro tries repeatedly and for each element
# of the input list, to (a) assert that the argument is indeed a directory, and
# (b) it contains under it both 'lib/classpath/libjavalang.so' and
# 'share/classpath/glibj.zip' files.
# -----------------------------------------------------------------------------
AC_DEFUN(_GNU_CRYPTO_FIND_GNU_CLASSPATH,[
AC_MSG_CHECKING([for GNU Classpath installation directory])
for _F in $1 ; do
  _GNU_CRYPTO_CHECK_CLASSPATH(${_F})
  if test x$GNU_CLASSPATH_INSTALL_DIR != x ; then
    break
  fi
done
if test x${GNU_CLASSPATH_INSTALL_DIR} = x ; then
  AC_MSG_RESULT([not found])
else
  AC_MSG_RESULT([${GNU_CLASSPATH_INSTALL_DIR}])
fi])# _GNU_CRYPTO_FIND_GNU_CLASSPATH


# given a directory as an input, this macro checks if the two files
# 'lib/classpath/libjavalang.so' and 'share/classpath/glibj.zip' exist under
# it.  if they do, then GNU_CLASSPATH_INSTALL_DIR is set to that argument.
# -----------------------------------------------------------------------------
AC_DEFUN([_GNU_CRYPTO_CHECK_CLASSPATH],
[if test -r $1/lib/classpath/libjavalang.so && test -r $1/share/classpath/glibj.zip ; then
  GNU_CLASSPATH_INSTALL_DIR=$1
fi])# _GNU_CRYPTO_CHECK_CLASSPATH

# =============================================================================

# check user preferences for the bytecode compiler to use.
# user preferences may be defined with --with-xxx style configure options.
# those of interest to this macro are:
#
#    --with-gcj=...
#    --with-jikes=...
#    --with-javac=...
#
# each of the above options may be (a) empty, (b) equal to 'yes' or 'no', or
# (c) points to the location of the executable of that compiler.
# when the option is specified with no value, default locations are searched
# for the executable to ensure they can be used.  if more than one are
# specified, GCJ is picked before Jikes, which is picked before Javac.
# the first thing this macro does is invoke the _GNU_CRYPTO_WHICH JAVA and the
# _GNU_CRYPTO_WITH_CLASSPATH macros.  this is to ensure that a proper runtime
# jar can be used if the chosen compiler needs it.
# it then checks the arguments for each option in turn, setting a USER_WANT_xxx
# if a positive definition of the corresponding --with-xxx was specified.
# finally the USE_xxx conditionals are set if configure is able to locate the
# appropriate binary.
# -----------------------------------------------------------------------------
AC_DEFUN([GNU_CRYPTO_WHICH_JAVAC],[
_GNU_CRYPTO_WHICH_JAVA
_GNU_CRYPTO_WITH_CLASSPATH

user_specified_compiler=_GNU_CRYPTO_WITH_GCJ _GNU_CRYPTO_WITH_JIKES _GNU_CRYPTO_WITH_JAVAC

AM_CONDITIONAL(USER_WANT_GCJ,   test "x${user_specified_compiler}" = xgcj)
AM_CONDITIONAL(USER_WANT_JIKES, test "x${user_specified_compiler}" = xjikes)
AM_CONDITIONAL(USER_WANT_JAVAC, test "x${user_specified_compiler}" = xjavac)

# sanity check
_GNU_CRYPTO_ENSURE_GCJ
AM_CONDITIONAL(USE_GCJ,   test "x${selected_compiler}" = xgcj)
AM_CONDITIONAL(USE_JIKES, test "x${selected_compiler}" = xjikes)
AM_CONDITIONAL(USE_JAVAC, test "x${selected_compiler}" = xjavac)

AM_CONDITIONAL(FOUND_GCJ,   test "x${GCJ}" != x)
AM_CONDITIONAL(FOUND_JIKES, test "x${JIKES}" != x)
AM_CONDITIONAL(FOUND_JAVAC, test "x${JAVAC}" != x)
])# _GNU_CRYPTO_WHICH_JAVAC


AC_DEFUN([_GNU_CRYPTO_ENSURE_GCJ],[
if test "x${user_specified_compiler}" = xgcj || test "x${user_specified_compiler}" = x ; then
  if test "x${GCJ}" != x; then
    AC_MSG_NOTICE([will use GCJ for bytecode compilation])
    selected_compiler=gcj
  else
    AC_MSG_NOTICE([GCJ specified but not found.  Will try with Jikes])
    user_specified_compiler=jikes
    _GNU_CRYPTO_ENSURE_JIKES
  fi
else
  _GNU_CRYPTO_ENSURE_JIKES
fi])# _GNU_CRYPTO_ENSURE_GCJ


AC_DEFUN([_GNU_CRYPTO_ENSURE_JIKES],[
if test "x${user_specified_compiler}" = xjikes; then
  if test "x${JIKES}" != x; then
    # cannot use jikes without either glibj.zip or rt.jar
    if test "x${GLIBJ_ZIP}" != x || test "x${JAVA_RT_JAR}" != x; then
      AC_MSG_NOTICE([will use Jikes for bytecode compilation])
      selected_compiler=jikes
    else
      AC_MSG_NOTICE([Jikes specified but runtime classes not found.  Will try with Javac])
      _GNU_CRYPTO_ENSURE_JAVAC
    fi
  else
    AC_MSG_NOTICE([Jikes specified but not found.  Will try with Javac])
    _GNU_CRYPTO_ENSURE_JAVAC
  fi
else
  _GNU_CRYPTO_ENSURE_JAVAC
fi])# GNU_CRYPTO_ENSURE_JIKES


AC_DEFUN([_GNU_CRYPTO_ENSURE_JAVAC],[
if test "x${JAVAC}" != x; then
  AC_MSG_NOTICE([will use Javac for bytecode compilation])
  selected_compiler=javac
else # user wants nothing; back-track
  if test "x${GCJ}" != x; then
    AC_MSG_NOTICE([will use GCJ for bytecode compilation])
    selected_compiler=gcj
  else
    if test "x${JIKES}" != x; then
      # cannot use jikes without either glibj.zip or rt.jar
      if test "x${GLIBJ_ZIP}" != x || test "x${JAVA_RT_JAR}" != x; then
        AC_MSG_NOTICE([will use Jikes for bytecode compilation])
        selected_compiler=jikes
      else
        AC_MSG_NOTICE([cannot find a runtime library for use with Jikes])
        _GNU_CRYPTO_NO_COMPILER
      fi
    else
      _GNU_CRYPTO_NO_COMPILER
    fi
  fi
fi])# _GNU_CRYPTO_ENSURE_JAVAC


AC_DEFUN([_GNU_CRYPTO_NO_COMPILER],[
AC_MSG_NOTICE([cannot find a suitable java bytecode compiler])
AC_MSG_ERROR([try --with-gcj[[=ARG]], --with-jikes[[=ARG]], or --with-javac[[=ARG]]], 1)
])# _GNU_CRYPTO_NO_COMPILER


AC_DEFUN([_GNU_CRYPTO_WITH_GCJ],[
AC_ARG_WITH([gcj],
            AC_HELP_STRING([--with-gcj@<:@=ARG@:>@],
                           [use GCJ for bytecode compilation, and optionally the path where to find it @<:@ARG=yes@:>@]),
            [if test "x${withval}" != x && test "x${withval}" != xyes && test "x${withval}" != xno; then
              user_specified_compiler=gcj
              _GNU_CRYPTO_CHECK_GCJ(${withval})
            elif test "x${withval}" != xno; then
              user_specified_compiler=gcj
              _GNU_CRYPTO_CHECK_GCJ
            else
              user_specified_compiler=
            fi],
            [_GNU_CRYPTO_CHECK_GCJ])
AM_CONDITIONAL(FOUND_GCJ, test "x${GCJ}" != x)
AC_SUBST(GCJ)
])# _GNU_CRYPTO_WITH_GCJ


AC_DEFUN([_GNU_CRYPTO_CHECK_GCJ],[
if test "x$1" != x; then
  if test -f "$1"; then
    GCJ="$1"
  else
    AC_PATH_PROG(GCJ, "$1")
  fi
else
  AC_PATH_PROG(GCJ, "gcj")
fi
if test "x$GCJ" != x; then
  AC_MSG_CHECKING(gcj version)
  GCJ_VERSION=`$GCJ --version`
  GCJ_VERSION_MAJOR=`echo "$GCJ_VERSION" | cut -d '.' -f 1`
  GCJ_VERSION_MINOR=`echo "$GCJ_VERSION" | cut -d '.' -f 2`
  if expr "$GCJ_VERSION_MAJOR" \< 3 > /dev/null; then
    GCJ=""
  fi
  if expr "$GCJ_VERSION_MAJOR" = 3 > /dev/null; then
    if expr "$GCJ_VERSION_MINOR" \< 1; then
      GCJ=""
    fi
  fi
  if test "x$GCJ" != x; then
    AC_MSG_RESULT($GCJ_VERSION)
    AM_PROG_GCJ
  else
    AC_MSG_WARN($GCJ_VERSION: gcj 3.1 or higher required)
  fi
fi])# _GNU_CRYPTO_CHECK_GCJ


AC_DEFUN([_GNU_CRYPTO_WITH_JIKES],[
AC_ARG_WITH([jikes],
            AC_HELP_STRING([--with-jikes@<:@=ARG@:>@],
                           [use Jikes for bytecode compilation, and optionally the path where to find it @<:@ARG=no@:>@]),
            [if test "x${withval}" != x && test "x${withval}" != xyes && test "x${withval}" != xno; then
              user_specified_compiler=jikes
              _GNU_CRYPTO_CHECK_JIKES(${withval})
            elif test "x${withval}" != xno; then
              user_specified_compiler=jikes
              _GNU_CRYPTO_CHECK_JIKES
            else
              user_specified_compiler=
            fi],
            [_GNU_CRYPTO_CHECK_JIKES])
AM_CONDITIONAL(FOUND_JIKES, test "x${JIKES}" != x)
AC_SUBST(JIKES)
])# _GNU_CRYPTO_WITH_JIKES


AC_DEFUN([_GNU_CRYPTO_CHECK_JIKES],[
if test "x$1" != x; then
  if test -f "$1"; then
    JIKES="$1"
  else
    AC_PATH_PROG(JIKES, "$1")
  fi
else
  AC_PATH_PROG(JIKES, "jikes")
fi])# _GNU_CRYPTO_CHECK_JIKES


AC_DEFUN([_GNU_CRYPTO_WITH_JAVAC],[
AC_ARG_WITH([javac],
            AC_HELP_STRING([--with-javac@<:@=ARG@:>@],
                           [use Javac for bytecode compilation, and optionally the path where to find it @<:@ARG=no@:>@]),
            [if test "x${withval}" != x && test "x${withval}" != xyes && test "x${withval}" != xno; then
              user_specified_compiler=javac
              _GNU_CRYPTO_CHECK_JAVAC(${withval})
            elif test "x${withval}" != xno; then
              user_specified_compiler=javac
              _GNU_CRYPTO_CHECK_JAVAC
            else
              user_specified_compiler=
            fi],
            [_GNU_CRYPTO_CHECK_JAVAC])
AM_CONDITIONAL(FOUND_JAVAC, test "x${JAVAC}" != x)
AC_SUBST(JAVAC)
])# _GNU_CRYPTO_WITH_JAVAC


AC_DEFUN([_GNU_CRYPTO_CHECK_JAVAC],[
if test "x$1" != x; then
  if test -f "$1"; then
    JAVAC="$1"
  else
    AC_PATH_PROG(JAVAC, "$1")
  fi
else
  AC_PATH_PROG(JAVAC, "javac")
fi])# _GNU_CRYPTO_CHECK_JAVAC

# =============================================================================

AC_DEFUN([_GNU_CRYPTO_WITH_JCE_JAR],[
AC_ARG_WITH([jce_jar],
            AC_HELP_STRING([--with-jce-jar=DIR],
                           [path to JCE framework classes (javax.crypto) jar.  if unspecified, /usr/local/jce/share, /usr/local/share, /usr/share, /opt/jce/share, and /opt/share are considered, in that order; unless --with-jce is specified]),
            [if test "x${withval}" != x && test "x${withval}" != xyes && test "x${withval}" != xno; then
              AC_MSG_CHECKING([for ${withval}])
              if test -r ${withval} ; then
                AC_MSG_RESULT(yes)
                JCE_JAR=${withval}
                found_jce_jar=true
              else
                AC_MSG_ERROR([cannot find indicated JCE jar])
              fi
            elif test "x${withval}" != xno; then
              AC_MSG_NOTICE([no value supplied --with-jce-jar.  will look in default locations])
              _GNU_CRYPTO_FIND_JCE_JAR([/usr/local/jce /usr/local /usr /opt/jce /opt])
              if test x$JCE_JAR = x ; then
                AC_MSG_ERROR([cannot find JCE jar; specify its location using --with-jce-jar])
              fi
              INCLUDE_FOR_MAUVE_JCE=""
              found_jce_jar=true
            else
              JCE_JAR=""
              INCLUDE_FOR_MAUVE_JCE="!"
              found_jce_jar=false
            fi],
            [JCE_JAR=""
             INCLUDE_FOR_MAUVE_JCE="!"
             found_jce_jar=false])
AM_CONDITIONAL(FOUND_JCE_JAR, test "x${found_jce_jar}" = xtrue)
AC_SUBST(JCE_JAR)
AC_SUBST(INCLUDE_FOR_MAUVE_JCE)
])# _GNU_CRYPTO_WITH_JCE_JAR


AC_DEFUN(_GNU_CRYPTO_FIND_JCE_JAR,[
AC_MSG_CHECKING([for JCE jar])
for _F in $1 ; do
  _GNU_CRYPTO_CHECK_JCE_JAR(${_F})
  if test x$JCE_JAR != x ; then
    break
  fi
done
if test x${JCE_JAR} = x ; then
  AC_MSG_RESULT([not found])
else
  AC_MSG_RESULT([${JCE_JAR}])
fi])# _GNU_CRYPTO_FIND_JCE_JAR


AC_DEFUN([_GNU_CRYPTO_CHECK_JCE_JAR],
[if test -r $1/share/javax-crypto.jar ; then
  JCE_JAR=$1/share/javax-crypto.jar
fi])# _GNU_CRYPTO_CHECK_JCE_JAR


# macros copied from Mauve project's configure.in and acinclude.m4
# -----------------------------------------------------------------------------

# Designate the temporary directory to use by Mauve
AC_DEFUN(GNU_CRYPTO_WITH_TMPDIR,[
AC_ARG_WITH([tmpdir],
            AC_HELP_STRING([--with-tmpdir=DIR],
                           [put temporary files in DIR @<:@/tmp@:>@]),
            TMPDIR="$with_tmpdir",
            TMPDIR=/tmp)
AC_SUBST(TMPDIR)
])# GNU_CRYPTO_WITH_TMPDIR


# -----------------------------------------------------------
# Original by Mark Elbrecht <snowball3@bigfoot.com>
# Modified by Brian Jones <cbj@gnu.org> for Mauve
# acx_check_pathname_style.m4
# http://research.cys.de/autoconf-archive/

AC_DEFUN(ACX_CHECK_PATHNAME_STYLE_DOS,[
AC_MSG_CHECKING([for Windows and DOS and OS/2 style pathnames])
AC_CACHE_VAL([acx_cv_pathname_style_dos],[
             AC_REQUIRE([AC_CANONICAL_HOST])
             acx_cv_pathname_style_dos="no"
             case ${host_os} in
               *djgpp | *mingw32* | *emx*) acx_cv_pathname_style_dos="yes" ;;
             esac])
AC_MSG_RESULT([$acx_cv_pathname_style_dos])
if test "$acx_cv_pathname_style_dos" = "yes"; then
  AC_DEFINE([HAVE_PATHNAME_STYLE_DOS],[],[defined if running on a system with dos style paths])
  CHECK_PATH_SEPARATOR=';'
  CHECK_FILE_SEPARATOR='\\'
else
  CHECK_PATH_SEPARATOR=':'
  CHECK_FILE_SEPARATOR='/'
fi
AC_SUBST(CHECK_PATH_SEPARATOR)
AC_SUBST(CHECK_FILE_SEPARATOR)
])

# =============================================================================

AC_DEFUN([GNU_CRYPTO_WITH_JCE],[
AC_ARG_WITH([jce],
            AC_HELP_STRING([--with-jce@<:@=ARG@:>@ ],
                           [build the Java Cryptography Extension (JCE) as a shared library @<:@ARG=yes@:>@.  If this option is specified then --with-jce-jar is ignored]),
            [case "${withval}" in
              yes) with_jce=yes ;;
              no)  with_jce=no ;;
              *)   AC_MSG_ERROR([bad value ${withval} for --with-jce]) ;;
            esac],
            [with_jce=yes])
AM_CONDITIONAL(WITH_JCE, test "x${with_jce}" = xyes)
if test "x${with_jce}" = xyes; then
  JCE_JAR="`pwd`/jce/javax-crypto.jar"
  INCLUDE_FOR_MAUVE_JCE=""
  found_jce_jar=true

  AM_CONDITIONAL(FOUND_JCE_JAR, test "x${found_jce_jar}" = xtrue)
  AC_SUBST(JCE_JAR)
  AC_SUBST(INCLUDE_FOR_MAUVE_JCE)
else
  _GNU_CRYPTO_WITH_JCE_JAR
fi])# GNU_CRYPTO_WITH_JCE

# =============================================================================

# process --with-sasl configure option.
# test if building the javax.security.sasl and javax.security.auth.callback
# extensions is desired, or not.  possible values are 'yes' or 'no' with the
# default being 'yes' i.e. build such a shared library.
# -----------------------------------------------------------------------------
AC_DEFUN([GNU_CRYPTO_WITH_SASL],[
AC_ARG_WITH([sasl],
            AC_HELP_STRING([--with-sasl@<:@=ARG@:>@ ],
                           [build the Java SASL and Callback Extensions in a shared library @<:@ARG=yes@:>@]),
            [case "${withval}" in
              yes) with_sasl=yes ;;
              no)  with_sasl=no ;;
              *)   AC_MSG_ERROR([bad value ${withval} for --with-sasl]) ;;
            esac],
            [with_sasl=yes])
AM_CONDITIONAL(WITH_SASL, test "x${with_sasl}" = xyes)
if test "x${with_sasl}" = xyes; then
  SASL_JAR="`pwd`/security/javax-security.jar"
  found_sasl_jar=true
else
  SASL_JAR=""
  found_sasl_jar=false
fi
AM_CONDITIONAL(FOUND_SASL_JAR, test "x${found_sasl_jar}" = xtrue)
AC_SUBST(SASL_JAR)])# GNU_CRYPTO_WITH_SASL

# ==============================================================================

# set configured compiler options.
# ------------------------------------------------------------------------------
AC_DEFUN([GNU_CRYPTO_SET_COMPILE_OPTS],[
AM_GCJFLAGS="--encoding=UTF-8 -fassume-compiled"
if test -z "${FOUND_JCE_JAR_TRUE}" ; then
  if test -z "${FOUND_SASL_JAR_TRUE}" ; then
    AM_GCJFLAGS="${AM_GCJFLAGS} --classpath=\${JCE_JAR}\${PATH_SEPARATOR}\${SASL_JAR}\${PATH_SEPARATOR}.\${PATH_SEPARATOR}\${srcdir}"
  else
    AM_GCJFLAGS="${AM_GCJFLAGS} --classpath=\${JCE_JAR}\${PATH_SEPARATOR}.\${PATH_SEPARATOR}\${srcdir}"
  fi # FOUND_SASL_JAR
else
  if test -z "${FOUND_SASL_JAR_TRUE}" ; then
    AM_GCJFLAGS="${AM_GCJFLAGS} --classpath=\${SASL_JAR}\${PATH_SEPARATOR}.\${PATH_SEPARATOR}\${srcdir}"
  else
    AM_GCJFLAGS="${AM_GCJFLAGS} --classpath=.\${PATH_SEPARATOR}\${srcdir}"
  fi #FOUND_SASL_JAR
fi # FOUND_JCE_JAR
AC_SUBST(AM_GCJFLAGS)

JIKESFLAGS="-bootclasspath"
if test -z "${USER_WANT_GCJ_TRUE}" ; then
  JIKESFLAGS="${JIKESFLAGS} \$(GLIBJ_ZIP)\$(PATH_SEPARATOR)\$(JCE_JAR)"
else
  if test -z "${FOUND_JAVAC_TRUE}" ; then
    JIKESFLAGS="${JIKESFLAGS} \$(JAVA_RT_JAR)\$(PATH_SEPARATOR)\$(JCE_JAR)"
  else
    JIKESFLAGS="${JIKESFLAGS} \$(GLIBJ_ZIP)\$(PATH_SEPARATOR)\$(JCE_JAR)"
  fi
fi
JIKESFLAGS="${JIKESFLAGS} -target 1.1 +F -extdirs '' -sourcepath \$(srcdir)"
if test -z "${FOUND_SASL_JAR_TRUE}" ; then
  JIKESFLAGS="${JIKESFLAGS} -classpath \$(SASL_JAR)\$(PATH_SEPARATOR). "
else
  JIKESFLAGS="${JIKESFLAGS} -classpath . "
fi # FOUND_SASL_JAR
AC_SUBST(JIKESFLAGS)

JAVACFLAGS="-sourcepath \$(srcdir)"
if test -z "${FOUND_JCE_JAR_TRUE}" ; then
  JAVACFLAGS="${JAVACFLAGS} -bootclasspath \$(JCE_JAR)\$(PATH_SEPARATOR)\$(JAVA_RT_JAR)"
fi
if test -z "${FOUND_SASL_JAR_TRUE}" ; then
  JAVACFLAGS="${JAVACFLAGS} -classpath \$(SASL_JAR)\$(PATH_SEPARATOR). "
else
  JAVACFLAGS="${JAVACFLAGS} -classpath . "
fi # FOUND_SASL_JAR
AC_SUBST(JAVACFLAGS)

if test -z "${USE_GCJ_TRUE}" ; then
  JAVAC_CMD="\$(GCJ) \$(AM_GCJFLAGS) \$(GCJFLAGS) -C "
else
  if test -z "${USE_JIKES_TRUE}" ; then
    JAVAC_CMD="\$(JIKES) \$(JIKESFLAGS) "
  else
    JAVAC_CMD="\$(JAVAC) \$(JAVACFLAGS) "
  fi
fi
AC_SUBST(JAVAC_CMD)])# GNU_CRYPTO_SET_COMPILE_OPTS
dnl java.m4: Java autoconf macros.
dnl @synopsis AC_PROG_JAVA
dnl
dnl Here is a summary of the main macros:
dnl
dnl AC_PROG_JAVAC: finds a Java compiler.
dnl
dnl AC_PROG_JAVA: finds a Java virtual machine.
dnl
dnl AC_CHECK_CLASS: finds if we have the given class (beware of CLASSPATH!).
dnl
dnl AC_CHECK_RQRD_CLASS: finds if we have the given class and stops otherwise.
dnl
dnl AC_TRY_COMPILE_JAVA: attempt to compile user given source.
dnl
dnl AC_TRY_RUN_JAVA: attempt to compile and run user given source.
dnl
dnl AC_JAVA_OPTIONS: adds Java configure options.
dnl
dnl AC_PROG_JAVA tests an existing Java virtual machine. It uses the
dnl environment variable JAVA then tests in sequence various common Java
dnl virtual machines. For political reasons, it starts with the free ones.
dnl You *must* call [AC_PROG_JAVAC] before.
dnl
dnl If you want to force a specific VM:
dnl
dnl - at the configure.in level, set JAVA=yourvm before calling AC_PROG_JAVA
dnl   (but after AC_INIT)
dnl
dnl - at the configure level, setenv JAVA
dnl
dnl You can use the JAVA variable in your Makefile.in, with @JAVA@.
dnl
dnl *Warning*: its success or failure can depend on a proper setting of the
dnl CLASSPATH env. variable.
dnl
dnl TODO: allow to exclude virtual machines (rationale: most Java programs
dnl cannot run with some VM like kaffe).
dnl
dnl Note: This is part of the set of autoconf M4 macros for Java programs.
dnl It is VERY IMPORTANT that you download the whole set, some
dnl macros depend on other. Unfortunately, the autoconf archive does not
dnl support the concept of set of macros, so I had to break it for
dnl submission.
dnl
dnl A Web page, with a link to the latest CVS snapshot is at
dnl <http://www.internatif.org/bortzmeyer/autoconf-Java/>.
dnl
dnl This is a sample configure.in
dnl Process this file with autoconf to produce a configure script.
dnl
dnl    AC_INIT(UnTag.java)
dnl
dnl    dnl Checks for programs.
dnl    AC_CHECK_CLASSPATH
dnl    AC_PROG_JAVAC
dnl    AC_PROG_JAVA
dnl
dnl    dnl Checks for classes
dnl    AC_CHECK_RQRD_CLASS(org.xml.sax.Parser)
dnl    AC_CHECK_RQRD_CLASS(com.jclark.xml.sax.Driver)
dnl
dnl    AC_OUTPUT(Makefile)
dnl
dnl @author Stephane Bortzmeyer <bortzmeyer@pasteur.fr>
dnl @version $Id: acinclude.m4,v 1.11 2003/09/27 16:47:40 rsdio Exp $
dnl
AC_DEFUN(AC_PROG_JAVA,[
AC_REQUIRE([AC_EXEEXT])dnl
AC_ARG_VAR(JAVA,      [Java bytecode interpreter.])
AC_ARG_VAR(JAVAFLAGS, [Java interpreter run-time flags.])
if test x$JAVAPREFIX = x; then
	test x$JAVA = x && AC_CHECK_PROGS(JAVA, kaffe$EXEEXT java$EXEEXT)
else
	test x$JAVA = x && AC_CHECK_PROGS(JAVA, kaffe$EXEEXT java$EXEEXT, $JAVAPREFIX)
fi
test x$JAVA = x && AC_MSG_ERROR([no acceptable Java virtual machine found in \$PATH])
AC_PROG_JAVA_WORKS
AC_PROVIDE([$0])dnl
])
dnl @synopsis AC_CHECK_CLASS
dnl
dnl AC_CHECK_CLASS tests the existence of a given Java class, either in
dnl a jar or in a '.class' file.
dnl
dnl *Warning*: its success or failure can depend on a proper setting of the
dnl CLASSPATH env. variable.
dnl
dnl Note: This is part of the set of autoconf M4 macros for Java programs.
dnl It is VERY IMPORTANT that you download the whole set, some
dnl macros depend on other. Unfortunately, the autoconf archive does not
dnl support the concept of set of macros, so I had to break it for
dnl submission.
dnl The general documentation, as well as the sample configure.in, is
dnl included in the AC_PROG_JAVA macro.
dnl
dnl @author Stephane Bortzmeyer <bortzmeyer@pasteur.fr>
dnl @version $Id: acinclude.m4,v 1.11 2003/09/27 16:47:40 rsdio Exp $
dnl
AC_DEFUN(AC_CHECK_CLASS,[
AC_REQUIRE([AC_PROG_JAVA])
ac_var_name=`echo $1 | sed 's/\./_/g'`
dnl Normaly I'd use a AC_CACHE_CHECK here but since the variable name is
dnl dynamic I need an extra level of extraction
AC_MSG_CHECKING([for $1 class])
AC_CACHE_VAL(ac_cv_class_$ac_var_name, [
if test x$ac_cv_prog_uudecode_base64 = xyes; then
dnl /**
dnl  * Test.java: used to test dynamicaly if a class exists.
dnl  */
dnl public class Test
dnl {
dnl 
dnl public static void
dnl main( String[] argv )
dnl {
dnl 	Class lib;
dnl 	if (argv.length < 1)
dnl 	 {
dnl 		System.err.println ("Missing argument");
dnl 		System.exit (77);
dnl 	 }
dnl 	try
dnl 	 {
dnl 		lib = Class.forName (argv[0]);
dnl 	 }
dnl 	catch (ClassNotFoundException e)
dnl 	 {
dnl 		System.exit (1);
dnl 	 }
dnl 	lib = null;
dnl 	System.exit (0);
dnl }
dnl 
dnl }
cat << \EOF > Test.uue
begin-base64 644 Test.class
yv66vgADAC0AKQcAAgEABFRlc3QHAAQBABBqYXZhL2xhbmcvT2JqZWN0AQAE
bWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBAARDb2RlAQAPTGluZU51
bWJlclRhYmxlDAAKAAsBAANlcnIBABVMamF2YS9pby9QcmludFN0cmVhbTsJ
AA0ACQcADgEAEGphdmEvbGFuZy9TeXN0ZW0IABABABBNaXNzaW5nIGFyZ3Vt
ZW50DAASABMBAAdwcmludGxuAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWCgAV
ABEHABYBABNqYXZhL2lvL1ByaW50U3RyZWFtDAAYABkBAARleGl0AQAEKEkp
VgoADQAXDAAcAB0BAAdmb3JOYW1lAQAlKExqYXZhL2xhbmcvU3RyaW5nOylM
amF2YS9sYW5nL0NsYXNzOwoAHwAbBwAgAQAPamF2YS9sYW5nL0NsYXNzBwAi
AQAgamF2YS9sYW5nL0NsYXNzTm90Rm91bmRFeGNlcHRpb24BAAY8aW5pdD4B
AAMoKVYMACMAJAoAAwAlAQAKU291cmNlRmlsZQEACVRlc3QuamF2YQAhAAEA
AwAAAAAAAgAJAAUABgABAAcAAABtAAMAAwAAACkqvgSiABCyAAwSD7YAFBBN
uAAaKgMyuAAeTKcACE0EuAAaAUwDuAAasQABABMAGgAdACEAAQAIAAAAKgAK
AAAACgAAAAsABgANAA4ADgATABAAEwASAB4AFgAiABgAJAAZACgAGgABACMA
JAABAAcAAAAhAAEAAQAAAAUqtwAmsQAAAAEACAAAAAoAAgAAAAQABAAEAAEA
JwAAAAIAKA==
====
EOF
		if uudecode$EXEEXT Test.uue; then
			:
		else
			echo "configure: __oline__: uudecode had trouble decoding base 64 file 'Test.uue'" >&AC_FD_CC
			echo "configure: failed file was:" >&AC_FD_CC
			cat Test.uue >&AC_FD_CC
			ac_cv_prog_uudecode_base64=no
		fi
	rm -f Test.uue
	if AC_TRY_COMMAND($JAVA $JAVAFLAGS Test $1) >/dev/null 2>&1; then
		eval "ac_cv_class_$ac_var_name=yes"
	else
		eval "ac_cv_class_$ac_var_name=no"
	fi
	rm -f Test.class
else
	AC_TRY_COMPILE_JAVA([$1], , [eval "ac_cv_class_$ac_var_name=yes"],
		[eval "ac_cv_class_$ac_var_name=no"])
fi
eval "ac_var_val=$`eval echo ac_cv_class_$ac_var_name`"
eval "HAVE_$ac_var_name=$`echo ac_cv_class_$ac_var_val`"
HAVE_LAST_CLASS=$ac_var_val
if test x$ac_var_val = xyes; then
	ifelse([$2], , :, [$2])
else
	ifelse([$3], , :, [$3])
fi
])
dnl for some reason the above statment didn't fall though here?
dnl do scripts have variable scoping?
eval "ac_var_val=$`eval echo ac_cv_class_$ac_var_name`"
AC_MSG_RESULT($ac_var_val)
])

dnl @synopsis AC_CHECK_CLASSPATH
dnl
dnl AC_CHECK_CLASSPATH just displays the CLASSPATH, for the edification
dnl of the user.
dnl
dnl Note: This is part of the set of autoconf M4 macros for Java programs.
dnl It is VERY IMPORTANT that you download the whole set, some
dnl macros depend on other. Unfortunately, the autoconf archive does not
dnl support the concept of set of macros, so I had to break it for
dnl submission.
dnl The general documentation, as well as the sample configure.in, is
dnl included in the AC_PROG_JAVA macro.
dnl
dnl @author Stephane Bortzmeyer <bortzmeyer@pasteur.fr>
dnl @version $Id: acinclude.m4,v 1.11 2003/09/27 16:47:40 rsdio Exp $
dnl
AC_DEFUN(AC_CHECK_CLASSPATH,[
AC_ARG_VAR(CLASSPATH, [Path to extra class libraries.])
if test "x$CLASSPATH" = x; then
        echo "You have no CLASSPATH, I hope it is good"
else
        echo "You have CLASSPATH $CLASSPATH, hope it is correct"
fi
])



dnl @synopsis AC_CHECK_RQRD_CLASS
dnl
dnl AC_CHECK_RQRD_CLASS tests the existence of a given Java class, either in
dnl a jar or in a '.class' file and fails if it doesn't exist.
dnl Its success or failure can depend on a proper setting of the
dnl CLASSPATH env. variable.
dnl
dnl Note: This is part of the set of autoconf M4 macros for Java programs.
dnl It is VERY IMPORTANT that you download the whole set, some
dnl macros depend on other. Unfortunately, the autoconf archive does not
dnl support the concept of set of macros, so I had to break it for
dnl submission.
dnl The general documentation, as well as the sample configure.in, is
dnl included in the AC_PROG_JAVA macro.
dnl
dnl @author Stephane Bortzmeyer <bortzmeyer@pasteur.fr>
dnl @version $Id: acinclude.m4,v 1.11 2003/09/27 16:47:40 rsdio Exp $
dnl

AC_DEFUN(AC_CHECK_RQRD_CLASS,[
CLASS=`echo $1|sed 's/\./_/g'`
AC_CHECK_CLASS($1)
if test "$HAVE_LAST_CLASS" = "no"; then
        AC_MSG_ERROR([Required class $1 missing, exiting.])
fi
])
dnl @synopsis AC_JAVA_OPTIONS
dnl
dnl AC_JAVA_OPTIONS adds configure command line options used for Java m4
dnl macros. This Macro is optional.
dnl
dnl Note: This is part of the set of autoconf M4 macros for Java programs.
dnl It is VERY IMPORTANT that you download the whole set, some
dnl macros depend on other. Unfortunately, the autoconf archive does not
dnl support the concept of set of macros, so I had to break it for
dnl submission.
dnl The general documentation, as well as the sample configure.in, is
dnl included in the AC_PROG_JAVA macro.
dnl
dnl @author Devin Weaver <ktohg@tritarget.com>
dnl @version $Id: acinclude.m4,v 1.11 2003/09/27 16:47:40 rsdio Exp $
dnl
AC_DEFUN(AC_JAVA_OPTIONS,[
AC_ARG_WITH(java-prefix,
	AC_HELP_STRING([--with-java-prefix=PFX],[prefix where Java runtime is installed (optional)]))
AC_ARG_WITH(javac-flags,
	AC_HELP_STRING([--with-javac-flags=FLAGS],[flags to pass to the Java compiler (optional)]))
AC_ARG_WITH(java-flags,
	AC_HELP_STRING([--with-java-flags=FLAGS],[flags to pass to the Java VM (optional)]))
JAVAPREFIX=$with_java_prefix
JAVACFLAGS=$with_javac_flags
JAVAFLAGS=$with_java_flags
AC_SUBST(JAVAPREFIX)dnl
AC_SUBST(JAVACFLAGS)dnl
AC_SUBST(JAVAFLAGS)dnl
AC_SUBST(JAVA)dnl
AC_SUBST(JAVAC)dnl
])
dnl @synopsis AC_PROG_JAVA_WORKS
dnl
dnl Internal use ONLY.
dnl
dnl Note: This is part of the set of autoconf M4 macros for Java programs.
dnl It is VERY IMPORTANT that you download the whole set, some
dnl macros depend on other. Unfortunately, the autoconf archive does not
dnl support the concept of set of macros, so I had to break it for
dnl submission.
dnl The general documentation, as well as the sample configure.in, is
dnl included in the AC_PROG_JAVA macro.
dnl
dnl @author Stephane Bortzmeyer <bortzmeyer@pasteur.fr>
dnl @version $Id: acinclude.m4,v 1.11 2003/09/27 16:47:40 rsdio Exp $
dnl
AC_DEFUN(AC_PROG_JAVA_WORKS, [
AC_CHECK_PROG(uudecode, uudecode$EXEEXT, yes)
if test x$uudecode = xyes; then
AC_CACHE_CHECK([if uudecode can decode base 64 file], ac_cv_prog_uudecode_base64, [
dnl /**
dnl  * Test.java: used to test if java compiler works.
dnl  */
dnl public class Test
dnl {
dnl 
dnl public static void
dnl main( String[] argv )
dnl {
dnl 	System.exit (0);
dnl }
dnl 
dnl }
cat << \EOF > Test.uue
begin-base64 644 Test.class
yv66vgADAC0AFQcAAgEABFRlc3QHAAQBABBqYXZhL2xhbmcvT2JqZWN0AQAE
bWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBAARDb2RlAQAPTGluZU51
bWJlclRhYmxlDAAKAAsBAARleGl0AQAEKEkpVgoADQAJBwAOAQAQamF2YS9s
YW5nL1N5c3RlbQEABjxpbml0PgEAAygpVgwADwAQCgADABEBAApTb3VyY2VG
aWxlAQAJVGVzdC5qYXZhACEAAQADAAAAAAACAAkABQAGAAEABwAAACEAAQAB
AAAABQO4AAyxAAAAAQAIAAAACgACAAAACgAEAAsAAQAPABAAAQAHAAAAIQAB
AAEAAAAFKrcAErEAAAABAAgAAAAKAAIAAAAEAAQABAABABMAAAACABQ=
====
EOF
if uudecode$EXEEXT Test.uue; then
	ac_cv_prog_uudecode_base64=yes
else
	echo "configure: __oline__: uudecode had trouble decoding base 64 file 'Test.uue'" >&AC_FD_CC
	echo "configure: failed file was:" >&AC_FD_CC
	cat Test.uue >&AC_FD_CC
	ac_cv_prog_uudecode_base64=no
fi
rm -f Test.uue])
fi
if test x$ac_cv_prog_uudecode_base64 != xyes; then
	rm -f Test.class
	AC_MSG_WARN([I have to compile Test.class from scratch])
	if test x$ac_cv_prog_javac_works = xno; then
		AC_MSG_ERROR([Cannot compile java source. $JAVAC does not work properly])
	fi
	if test x$ac_cv_prog_javac_works = x; then
		AC_PROG_JAVAC
	fi
fi
AC_CACHE_CHECK(if $JAVA works, ac_cv_prog_java_works, [
JAVA_TEST=Test.java
CLASS_TEST=Test.class
TEST=Test
changequote(, )dnl
cat << \EOF > $JAVA_TEST
/* [#]line __oline__ "configure" */
public class Test {
public static void main (String args[]) {
	System.exit (0);
} }
EOF
changequote([, ])dnl
if test x$ac_cv_prog_uudecode_base64 != xyes; then
	if AC_TRY_COMMAND($JAVAC $JAVACFLAGS $JAVA_TEST) && test -s $CLASS_TEST; then
		:
	else
	  echo "configure: failed program was:" >&AC_FD_CC
	  cat $JAVA_TEST >&AC_FD_CC
	  AC_MSG_ERROR(The Java compiler $JAVAC failed (see config.log, check the CLASSPATH?))
	fi
fi
if AC_TRY_COMMAND($JAVA $JAVAFLAGS $TEST) >/dev/null 2>&1; then
  ac_cv_prog_java_works=yes
else
  echo "configure: failed program was:" >&AC_FD_CC
  cat $JAVA_TEST >&AC_FD_CC
  AC_MSG_ERROR(The Java VM $JAVA failed (see config.log, check the CLASSPATH?))
fi
rm -fr $JAVA_TEST $CLASS_TEST Test.uue
])
AC_PROVIDE([$0])dnl
]
)

dnl @synopsis AC_PROG_JAVAC
dnl
dnl AC_PROG_JAVAC tests an existing Java compiler. It uses the environment
dnl variable JAVAC then tests in sequence various common Java compilers. For
dnl political reasons, it starts with the free ones.
dnl
dnl If you want to force a specific compiler:
dnl
dnl - at the configure.in level, set JAVAC=yourcompiler before calling
dnl AC_PROG_JAVAC
dnl
dnl - at the configure level, setenv JAVAC
dnl
dnl You can use the JAVAC variable in your Makefile.in, with @JAVAC@.
dnl
dnl *Warning*: its success or failure can depend on a proper setting of the
dnl CLASSPATH env. variable.
dnl
dnl TODO: allow to exclude compilers (rationale: most Java programs cannot compile
dnl with some compilers like guavac).
dnl
dnl Note: This is part of the set of autoconf M4 macros for Java programs.
dnl It is VERY IMPORTANT that you download the whole set, some
dnl macros depend on other. Unfortunately, the autoconf archive does not
dnl support the concept of set of macros, so I had to break it for
dnl submission.
dnl The general documentation, as well as the sample configure.in, is
dnl included in the AC_PROG_JAVA macro.
dnl
dnl @author Stephane Bortzmeyer <bortzmeyer@pasteur.fr>
dnl @version $Id: acinclude.m4,v 1.11 2003/09/27 16:47:40 rsdio Exp $
dnl
AC_DEFUN(AC_PROG_JAVAC,[
AC_REQUIRE([AC_EXEEXT])dnl
AC_ARG_VAR(JAVAC,      [Java bytecode compiler.])
AC_ARG_VAR(JAVACFLAGS, [Extra flags for the java compiler.])
if test "x$JAVAPREFIX" = x; then
	test "x$JAVAC" = x && AC_CHECK_PROGS(JAVAC, "gcj$EXEEXT -C" guavac$EXEEXT jikes$EXEEXT javac$EXEEXT)
else
	test "x$JAVAC" = x && AC_CHECK_PROGS(JAVAC, "gcj$EXEEXT -C" guavac$EXEEXT jikes$EXEEXT javac$EXEEXT, $JAVAPREFIX)
fi
test "x$JAVAC" = x && AC_MSG_ERROR([no acceptable Java compiler found in \$PATH])
AC_PROG_JAVAC_WORKS
AC_PROVIDE([$0])dnl
])

dnl @synopsis AC_PROG_JAVAC_WORKS
dnl
dnl Internal use ONLY.
dnl
dnl Note: This is part of the set of autoconf M4 macros for Java programs.
dnl It is VERY IMPORTANT that you download the whole set, some
dnl macros depend on other. Unfortunately, the autoconf archive does not
dnl support the concept of set of macros, so I had to break it for
dnl submission.
dnl The general documentation, as well as the sample configure.in, is
dnl included in the AC_PROG_JAVA macro.
dnl
dnl @author Stephane Bortzmeyer <bortzmeyer@pasteur.fr>
dnl @version $Id: acinclude.m4,v 1.11 2003/09/27 16:47:40 rsdio Exp $
dnl
AC_DEFUN(AC_PROG_JAVAC_WORKS,[
AC_CACHE_CHECK([if $JAVAC works], ac_cv_prog_javac_works, [
JAVA_TEST=Test.java
CLASS_TEST=Test.class
cat << \EOF > $JAVA_TEST
/* [#]line __oline__ "configure" */
public class Test {
}
EOF
if AC_TRY_COMMAND($JAVAC $JAVACFLAGS $JAVA_TEST) >/dev/null 2>&1; then
  ac_cv_prog_javac_works=yes
else
  AC_MSG_ERROR([The Java compiler $JAVAC failed (see config.log, check the CLASSPATH?)])
  echo "configure: failed program was:" >&AC_FD_CC
  cat $JAVA_TEST >&AC_FD_CC
fi
rm -f $JAVA_TEST $CLASS_TEST
])
AC_PROVIDE([$0])dnl
])
dnl @synopsis AC_TRY_COMPILE_JAVA
dnl
dnl AC_TRY_COMPILE_JAVA attempt to compile user given source.
dnl
dnl *Warning*: its success or failure can depend on a proper setting of the
dnl CLASSPATH env. variable.
dnl
dnl Note: This is part of the set of autoconf M4 macros for Java programs.
dnl It is VERY IMPORTANT that you download the whole set, some
dnl macros depend on other. Unfortunately, the autoconf archive does not
dnl support the concept of set of macros, so I had to break it for
dnl submission.
dnl The general documentation, as well as the sample configure.in, is
dnl included in the AC_PROG_JAVA macro.
dnl
dnl @author Devin Weaver <ktohg@tritarget.com>
dnl @version $Id: acinclude.m4,v 1.11 2003/09/27 16:47:40 rsdio Exp $
dnl
AC_DEFUN(AC_TRY_COMPILE_JAVA,[
AC_REQUIRE([AC_PROG_JAVAC])dnl
cat << \EOF > Test.java
/* [#]line __oline__ "configure" */
ifelse([$1], , , [import $1;])
public class Test {
[$2]
}
EOF
if AC_TRY_COMMAND($JAVAC $JAVACFLAGS Test.java) && test -s Test.class
then
dnl Don't remove the temporary files here, so they can be examined.
  ifelse([$3], , :, [$3])
else
  echo "configure: failed program was:" >&AC_FD_CC
  cat Test.java >&AC_FD_CC
ifelse([$4], , , [  rm -fr Test*
  $4
])dnl
fi
rm -fr Test*])
dnl @synopsis AC_TRY_RUN_JAVA
dnl
dnl AC_TRY_RUN_JAVA attempt to compile and run user given source.
dnl
dnl *Warning*: its success or failure can depend on a proper setting of the
dnl CLASSPATH env. variable.
dnl
dnl Note: This is part of the set of autoconf M4 macros for Java programs.
dnl It is VERY IMPORTANT that you download the whole set, some
dnl macros depend on other. Unfortunately, the autoconf archive does not
dnl support the concept of set of macros, so I had to break it for
dnl submission.
dnl The general documentation, as well as the sample configure.in, is
dnl included in the AC_PROG_JAVA macro.
dnl
dnl @author Devin Weaver <ktohg@tritarget.com>
dnl @version $Id: acinclude.m4,v 1.11 2003/09/27 16:47:40 rsdio Exp $
dnl
AC_DEFUN(AC_TRY_RUN_JAVA,[
AC_REQUIRE([AC_PROG_JAVAC])dnl
AC_REQUIRE([AC_PROG_JAVA])dnl
cat << \EOF > Test.java
/* [#]line __oline__ "configure" */
ifelse([$1], , , [include $1;])
public class Test {
[$2]
}
EOF
if AC_TRY_COMMAND($JAVAC $JAVACFLAGS Test.java) && test -s Test.class && ($JAVA $JAVAFLAGS Test; exit) 2>/dev/null
then
dnl Don't remove the temporary files here, so they can be examined.
  ifelse([$3], , :, [$3])
else
  echo "configure: failed program was:" >&AC_FD_CC
  cat Test.java >&AC_FD_CC
ifelse([$4], , , [  rm -fr Test*
  $4
])dnl
fi
rm -fr Test*])

dnl AC_CHECK_PATH_SEPARATOR
dnl
dnl Determines the strings used to separate paths (e.g. ':') and
dnl directories (e.g. '/').
dnl
AC_DEFUN([AC_CHECK_PATH_SEPARATOR],[
AC_REQUIRE([AC_PROG_JAVA])
AC_MSG_CHECKING([for the system path separator])
AC_CACHE_VAL(ac_cv_path_separator, [
if test x$ac_cv_prog_uudecode_base64 = xyes; then
dnl class pathtest {
dnl    public static void main(String[] argv) {
dnl       System.out.println(System.getProperty("path.separator"));
dnl    }
dnl }
cat << \EOF > pathtest.uue
begin-base64 640 pathtest.class
yv66vgADAC0AIQcAAgEACHBhdGh0ZXN0BwAEAQAQamF2YS9sYW5nL09iamVj
dAEABG1haW4BABYoW0xqYXZhL2xhbmcvU3RyaW5nOylWAQAEQ29kZQEAD0xp
bmVOdW1iZXJUYWJsZQwACgALAQADb3V0AQAVTGphdmEvaW8vUHJpbnRTdHJl
YW07CQANAAkHAA4BABBqYXZhL2xhbmcvU3lzdGVtCAAQAQAOcGF0aC5zZXBh
cmF0b3IMABIAEwEAC2dldFByb3BlcnR5AQAmKExqYXZhL2xhbmcvU3RyaW5n
OylMamF2YS9sYW5nL1N0cmluZzsKAA0AEQwAFgAXAQAHcHJpbnRsbgEAFShM
amF2YS9sYW5nL1N0cmluZzspVgoAGQAVBwAaAQATamF2YS9pby9QcmludFN0
cmVhbQEABjxpbml0PgEAAygpVgwAGwAcCgADAB0BAApTb3VyY2VGaWxlAQAN
cGF0aHRlc3QuamF2YQAgAAEAAwAAAAAAAgAJAAUABgABAAcAAAAoAAIAAQAA
AAyyAAwSD7gAFLYAGLEAAAABAAgAAAAKAAIAAAADAAsABAAAABsAHAABAAcA
AAAhAAEAAQAAAAUqtwAesQAAAAEACAAAAAoAAgAAAAEABAABAAEAHwAAAAIA
IA==
====
EOF
		if uudecode$EXEEXT pathtest.uue; then
			:
		else
			echo "configure: __oline__: uudecode had trouble decoding base 64 file 'pathtest.uue'" >&AC_FD_CC
			echo "configure: failed file was:" >&AC_FD_CC
			cat pathtest.uue >&AC_FD_CC
			ac_cv_prog_uudecode_base64=no
		fi
	rm -f pathtest.uue
	ac_cv_path_separator=$($JAVA $JAVAFLAGS pathtest)
	rm -f pathtest.class
	])
AC_MSG_RESULT([$ac_cv_path_separator])
PATH_SEPARATOR=$ac_cv_path_separator
fi
])

dnl AC_CHECK_FILE_SEPARATOR
dnl
dnl Determines the strings used to separate files (e.g. '/').
dnl
AC_DEFUN([AC_CHECK_FILE_SEPARATOR],[
AC_REQUIRE([AC_PROG_JAVA])
AC_MSG_CHECKING([for the system file separator])
AC_CACHE_VAL(ac_cv_file_separator, [
if test x$ac_cv_prog_uudecode_base64 = xyes; then
dnl class filetest {
dnl    public static void main(String[] argv) {
dnl       System.out.println(System.getProperty("file.separator"));
dnl    }
dnl }
cat << \EOF > filetest.uue
begin-base64 644 filetest.class
yv66vgADAC0AIQcAAgEACGZpbGV0ZXN0BwAEAQAQamF2YS9sYW5nL09iamVj
dAEABG1haW4BABYoW0xqYXZhL2xhbmcvU3RyaW5nOylWAQAEQ29kZQEAD0xp
bmVOdW1iZXJUYWJsZQwACgALAQADb3V0AQAVTGphdmEvaW8vUHJpbnRTdHJl
YW07CQANAAkHAA4BABBqYXZhL2xhbmcvU3lzdGVtCAAQAQAOZmlsZS5zZXBh
cmF0b3IMABIAEwEAC2dldFByb3BlcnR5AQAmKExqYXZhL2xhbmcvU3RyaW5n
OylMamF2YS9sYW5nL1N0cmluZzsKAA0AEQwAFgAXAQAHcHJpbnRsbgEAFShM
amF2YS9sYW5nL1N0cmluZzspVgoAGQAVBwAaAQATamF2YS9pby9QcmludFN0
cmVhbQEABjxpbml0PgEAAygpVgwAGwAcCgADAB0BAApTb3VyY2VGaWxlAQAN
ZmlsZXRlc3QuamF2YQAgAAEAAwAAAAAAAgAJAAUABgABAAcAAAAoAAIAAQAA
AAyyAAwSD7gAFLYAGLEAAAABAAgAAAAKAAIAAAADAAsABAAAABsAHAABAAcA
AAAhAAEAAQAAAAUqtwAesQAAAAEACAAAAAoAAgAAAAEABAABAAEAHwAAAAIA
IA==
====
EOF
		if uudecode$EXEEXT filetest.uue; then
			:
		else
			echo "configure: __oline__: uudecode had trouble decoding base 64 file 'filetest.uue'" >&AC_FD_CC
			echo "configure: failed file was:" >&AC_FD_CC
			cat filetest.uue >&AC_FD_CC
			ac_cv_prog_uudecode_base64=no
		fi
	rm -f filetest.uue
	ac_cv_file_separator=$($JAVA $JAVAFLAGS filetest)
	rm -f filetest.class
	])
AC_MSG_RESULT([$ac_cv_file_separator])
if test $ac_cv_file_separator = '\\'; then
	ac_cv_file_separator=\\\\
fi
FILE_SEPARATOR=$ac_cv_file_separator
fi
])

dnl @synopsis AC_PROG_JAR
dnl
AC_DEFUN(AC_PROG_JAR,[
AC_REQUIRE([AC_EXEEXT])dnl
AC_ARG_VAR(JAR,      [Java archiver.])
test "x$JAR" = x && AC_CHECK_PROGS(JAR, "jar$EXEEXT")
test "x$JAR" = x && AC_MSG_ERROR([no acceptable Java archiver found in \$PATH])
AC_PROVIDE([$0])dnl
])

# AM_CONDITIONAL                                              -*- Autoconf -*-

# Copyright 1997, 2000, 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 5

AC_PREREQ(2.52)

# AM_CONDITIONAL(NAME, SHELL-CONDITION)
# -------------------------------------
# Define a conditional.
AC_DEFUN([AM_CONDITIONAL],
[ifelse([$1], [TRUE],  [AC_FATAL([$0: invalid condition: $1])],
        [$1], [FALSE], [AC_FATAL([$0: invalid condition: $1])])dnl
AC_SUBST([$1_TRUE])
AC_SUBST([$1_FALSE])
if $2; then
  $1_TRUE=
  $1_FALSE='#'
else
  $1_TRUE='#'
  $1_FALSE=
fi
AC_CONFIG_COMMANDS_PRE(
[if test -z "${$1_TRUE}" && test -z "${$1_FALSE}"; then
  AC_MSG_ERROR([conditional "$1" was never defined.
Usually this means the macro was only invoked conditionally.])
fi])])

# Check for Java compiler.
# For now we only handle the GNU compiler.

# Copyright 1999, 2000, Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

AC_DEFUN([AM_PROG_GCJ],[
AC_CHECK_PROGS(GCJ, gcj, gcj)
test -z "$GCJ" && AC_MSG_ERROR([no acceptable gcj found in \$PATH])
if test "x${GCJFLAGS-unset}" = xunset; then
   GCJFLAGS="-g -O2"
fi
AC_SUBST(GCJFLAGS)
_AM_IF_OPTION([no-dependencies],, [_AM_DEPENDENCIES(GCJ)])
])

# Helper functions for option handling.                    -*- Autoconf -*-

# Copyright 2001, 2002  Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 2

# _AM_MANGLE_OPTION(NAME)
# -----------------------
AC_DEFUN([_AM_MANGLE_OPTION],
[[_AM_OPTION_]m4_bpatsubst($1, [[^a-zA-Z0-9_]], [_])])

# _AM_SET_OPTION(NAME)
# ------------------------------
# Set option NAME.  Presently that only means defining a flag for this option.
AC_DEFUN([_AM_SET_OPTION],
[m4_define(_AM_MANGLE_OPTION([$1]), 1)])

# _AM_SET_OPTIONS(OPTIONS)
# ----------------------------------
# OPTIONS is a space-separated list of Automake options.
AC_DEFUN([_AM_SET_OPTIONS],
[AC_FOREACH([_AM_Option], [$1], [_AM_SET_OPTION(_AM_Option)])])

# _AM_IF_OPTION(OPTION, IF-SET, [IF-NOT-SET])
# -------------------------------------------
# Execute IF-SET if OPTION is set, IF-NOT-SET otherwise.
AC_DEFUN([_AM_IF_OPTION],
[m4_ifset(_AM_MANGLE_OPTION([$1]), [$2], [$3])])

# serial 5						-*- Autoconf -*-

# Copyright (C) 1999, 2000, 2001, 2002, 2003  Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.


# There are a few dirty hacks below to avoid letting `AC_PROG_CC' be
# written in clear, in which case automake, when reading aclocal.m4,
# will think it sees a *use*, and therefore will trigger all it's
# C support machinery.  Also note that it means that autoscan, seeing
# CC etc. in the Makefile, will ask for an AC_PROG_CC use...



# _AM_DEPENDENCIES(NAME)
# ----------------------
# See how the compiler implements dependency checking.
# NAME is "CC", "CXX", "GCJ", or "OBJC".
# We try a few techniques and use that to set a single cache variable.
#
# We don't AC_REQUIRE the corresponding AC_PROG_CC since the latter was
# modified to invoke _AM_DEPENDENCIES(CC); we would have a circular
# dependency, and given that the user is not expected to run this macro,
# just rely on AC_PROG_CC.
AC_DEFUN([_AM_DEPENDENCIES],
[AC_REQUIRE([AM_SET_DEPDIR])dnl
AC_REQUIRE([AM_OUTPUT_DEPENDENCY_COMMANDS])dnl
AC_REQUIRE([AM_MAKE_INCLUDE])dnl
AC_REQUIRE([AM_DEP_TRACK])dnl

ifelse([$1], CC,   [depcc="$CC"   am_compiler_list=],
       [$1], CXX,  [depcc="$CXX"  am_compiler_list=],
       [$1], OBJC, [depcc="$OBJC" am_compiler_list='gcc3 gcc'],
       [$1], GCJ,  [depcc="$GCJ"  am_compiler_list='gcc3 gcc'],
                   [depcc="$$1"   am_compiler_list=])

AC_CACHE_CHECK([dependency style of $depcc],
               [am_cv_$1_dependencies_compiler_type],
[if test -z "$AMDEP_TRUE" && test -f "$am_depcomp"; then
  # We make a subdir and do the tests there.  Otherwise we can end up
  # making bogus files that we don't know about and never remove.  For
  # instance it was reported that on HP-UX the gcc test will end up
  # making a dummy file named `D' -- because `-MD' means `put the output
  # in D'.
  mkdir conftest.dir
  # Copy depcomp to subdir because otherwise we won't find it if we're
  # using a relative directory.
  cp "$am_depcomp" conftest.dir
  cd conftest.dir
  # We will build objects and dependencies in a subdirectory because
  # it helps to detect inapplicable dependency modes.  For instance
  # both Tru64's cc and ICC support -MD to output dependencies as a
  # side effect of compilation, but ICC will put the dependencies in
  # the current directory while Tru64 will put them in the object
  # directory.
  mkdir sub

  am_cv_$1_dependencies_compiler_type=none
  if test "$am_compiler_list" = ""; then
     am_compiler_list=`sed -n ['s/^#*\([a-zA-Z0-9]*\))$/\1/p'] < ./depcomp`
  fi
  for depmode in $am_compiler_list; do
    # Setup a source with many dependencies, because some compilers
    # like to wrap large dependency lists on column 80 (with \), and
    # we should not choose a depcomp mode which is confused by this.
    #
    # We need to recreate these files for each test, as the compiler may
    # overwrite some of them when testing with obscure command lines.
    # This happens at least with the AIX C compiler.
    : > sub/conftest.c
    for i in 1 2 3 4 5 6; do
      echo '#include "conftst'$i'.h"' >> sub/conftest.c
      : > sub/conftst$i.h
    done
    echo "${am__include} ${am__quote}sub/conftest.Po${am__quote}" > confmf

    case $depmode in
    nosideeffect)
      # after this tag, mechanisms are not by side-effect, so they'll
      # only be used when explicitly requested
      if test "x$enable_dependency_tracking" = xyes; then
	continue
      else
	break
      fi
      ;;
    none) break ;;
    esac
    # We check with `-c' and `-o' for the sake of the "dashmstdout"
    # mode.  It turns out that the SunPro C++ compiler does not properly
    # handle `-M -o', and we need to detect this.
    if depmode=$depmode \
       source=sub/conftest.c object=sub/conftest.${OBJEXT-o} \
       depfile=sub/conftest.Po tmpdepfile=sub/conftest.TPo \
       $SHELL ./depcomp $depcc -c -o sub/conftest.${OBJEXT-o} sub/conftest.c \
         >/dev/null 2>conftest.err &&
       grep sub/conftst6.h sub/conftest.Po > /dev/null 2>&1 &&
       grep sub/conftest.${OBJEXT-o} sub/conftest.Po > /dev/null 2>&1 &&
       ${MAKE-make} -s -f confmf > /dev/null 2>&1; then
      # icc doesn't choke on unknown options, it will just issue warnings
      # (even with -Werror).  So we grep stderr for any message
      # that says an option was ignored.
      if grep 'ignoring option' conftest.err >/dev/null 2>&1; then :; else
        am_cv_$1_dependencies_compiler_type=$depmode
        break
      fi
    fi
  done

  cd ..
  rm -rf conftest.dir
else
  am_cv_$1_dependencies_compiler_type=none
fi
])
AC_SUBST([$1DEPMODE], [depmode=$am_cv_$1_dependencies_compiler_type])
AM_CONDITIONAL([am__fastdep$1], [
  test "x$enable_dependency_tracking" != xno \
  && test "$am_cv_$1_dependencies_compiler_type" = gcc3])
])


# AM_SET_DEPDIR
# -------------
# Choose a directory name for dependency files.
# This macro is AC_REQUIREd in _AM_DEPENDENCIES
AC_DEFUN([AM_SET_DEPDIR],
[AC_REQUIRE([AM_SET_LEADING_DOT])dnl
AC_SUBST([DEPDIR], ["${am__leading_dot}deps"])dnl
])


# AM_DEP_TRACK
# ------------
AC_DEFUN([AM_DEP_TRACK],
[AC_ARG_ENABLE(dependency-tracking,
[  --disable-dependency-tracking Speeds up one-time builds
  --enable-dependency-tracking  Do not reject slow dependency extractors])
if test "x$enable_dependency_tracking" != xno; then
  am_depcomp="$ac_aux_dir/depcomp"
  AMDEPBACKSLASH='\'
fi
AM_CONDITIONAL([AMDEP], [test "x$enable_dependency_tracking" != xno])
AC_SUBST([AMDEPBACKSLASH])
])

# Generate code to set up dependency tracking.   -*- Autoconf -*-

# Copyright 1999, 2000, 2001, 2002 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

#serial 2

# _AM_OUTPUT_DEPENDENCY_COMMANDS
# ------------------------------
AC_DEFUN([_AM_OUTPUT_DEPENDENCY_COMMANDS],
[for mf in $CONFIG_FILES; do
  # Strip MF so we end up with the name of the file.
  mf=`echo "$mf" | sed -e 's/:.*$//'`
  # Check whether this is an Automake generated Makefile or not.
  # We used to match only the files named `Makefile.in', but
  # some people rename them; so instead we look at the file content.
  # Grep'ing the first line is not enough: some people post-process
  # each Makefile.in and add a new line on top of each file to say so.
  # So let's grep whole file.
  if grep '^#.*generated by automake' $mf > /dev/null 2>&1; then
    dirpart=`AS_DIRNAME("$mf")`
  else
    continue
  fi
  grep '^DEP_FILES *= *[[^ @%:@]]' < "$mf" > /dev/null || continue
  # Extract the definition of DEP_FILES from the Makefile without
  # running `make'.
  DEPDIR=`sed -n -e '/^DEPDIR = / s///p' < "$mf"`
  test -z "$DEPDIR" && continue
  # When using ansi2knr, U may be empty or an underscore; expand it
  U=`sed -n -e '/^U = / s///p' < "$mf"`
  test -d "$dirpart/$DEPDIR" || mkdir "$dirpart/$DEPDIR"
  # We invoke sed twice because it is the simplest approach to
  # changing $(DEPDIR) to its actual value in the expansion.
  for file in `sed -n -e '
    /^DEP_FILES = .*\\\\$/ {
      s/^DEP_FILES = //
      :loop
	s/\\\\$//
	p
	n
	/\\\\$/ b loop
      p
    }
    /^DEP_FILES = / s/^DEP_FILES = //p' < "$mf" | \
       sed -e 's/\$(DEPDIR)/'"$DEPDIR"'/g' -e 's/\$U/'"$U"'/g'`; do
    # Make sure the directory exists.
    test -f "$dirpart/$file" && continue
    fdir=`AS_DIRNAME(["$file"])`
    AS_MKDIR_P([$dirpart/$fdir])
    # echo "creating $dirpart/$file"
    echo '# dummy' > "$dirpart/$file"
  done
done
])# _AM_OUTPUT_DEPENDENCY_COMMANDS


# AM_OUTPUT_DEPENDENCY_COMMANDS
# -----------------------------
# This macro should only be invoked once -- use via AC_REQUIRE.
#
# This code is only required when automatic dependency tracking
# is enabled.  FIXME.  This creates each `.P' file that we will
# need in order to bootstrap the dependency handling code.
AC_DEFUN([AM_OUTPUT_DEPENDENCY_COMMANDS],
[AC_CONFIG_COMMANDS([depfiles],
     [test x"$AMDEP_TRUE" != x"" || _AM_OUTPUT_DEPENDENCY_COMMANDS],
     [AMDEP_TRUE="$AMDEP_TRUE" ac_aux_dir="$ac_aux_dir"])
])

# Check to see how 'make' treats includes.	-*- Autoconf -*-

# Copyright (C) 2001, 2002, 2003 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 2

# AM_MAKE_INCLUDE()
# -----------------
# Check to see how make treats includes.
AC_DEFUN([AM_MAKE_INCLUDE],
[am_make=${MAKE-make}
cat > confinc << 'END'
am__doit:
	@echo done
.PHONY: am__doit
END
# If we don't find an include directive, just comment out the code.
AC_MSG_CHECKING([for style of include used by $am_make])
am__include="#"
am__quote=
_am_result=none
# First try GNU make style include.
echo "include confinc" > confmf
# We grep out `Entering directory' and `Leaving directory'
# messages which can occur if `w' ends up in MAKEFLAGS.
# In particular we don't look at `^make:' because GNU make might
# be invoked under some other name (usually "gmake"), in which
# case it prints its new name instead of `make'.
if test "`$am_make -s -f confmf 2> /dev/null | grep -v 'ing directory'`" = "done"; then
   am__include=include
   am__quote=
   _am_result=GNU
fi
# Now try BSD make style include.
if test "$am__include" = "#"; then
   echo '.include "confinc"' > confmf
   if test "`$am_make -s -f confmf 2> /dev/null`" = "done"; then
      am__include=.include
      am__quote="\""
      _am_result=BSD
   fi
fi
AC_SUBST([am__include])
AC_SUBST([am__quote])
AC_MSG_RESULT([$_am_result])
rm -f confinc confmf
])

#                                                          -*- Autoconf -*-
# Copyright (C) 2003  Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 1

# Check whether the underlying file-system supports filenames
# with a leading dot.  For instance MS-DOS doesn't.
AC_DEFUN([AM_SET_LEADING_DOT],
[rm -rf .tst 2>/dev/null
mkdir .tst 2>/dev/null
if test -d .tst; then
  am__leading_dot=.
else
  am__leading_dot=_
fi
rmdir .tst 2>/dev/null
AC_SUBST([am__leading_dot])])

# Do all the work for Automake.                            -*- Autoconf -*-

# This macro actually does too much some checks are only needed if
# your package does certain things.  But this isn't really a big deal.

# Copyright (C) 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003
# Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 10

AC_PREREQ([2.54])

# Autoconf 2.50 wants to disallow AM_ names.  We explicitly allow
# the ones we care about.
m4_pattern_allow([^AM_[A-Z]+FLAGS$])dnl

# AM_INIT_AUTOMAKE(PACKAGE, VERSION, [NO-DEFINE])
# AM_INIT_AUTOMAKE([OPTIONS])
# -----------------------------------------------
# The call with PACKAGE and VERSION arguments is the old style
# call (pre autoconf-2.50), which is being phased out.  PACKAGE
# and VERSION should now be passed to AC_INIT and removed from
# the call to AM_INIT_AUTOMAKE.
# We support both call styles for the transition.  After
# the next Automake release, Autoconf can make the AC_INIT
# arguments mandatory, and then we can depend on a new Autoconf
# release and drop the old call support.
AC_DEFUN([AM_INIT_AUTOMAKE],
[AC_REQUIRE([AM_SET_CURRENT_AUTOMAKE_VERSION])dnl
 AC_REQUIRE([AC_PROG_INSTALL])dnl
# test to see if srcdir already configured
if test "`cd $srcdir && pwd`" != "`pwd`" &&
   test -f $srcdir/config.status; then
  AC_MSG_ERROR([source directory already configured; run "make distclean" there first])
fi

# test whether we have cygpath
if test -z "$CYGPATH_W"; then
  if (cygpath --version) >/dev/null 2>/dev/null; then
    CYGPATH_W='cygpath -w'
  else
    CYGPATH_W=echo
  fi
fi
AC_SUBST([CYGPATH_W])

# Define the identity of the package.
dnl Distinguish between old-style and new-style calls.
m4_ifval([$2],
[m4_ifval([$3], [_AM_SET_OPTION([no-define])])dnl
 AC_SUBST([PACKAGE], [$1])dnl
 AC_SUBST([VERSION], [$2])],
[_AM_SET_OPTIONS([$1])dnl
 AC_SUBST([PACKAGE], ['AC_PACKAGE_TARNAME'])dnl
 AC_SUBST([VERSION], ['AC_PACKAGE_VERSION'])])dnl

_AM_IF_OPTION([no-define],,
[AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of package])
 AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version number of package])])dnl

# Some tools Automake needs.
AC_REQUIRE([AM_SANITY_CHECK])dnl
AC_REQUIRE([AC_ARG_PROGRAM])dnl
AM_MISSING_PROG(ACLOCAL, aclocal-${am__api_version})
AM_MISSING_PROG(AUTOCONF, autoconf)
AM_MISSING_PROG(AUTOMAKE, automake-${am__api_version})
AM_MISSING_PROG(AUTOHEADER, autoheader)
AM_MISSING_PROG(MAKEINFO, makeinfo)
AM_MISSING_PROG(AMTAR, tar)
AM_PROG_INSTALL_SH
AM_PROG_INSTALL_STRIP
# We need awk for the "check" target.  The system "awk" is bad on
# some platforms.
AC_REQUIRE([AC_PROG_AWK])dnl
AC_REQUIRE([AC_PROG_MAKE_SET])dnl
AC_REQUIRE([AM_SET_LEADING_DOT])dnl

_AM_IF_OPTION([no-dependencies],,
[AC_PROVIDE_IFELSE([AC_PROG_CC],
                  [_AM_DEPENDENCIES(CC)],
                  [define([AC_PROG_CC],
                          defn([AC_PROG_CC])[_AM_DEPENDENCIES(CC)])])dnl
AC_PROVIDE_IFELSE([AC_PROG_CXX],
                  [_AM_DEPENDENCIES(CXX)],
                  [define([AC_PROG_CXX],
                          defn([AC_PROG_CXX])[_AM_DEPENDENCIES(CXX)])])dnl
])
])


# When config.status generates a header, we must update the stamp-h file.
# This file resides in the same directory as the config header
# that is generated.  The stamp files are numbered to have different names.

# Autoconf calls _AC_AM_CONFIG_HEADER_HOOK (when defined) in the
# loop where config.status creates the headers, so we can generate
# our stamp files there.
AC_DEFUN([_AC_AM_CONFIG_HEADER_HOOK],
[# Compute $1's index in $config_headers.
_am_stamp_count=1
for _am_header in $config_headers :; do
  case $_am_header in
    $1 | $1:* )
      break ;;
    * )
      _am_stamp_count=`expr $_am_stamp_count + 1` ;;
  esac
done
echo "timestamp for $1" >`AS_DIRNAME([$1])`/stamp-h[]$_am_stamp_count])

# Copyright 2002  Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA

# AM_AUTOMAKE_VERSION(VERSION)
# ----------------------------
# Automake X.Y traces this macro to ensure aclocal.m4 has been
# generated from the m4 files accompanying Automake X.Y.
AC_DEFUN([AM_AUTOMAKE_VERSION],[am__api_version="1.7"])

# AM_SET_CURRENT_AUTOMAKE_VERSION
# -------------------------------
# Call AM_AUTOMAKE_VERSION so it can be traced.
# This function is AC_REQUIREd by AC_INIT_AUTOMAKE.
AC_DEFUN([AM_SET_CURRENT_AUTOMAKE_VERSION],
	 [AM_AUTOMAKE_VERSION([1.7.7])])

#
# Check to make sure that the build environment is sane.
#

# Copyright 1996, 1997, 2000, 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 3

# AM_SANITY_CHECK
# ---------------
AC_DEFUN([AM_SANITY_CHECK],
[AC_MSG_CHECKING([whether build environment is sane])
# Just in case
sleep 1
echo timestamp > conftest.file
# Do `set' in a subshell so we don't clobber the current shell's
# arguments.  Must try -L first in case configure is actually a
# symlink; some systems play weird games with the mod time of symlinks
# (eg FreeBSD returns the mod time of the symlink's containing
# directory).
if (
   set X `ls -Lt $srcdir/configure conftest.file 2> /dev/null`
   if test "$[*]" = "X"; then
      # -L didn't work.
      set X `ls -t $srcdir/configure conftest.file`
   fi
   rm -f conftest.file
   if test "$[*]" != "X $srcdir/configure conftest.file" \
      && test "$[*]" != "X conftest.file $srcdir/configure"; then

      # If neither matched, then we have a broken ls.  This can happen
      # if, for instance, CONFIG_SHELL is bash and it inherits a
      # broken ls alias from the environment.  This has actually
      # happened.  Such a system could not be considered "sane".
      AC_MSG_ERROR([ls -t appears to fail.  Make sure there is not a broken
alias in your environment])
   fi

   test "$[2]" = conftest.file
   )
then
   # Ok.
   :
else
   AC_MSG_ERROR([newly created file is older than distributed files!
Check your system clock])
fi
AC_MSG_RESULT(yes)])

#  -*- Autoconf -*-


# Copyright 1997, 1999, 2000, 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 3

# AM_MISSING_PROG(NAME, PROGRAM)
# ------------------------------
AC_DEFUN([AM_MISSING_PROG],
[AC_REQUIRE([AM_MISSING_HAS_RUN])
$1=${$1-"${am_missing_run}$2"}
AC_SUBST($1)])


# AM_MISSING_HAS_RUN
# ------------------
# Define MISSING if not defined so far and test if it supports --run.
# If it does, set am_missing_run to use it, otherwise, to nothing.
AC_DEFUN([AM_MISSING_HAS_RUN],
[AC_REQUIRE([AM_AUX_DIR_EXPAND])dnl
test x"${MISSING+set}" = xset || MISSING="\${SHELL} $am_aux_dir/missing"
# Use eval to expand $SHELL
if eval "$MISSING --run true"; then
  am_missing_run="$MISSING --run "
else
  am_missing_run=
  AC_MSG_WARN([`missing' script is too old or missing])
fi
])

# AM_AUX_DIR_EXPAND

# Copyright 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# For projects using AC_CONFIG_AUX_DIR([foo]), Autoconf sets
# $ac_aux_dir to `$srcdir/foo'.  In other projects, it is set to
# `$srcdir', `$srcdir/..', or `$srcdir/../..'.
#
# Of course, Automake must honor this variable whenever it calls a
# tool from the auxiliary directory.  The problem is that $srcdir (and
# therefore $ac_aux_dir as well) can be either absolute or relative,
# depending on how configure is run.  This is pretty annoying, since
# it makes $ac_aux_dir quite unusable in subdirectories: in the top
# source directory, any form will work fine, but in subdirectories a
# relative path needs to be adjusted first.
#
# $ac_aux_dir/missing
#    fails when called from a subdirectory if $ac_aux_dir is relative
# $top_srcdir/$ac_aux_dir/missing
#    fails if $ac_aux_dir is absolute,
#    fails when called from a subdirectory in a VPATH build with
#          a relative $ac_aux_dir
#
# The reason of the latter failure is that $top_srcdir and $ac_aux_dir
# are both prefixed by $srcdir.  In an in-source build this is usually
# harmless because $srcdir is `.', but things will broke when you
# start a VPATH build or use an absolute $srcdir.
#
# So we could use something similar to $top_srcdir/$ac_aux_dir/missing,
# iff we strip the leading $srcdir from $ac_aux_dir.  That would be:
#   am_aux_dir='\$(top_srcdir)/'`expr "$ac_aux_dir" : "$srcdir//*\(.*\)"`
# and then we would define $MISSING as
#   MISSING="\${SHELL} $am_aux_dir/missing"
# This will work as long as MISSING is not called from configure, because
# unfortunately $(top_srcdir) has no meaning in configure.
# However there are other variables, like CC, which are often used in
# configure, and could therefore not use this "fixed" $ac_aux_dir.
#
# Another solution, used here, is to always expand $ac_aux_dir to an
# absolute PATH.  The drawback is that using absolute paths prevent a
# configured tree to be moved without reconfiguration.

# Rely on autoconf to set up CDPATH properly.
AC_PREREQ([2.50])

AC_DEFUN([AM_AUX_DIR_EXPAND], [
# expand $ac_aux_dir to an absolute path
am_aux_dir=`cd $ac_aux_dir && pwd`
])

# AM_PROG_INSTALL_SH
# ------------------
# Define $install_sh.

# Copyright 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

AC_DEFUN([AM_PROG_INSTALL_SH],
[AC_REQUIRE([AM_AUX_DIR_EXPAND])dnl
install_sh=${install_sh-"$am_aux_dir/install-sh"}
AC_SUBST(install_sh)])

# AM_PROG_INSTALL_STRIP

# Copyright 2001 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# One issue with vendor `install' (even GNU) is that you can't
# specify the program used to strip binaries.  This is especially
# annoying in cross-compiling environments, where the build's strip
# is unlikely to handle the host's binaries.
# Fortunately install-sh will honor a STRIPPROG variable, so we
# always use install-sh in `make install-strip', and initialize
# STRIPPROG with the value of the STRIP variable (set by the user).
AC_DEFUN([AM_PROG_INSTALL_STRIP],
[AC_REQUIRE([AM_PROG_INSTALL_SH])dnl
# Installed binaries are usually stripped using `strip' when the user
# run `make install-strip'.  However `strip' might not be the right
# tool to use in cross-compilation environments, therefore Automake
# will honor the `STRIP' environment variable to overrule this program.
dnl Don't test for $cross_compiling = yes, because it might be `maybe'.
if test "$cross_compiling" != no; then
  AC_CHECK_TOOL([STRIP], [strip], :)
fi
INSTALL_STRIP_PROGRAM="\${SHELL} \$(install_sh) -c -s"
AC_SUBST([INSTALL_STRIP_PROGRAM])])

# Add --enable-maintainer-mode option to configure.
# From Jim Meyering

# Copyright 1996, 1998, 2000, 2001, 2002  Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 2

AC_DEFUN([AM_MAINTAINER_MODE],
[AC_MSG_CHECKING([whether to enable maintainer-specific portions of Makefiles])
  dnl maintainer-mode is disabled by default
  AC_ARG_ENABLE(maintainer-mode,
[  --enable-maintainer-mode enable make rules and dependencies not useful
                          (and sometimes confusing) to the casual installer],
      USE_MAINTAINER_MODE=$enableval,
      USE_MAINTAINER_MODE=no)
  AC_MSG_RESULT([$USE_MAINTAINER_MODE])
  AM_CONDITIONAL(MAINTAINER_MODE, [test $USE_MAINTAINER_MODE = yes])
  MAINT=$MAINTAINER_MODE_TRUE
  AC_SUBST(MAINT)dnl
]
)

AU_DEFUN([jm_MAINTAINER_MODE], [AM_MAINTAINER_MODE])

