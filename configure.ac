AC_INIT([BigBrother Surveillance],[0.1],[jornt@3vande8.nl])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AM_PROG_AR
LT_INIT
AC_PROG_CC
LT_INIT
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
 Makefile
 lib/Makefile
 src/Makefile
 util/Makefile
 tests/Makefile
])

#headers needed
AC_CHECK_HEADERS([hidapi/hidapi.h], [], [AC_MSG_ERROR([hidapi/hidapi.h not found])])
AC_CHECK_HEADERS([wolfssl/ssl.h], [], [AC_MSG_ERROR([wolfssl/ssl.h not found])])
AC_CHECK_HEADERS([iv.h], [], [AC_MSG_ERROR([iv.h not found])])
AC_CHECK_HEADERS([toml.h], [], [AC_MSG_ERROR([toml.h not found])])
AC_CHECK_HEADERS([mxml.h], [], [AC_MSG_ERROR([mxml.h not found])])
AC_CHECK_HEADERS([toml.h], [], [AC_MSG_ERROR([toml.h not found])])
AC_OUTPUT
