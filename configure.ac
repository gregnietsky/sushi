#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([sushi], [0.1], [gregnietsky@gmail.com])
AC_CONFIG_SRCDIR([src/sushi.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([ncurses], [initscr])
AC_CHECK_LIB([pam], [pam_start])
AC_CHECK_LIB([pthread], [pthread_create])
AC_CHECK_LIB([util], [forkpty])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h string.h sys/ioctl.h sys/time.h unistd.h utmp.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_PID_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_GETGROUPS
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strdup strndup])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
