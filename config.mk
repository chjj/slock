# slock version
VERSION = 0.8

# Customize below to fit your system

# paths
PREFIX = /usr/local

X11INC = /usr/X11R6/include
X11LIB = /usr/X11R6/lib

# includes and libs
INCS = -I. -I/usr/include -I${X11INC}
LIBS = -L/usr/lib -lc -lcrypt -L${X11LIB} -lX11

# flags
CFLAGS = -Os ${INCS} -DVERSION=\"${VERSION}\" -DHAVE_SHADOW_H
LDFLAGS = ${LIBS}
#CFLAGS = -g -Wall -O2 ${INCS} -DVERSION=\"${VERSION}\" -DHAVE_SHADOW_H
#LDFLAGS = -g ${LIBS}

# On *BSD remove -DHAVE_SHADOW_H from CFLAGS
# On OpenBSD and Darwin remove -lcrypt from LIBS

# compiler and linker
CC = cc
LD = ${CC}
