AM_CPPFLAGS	= -D_GNU_SOURCE			\
              -g                    \
              -I$(top_srcdir)/lib   \
              `pkg-config --cflags-only-I gstreamer-1.0 ivykis gstreamer-1.0 ivykis hidapi-hidraw wolfssl mxml gstreamer-app-1.0`
LDADD			= $(top_builddir)/lib/libbb.la 

AM_LDFLAGS = `pkg-config --libs ivykis gstreamer-1.0 ivykis hidapi-hidraw wolfssl mxml gstreamer-app-1.0` -ltoml

bin_PROGRAMS = bb
bb_SOURCES = bb.c


