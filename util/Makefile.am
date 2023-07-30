AM_CPPFLAGS	= -D_GNU_SOURCE			\
			  -I$(top_srcdir)/lib	\
			  -I$(top_builddir)/lib \
              -g

LDADD			= $(top_builddir)/lib/libbb.la 

AM_LDFLAGS = -lhidapi-hidraw -livykis

bin_PROGRAMS = usb_relay_util 
usb_relay_util_SOURCES = usb_relay_util.c

