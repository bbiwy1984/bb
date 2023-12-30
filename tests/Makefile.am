AM_CPPFLAGS	= -D_GNU_SOURCE			\
              -g                    \
			  -I$(top_srcdir)/lib	\
			  -I$(top_builddir)/lib \
              `pkg-config --cflags-only-I gstreamer-1.0 ivykis gstreamer-1.0 gstreamer-app-1.0 ivykis hidapi-hidraw wolfssl mxml`                   

LDADD			= $(top_builddir)/lib/libbb.la 

AM_LDFLAGS = `pkg-config --libs gstreamer-1.0 gstreamer-app-1.0 ivykis gstreamer-1.0 ivykis hidapi-hidraw wolfssl mxml` -ltoml

bin_PROGRAMS = test_conf #test_reo test_wire
test_conf_SOURCES = test_config.c 
#test_reo_SOURCES = test_reo.c
#test_wire_SOURCES = test_wire.c
