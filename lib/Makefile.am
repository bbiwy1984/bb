AM_CPPFLAGS = -Wcpp -g `pkg-config --cflags-only-I gstreamer-1.0 ivykis gstreamer-1.0 gstreamer-app-1.0 ivykis hidapi-hidraw wolfssl mxml`
AM_LDFLAGS = `pkg-config --libs gstreamer-1.0 gstreamer-app-1.0 ivykis gstreamer-1.0 ivykis hidapi-hidraw wolfssl mxml`
AM_LDFLAGS += -ltoml 

lib_LTLIBRARIES = libbb.la 

SRC = bb_tcp.c bb_usb_relay.c bb_crypto.c bb_reolink.c bb_xml.c bb_av.c bb_config.c bb_wire.c
INC = bb_tcp.h bb_errors.h bb_usb_relay.h bb_reolink.h bb_crypto.h bb_xml.h bb_av.h bb_config.h bb_wire.h

libbb_la_SOURCES = $(SRC)
include_HEADERS = $(INC)
