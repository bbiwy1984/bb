#ifndef BB_AV_H
#define BB_AV_H

#include <stdint.h>
#include <iv_event_raw.h>
#include <gst/gst.h>

#define SOURCE_FILE     0
#define SOURCE_OTHER    1
#define DEST_FILE       0
#define DEST_BUFFER     1

struct av_data
{
    int src_type;
    int dst_type;
    GstElement *source;
    GstElement *decodebin;
    GstElement *convert;
    GstElement *resample;
    GstElement *resample_caps;
    GstElement *queue;
    GstElement *adpcm;
    GstElement *adpcm_caps;
    GstElement *sink;
    GstElement *sink_caps;
    GstElement *pipeline;

    //should be changed in the future, this is not the right place
    struct iv_event_raw audio_ready_ev;
    struct iv_event_raw start_audio_ev;
};

uint32_t av_init(struct av_data *avd, int src_type, int dst_type);

static inline void av_set_input(struct av_data *avd, char *input)
{
    if (avd->src_type == SOURCE_FILE)
        g_object_set(avd->decodebin, "uri", input, NULL);
}

static inline void av_set_adpcm(struct av_data *avd, int blockalign, 
    char *layout)
{
    g_object_set(avd->adpcm, "blockalign", blockalign, NULL);
}

static inline void av_set_audio_filter(struct av_data *avd, int rate, 
    int channel)
{
    GstCaps *caps;

    caps = gst_caps_new_simple("audio/x-raw", 
                                "rate", G_TYPE_INT, rate,
                                "channels", G_TYPE_INT, channel,
                                NULL);
    g_object_set(avd->resample_caps, "caps", caps, NULL);
}

static inline void av_set_sink_caps(struct av_data *avd, int rate,
    int channel, char *layout, int block_align)
{
    GstCaps *caps;
    
    caps = gst_caps_new_simple("audio/x-raw",
                                "layout", G_TYPE_STRING, layout,
                                "block_align", G_TYPE_INT, block_align,
                                "channels", G_TYPE_INT, channel,
                                "rate", G_TYPE_INT, rate,
                                NULL);
    g_object_set(avd->sink_caps, "caps", caps, NULL);
}

void test(struct av_data *avd);
void start_audio(void *object);
int get_audio_frame(struct av_data *avd, char *buf, int len);

#endif
