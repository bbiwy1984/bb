#include <iv.h>
#include <stdio.h>
#include <stdbool.h>
#include <iv_event_raw.h>
#include <glib-object.h>
#include <gst/app/gstappsink.h>

#include <bb_av.h>
#include <bb_layer.h>
#include <bb_errors.h>

uint32_t av_init(struct av_data *avd, int src_type, int dst_type)
{
    gst_init(0, NULL);

    avd->src_type = src_type;
    avd->dst_type = dst_type;

    avd->decodebin = gst_element_factory_make("uridecodebin", "decodebin");
    if (avd->decodebin == NULL)
        return CANT_CREATE_ELEMENT;

    avd->convert = gst_element_factory_make("audioconvert", "convert");
    if (avd->convert == NULL)
        return CANT_CREATE_ELEMENT;

    avd->resample = gst_element_factory_make("audioresample", "resample");
    if (avd->resample == NULL)
        return CANT_CREATE_ELEMENT;

    avd->resample_caps = gst_element_factory_make("capsfilter", NULL);
    if (avd->resample_caps == NULL)
        return CANT_CREATE_ELEMENT;

    avd->queue = gst_element_factory_make("queue", "queue");
    if (avd->queue == NULL)
        return CANT_CREATE_ELEMENT;

    avd->adpcm = gst_element_factory_make("adpcmenc", "adpcm");
    if (avd->adpcm == NULL)
        return CANT_CREATE_ELEMENT;

    avd->adpcm_caps = gst_element_factory_make("capsfilter", NULL);
    if (avd->adpcm_caps == NULL)
        return CANT_CREATE_ELEMENT;

    if (dst_type == DEST_FILE)
        avd->sink = gst_element_factory_make("filesink", "sink");
    else if (dst_type == DEST_BUFFER)
        avd->sink = gst_element_factory_make("appsink", "sink");

    if (avd->sink == NULL)
        return CANT_CREATE_ELEMENT;

    avd->sink_caps = gst_element_factory_make("capsfilter", NULL);
    if (avd->sink_caps == NULL)
        return CANT_CREATE_ELEMENT;

    avd->pipeline = gst_pipeline_new("gstreamer-pipeline");
    if (avd->pipeline == NULL)
        return CANT_CREATE_PIPELINE;

    //link it all
    gst_bin_add_many(GST_BIN(avd->pipeline), avd->decodebin, 
        avd->convert, avd->resample, avd->resample_caps, avd->queue, avd->adpcm,
        avd->sink, NULL);

    if (!gst_element_link_many(avd->convert, avd->resample, 
        avd->resample_caps, avd->queue, avd->adpcm, avd->sink, 
        NULL))
    {
        fprintf(stderr, "bla\n");
        gst_object_unref(avd->pipeline);
        return CANT_LINK_ELEMENT;
    }
}

//code taken from gstreamer examples
static void pad_handler(GstElement *src, GstPad *new_pad, struct av_data *avd)
{
  GstPad *sink_pad = gst_element_get_static_pad (avd->convert, "sink");
  GstPadLinkReturn ret;
  GstCaps *new_pad_caps = NULL;
  GstStructure *new_pad_struct = NULL;
  const gchar *new_pad_type = NULL;

  /* If our converter is already linked, we have nothing to do here */
  if (gst_pad_is_linked (sink_pad)) {
    goto exit;
  }

  /* Check the new pad's type */
  new_pad_caps = gst_pad_get_current_caps (new_pad);
  new_pad_struct = gst_caps_get_structure (new_pad_caps, 0);
  new_pad_type = gst_structure_get_name (new_pad_struct);
  if (!g_str_has_prefix (new_pad_type, "audio/x-raw")) {
    goto exit;
  }

  /* Attempt the link */
  ret = gst_pad_link (new_pad, sink_pad);
  if (GST_PAD_LINK_FAILED (ret)) {
    g_print ("Type is '%s' but link failed.\n", new_pad_type);
  } 

exit:
  /* Unreference the new pad's caps, if we got them */
  if (new_pad_caps != NULL)
    gst_caps_unref (new_pad_caps);

  /* Unreference the sink pad */
  gst_object_unref (sink_pad);
}

int get_audio_frame(struct av_data *avd, char *buf, int len)
{
	GstMapInfo map;
    GstAppSink *sink;
    GstBuffer *buffer;
	GstSample* sample;

    if (GST_IS_APP_SINK(avd->sink) == FALSE)
        return -1;

    sink = GST_APP_SINK(avd->sink);
    sample = gst_app_sink_pull_sample(sink);
    buffer = gst_sample_get_buffer(sample);

    //and copy the data into buf
    gst_buffer_map(buffer, &map, GST_MAP_READ);
    if (map.size != len)
        return -1;

    memcpy(buf, map.data, len);
    gst_buffer_unmap(buffer, &map);
    gst_sample_unref(sample);
    
    return map.size;
}

void start_audio(void *object)
{
    int ret;
    GstBus *bus;
    GstState state;
    GstMessage *msg;
    gboolean terminate;

    struct doorbell *db;
    struct av_data *avd;

    db = (struct doorbell*)object;
    avd = db->avd;
    terminate = false;

    ret = gst_element_get_state(avd->pipeline, &state, NULL, 
        GST_CLOCK_TIME_NONE);

    //this is like "after linking"
    g_signal_connect(avd->decodebin, "pad-added", G_CALLBACK(pad_handler), avd);

    //set state to playing to show that we are ready
    ret = gst_element_set_state(avd->pipeline, GST_STATE_PLAYING);    
    if (ret == GST_STATE_CHANGE_FAILURE)
        return;
    
    bus = gst_element_get_bus(avd->pipeline);
    
    //we are almost done, we need to call this function here, because the
    //while loop below blocks this thread
    iv_event_raw_post(&(avd->audio_ready_ev));
    
    //terminate on error and eos
    do {
        msg = gst_bus_timed_pop_filtered(bus, GST_CLOCK_TIME_NONE, 
            GST_MESSAGE_STATE_CHANGED | GST_MESSAGE_ERROR | GST_MESSAGE_EOS);

        if (msg != NULL) {
            switch (GST_MESSAGE_TYPE (msg)) {
                case GST_MESSAGE_ERROR:
                case GST_MESSAGE_EOS:
                    terminate = true;
                    break;
            }
            gst_message_unref(msg);
        }
    } while (!terminate);

    //clean everything up
    gst_object_unref(bus);
    gst_element_set_state(avd->pipeline, GST_STATE_NULL);
    gst_object_unref(avd->pipeline);
}

