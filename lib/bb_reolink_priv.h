#ifndef BB_REOLINK_PRIV_H
#define BB_REOLINK_PRIV_H

#include <bb_fsm.h>
#include <bb_reolink.h>

//protocol related defines
#define HEADER_MAGIC                0xf0, 0xde, 0xbc, 0x0a

#define LEGACY_LOGIN_MSG_ID         0x01, 0x00, 0x00, 0x00
#define MODERN_LOGIN_MSG_ID         0x01, 0x00, 0x00, 0x00
#define PING_MSG_ID                 0x5d, 0x00, 0x00, 0x00
#define TALK_ABILITY_MSG_ID         0x0a, 0x00, 0x00, 0x00
#define TALK_CONFIG_MSG_ID          0xc9, 0x00, 0x00, 0x00
#define TALK_MSG_ID                 0xca, 0x00, 0x00, 0x00
#define ALARM_EVENT_LIST_MSG_ID     0x21, 0x00, 0x00, 0x00

#define LEGACY_LOGIN_MSG_LEN        0x2c, 0x07, 0x00, 0x00, 0x00
#define MODERN_LOGIN_MSG_LEN        0x28, 0x01, 0x00, 0x00
#define PING_MSG_LEN                0x00, 0x00, 0x00, 0x00
#define EMPTY_MSG_LEN               0x00, 0x00, 0x00, 0x00

#define ADPCM_MAGIC_1               0x30, 0x31, 0x77, 0x62
#define ADPCM_PAYLOAD_LEN           0x00, 0x00
#define ADPCM_PAYLOAD_LEN_OFFSET    2
#define ADPCM_PAYLOAD_LEN_DEC       2
#define ADPCM_MAGIC_2               0x00, 0x01
#define ENC_SYNC_OFFSET             14
#define DVI_BLOCK_SIZE              0x00, 0x01
#define DVI_BLOCK_SIZE_DEC          516

#define LEGACY_ENC_OFFSET           0x00, 0x00, 0x00, 0x00
#define LEGACY_ENC_MODE             0x00, 0x00, 0x00, 0x02
#define MODERN_ENC_OFFSET           0x00, 0x00, 0x01, 0x00
#define TALK_ENC_OFFSET             0x00, 0x00, 0x01, 0x00
#define MODERN_STAT_CODE_REQ        0x00, 0x00
#define MODERN_STAT_CODE_REP        0xc8, 0x00
#define TALK_CONFIG_STAT_CODE_REP   0x00, 0x00
#define ALARM_ENC_OFFSET            0x00, 0x00, 0x00, 0x00
#define ENC_MODE_AES                0x02
#define LEGACY_UNKNOWN              0xdc
#define LEGACY_UNKNOWN_REP          0xdd

#define LEGACY_MSG_CLASS_REQ        0x14, 0x65
#define MODERN_MSG_CLASS_REQ        0x14, 0x64
#define LEGACY_MSG_CLASS_REP        0x14, 0x66
#define MODERN_MSG_CLASS_REP        0x00, 0x00
#define MODERN_PAYLOAD_OFFSET       0x00, 0x00, 0x00, 0x00

#define LEGACY_HEADER_SIZE          sizeof(login_header)

#define SLEEP_TIME                  60859370

//internal crypto related stuff
#define REO_XOR_KEY                 0x1f, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0xff
#define REO_IV                      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66

//length defines
#define REO_MD5_LEN                 (WC_MD5_DIGEST_SIZE - 1)
#define USER_PASS_MAX_LEN           128
#define ODD_LEGACY_LOGIN_LEN        0x740
#define LEN_OFFSET                  8
#define PAYLOAD_OFFSET              20
#define MODERN_HEADER_SIZE          24
#define MAGIC_LEN                   4
#define MESSAGE_ID_OFFSET           4
#define PAYLOAD_OFF_SIZE            4
#define PAYLOAD_LEN                 4
#define MSG_CLASS_LEN               4
#define MSG_ID_LEN                  4
#define ENC_OFFSET_LEN              4
#define STATUS_CODE_LEN             2
#define LEGACY_MSG_CLASS_REP_LEN    2 
#define PAYLOAD_LEN_OFFSET          8
#define PAYLOAD_LEN_SIZE            4

//state machine related defines we use these numbers for bitwise operations
//this way we can easily see if we can switch to a state or not
#define ST_ID_LED_STATE_WRITE                   0x4000000000000
#define ST_ID_LED_STATE                         0x2000000000000
#define ST_ID_UNKNOWN                           0x1000000000000
#define ST_ID_ABILITY_INFO                      0x800000000000
#define ST_ID_ABILITY_SUPPORT                   0x400000000000 
#define ST_ID_ALARM_EVENT_LIST                  0x200000000000 
#define ST_ID_AUDIO_CFG_WRITE                   0x100000000000
#define ST_ID_COMPRESSION                       0x80000000000 
#define ST_ID_COMPRESSION_WRITE                 0x40000000000 
#define ST_ID_CONFIG_FILE_INFO                  0x20000000000 
#define ST_ID_FLOOD_LIGHT_MANUAL                0x10000000000 
#define ST_ID_FLOOD_LIGHT_TASK_READ             0x8000000000 
#define ST_ID_FLOOD_LIGHT_TASK_READ_EXTENDED    0x4000000000 
#define ST_ID_FLOOD_LIGHT_TASK_WRITE            0x2000000000 
#define ST_ID_HDD_INFO_LIST                     0x1000000000 
#define ST_ID_IP                                0x800000000 
#define ST_ID_IP_WRITE                          0x400000000 
#define ST_ID_LEGACY_LOGIN                      0x200000000 
#define ST_ID_LINK_TYPE                         0x100000000 
#define ST_ID_LOGOUT                            0x80000000 
#define ST_ID_MODERN_LOGIN                      0x40000000 
#define ST_ID_OSD_CHANNEL_NAME                  0x20000000 
#define ST_ID_OSD_CHANNEL_NAME_WRITE            0x10000000 
#define ST_ID_PTZ_CONTROL                       0x8000000 
#define ST_ID_PTZ_PRESET                        0x4000000 
#define ST_ID_REBOOT                            0x2000000 
#define ST_ID_RECORD                            0x1000000 
#define ST_ID_RECORD_CFG                        0x800000 
#define ST_ID_RECORD_CFG_WRITE                  0x400000 
#define ST_ID_RECORD_WRITE                      0x200000 
#define ST_ID_RF_ALARM                          0x100000 
#define ST_ID_RF_ALARM_CFG                      0x80000 
#define ST_ID_SERIAL                            0x40000 
#define ST_ID_SHELTER_BASIC                     0x20000 
#define ST_ID_SHELTER_EXTENDED                  0x10000 
#define ST_ID_START_MOTION_ALARM                0x8000 
#define ST_ID_STOP_REVIEW                       0x4000 
#define ST_ID_STREAM                            0x2000 
#define ST_ID_STREAM_INFO_LIST                  0x1000 
#define ST_ID_SUPPORT                           0x800 
#define ST_ID_SYSTEM_GENERAL                    0x400 
#define ST_ID_TALK                              0x200 
#define ST_ID_TALK_ABILITY                      0x100 
#define ST_ID_TALK_CONFIG                       0x80 
#define ST_ID_VERSION_INFO                      0x40
#define ST_ID_VIDEO_INPUT                       0x20
#define ST_ID_VIDEO_INPUT_NEW                   0x10
#define ST_ID_VIDEO_INPUT_EXTENDED              0x8
#define ST_ID_VIDEO_INPUT_WRITE                 0x2 
#define ST_ID_WIFI_SIGNAL                       0x1 
#define ST_ID_NOT_SUPPORTED                     0x0 

//yes yes yes we can use enum here as well, but for clarity we don't
#define ST_NOT_SUPPORTED                  0
#define ST_WIFI_SIGNAL                    1
#define ST_VIDEO_INPUT_WRITE              2
#define ST_VIDEO_INPUT_EXTENDED           3
#define ST_VIDEO_INPUT_NEW                4
#define ST_VIDEO_INPUT                    5
#define ST_VERSION_INFO                   6
#define ST_TALK_CONFIG                    7
#define ST_TALK_ABILITY                   8
#define ST_TALK                           9
#define ST_SYSTEM_GENERAL                 10
#define ST_SUPPORT                        11
#define ST_STREAM_INFO_LIST               12
#define ST_STREAM                         13
#define ST_STOP_PREVIEW                   14
#define ST_START_MOTION_ALARM             15
#define ST_SHELTER_EXTENDED               16
#define ST_SHELTER_BASIC                  17
#define ST_SERIAL                         18
#define ST_RF_ALARM_CFG                   19
#define ST_RF_ALARM                       20
#define ST_RECORD_WRITE                   21
#define ST_RECORD_CFG_WRITE               22
#define ST_RECORD_CFG                     23
#define ST_RECORD                         24
#define ST_REBOOT                         25
#define ST_PTZ_PRESET                     26
#define ST_PTZ_CONTROL                    27
#define ST_OSD_CHANNEL_NAME_WRITE         28
#define ST_OSD_CHANNEL_NAME               29
#define ST_MODERN_LOGIN                   30
#define ST_LOGOUT                         31
#define ST_LINK_TYPE                      32
#define ST_LEGACY_LOGIN                   33
#define ST_IP_WRITE                       34
#define ST_IP                             35
#define ST_HDD_INFO_LIST                  36
#define ST_FLOOD_LIGHT_TASK_WRITE         37
#define ST_FLOOD_LIGHT_TASK_READ_EXTENDED 38
#define ST_FLOOD_LIGHT_TASK_READ          39
#define ST_FLOOD_LIGHT_MANUAL             40
#define ST_CONFIG_FILE_INFO               41
#define ST_COMPRESSION_WRITE              42
#define ST_COMPRESSION                    43
#define ST_AUDIO_CFG_WRITE                44
#define ST_ALARM_EVENT_LIST               45
#define ST_ABILITY_SUPPORT                46
#define ST_ABILITY_INFO                   47
#define ST_UNKNOWN                        48
#define ST_LED_STATE                      49
#define ST_LED_STATE_WRITE                50

#define REO_XML_NONCE        "nonce"
#define REO_XML_USER         "userName"
#define REO_XML_PASS         "password"
#define REO_XML_STATUS       "status"
#define REO_XML_AI_TYPE      "AItype"

#define REO_MODERN_LOGIN_XML "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" \
                             "<body>\n" \
                             "<LoginUser version=\"1.1\">\n" \
                             "<userName>x</userName>\n" \
                             "<password>x</password>\n" \
                             "<userVer>1</userVer>\n" \
                             "</LoginUser>\n" \
                             "<LoginNet version=\"1.1\">\n" \
                             "<type>LAN</type>\n" \
                             "<udpPort>0</udpPort>\n" \
                             "</LoginNet>\n" \
                             "</body>\n"

#define REO_TALK_ABILITY     "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" \
                             "<Extension version=\"1.1\">\n" \
                             "<channelId>0</channelId>\n" \
                             "</Extension>\n"

#define REO_TALK_CONFIG_BODY "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" \
                             "<Extension version=\"1.1\">\n" \
                             "<channelId>0</channelId>\n" \
                             "</Extension>\n"

#define REO_TALK_CONFIG_BIN  "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" \
                             "<body>\n" \
                             "<TalkConfig version=\"\">\n" \
                             "<channelId>0</channelId>\n" \
                             "<duplex>FDX</duplex>\n" \
                             "<audioStreamMode>followVideoStream" \
                             "</audioStreamMode>\n" \
                             "<audioConfig>\n" \
                             "<priority>0</priority>\n" \
                             "<audioType>adpcm</audioType>\n" \
                             "<sampleRate>16000</sampleRate>\n" \
                             "<samplePrecision>16</samplePrecision>\n" \
                             "<lengthPerEncoder>1024</lengthPerEncoder>\n" \
                             "<soundTrack>mono</soundTrack>\n" \
                             "</audioConfig>\n" \
                             "</TalkConfig>\n" \
                             "</body>\n" 

#define REO_TALK             "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n" \
                             "<Extension version=\"1.1\">\n" \
                             "<binaryData>1</binaryData>\n" \
                             "<channelId>0</channelId>\n" \
                             "</Extension>\n"

static char login_header[]             = { HEADER_MAGIC, 
    LEGACY_LOGIN_MSG_ID, LEGACY_LOGIN_MSG_LEN, LEGACY_ENC_MODE, 
    LEGACY_UNKNOWN, LEGACY_MSG_CLASS_REQ };

static char login_modern_header[]      = { HEADER_MAGIC,
    MODERN_LOGIN_MSG_ID, MODERN_LOGIN_MSG_LEN, MODERN_ENC_OFFSET,
    MODERN_STAT_CODE_REQ, MODERN_MSG_CLASS_REQ, MODERN_PAYLOAD_OFFSET };

static char ping_header[]              = { HEADER_MAGIC,
    PING_MSG_ID, EMPTY_MSG_LEN, MODERN_ENC_OFFSET, MODERN_STAT_CODE_REQ,
    MODERN_MSG_CLASS_REQ, MODERN_PAYLOAD_OFFSET };

static char talk_ability_header[]      = { HEADER_MAGIC,
    TALK_ABILITY_MSG_ID, EMPTY_MSG_LEN, MODERN_ENC_OFFSET, MODERN_STAT_CODE_REQ,
    MODERN_MSG_CLASS_REQ, MODERN_PAYLOAD_OFFSET };

static char talk_config_header[]      = { HEADER_MAGIC,
    TALK_CONFIG_MSG_ID, EMPTY_MSG_LEN, MODERN_ENC_OFFSET, MODERN_STAT_CODE_REQ,
    MODERN_MSG_CLASS_REQ, MODERN_PAYLOAD_OFFSET };

static char talk_header[]             = { HEADER_MAGIC,
    TALK_MSG_ID, EMPTY_MSG_LEN, TALK_ENC_OFFSET, MODERN_STAT_CODE_REQ,
    MODERN_MSG_CLASS_REQ, MODERN_PAYLOAD_OFFSET };

static char adpcm_header[]            = { ADPCM_MAGIC_1, ADPCM_PAYLOAD_LEN, 
    ADPCM_PAYLOAD_LEN, ADPCM_MAGIC_2, DVI_BLOCK_SIZE };

static char talk_enc_offset[]          = {TALK_ENC_OFFSET}; 
static char reo_xor_key[]              = {REO_XOR_KEY};
static char header_magic[]             = {HEADER_MAGIC};
static char legacy_login_msg_id[]      = {LEGACY_LOGIN_MSG_ID};
static char legacy_enc_offset[]        = {LEGACY_ENC_OFFSET};
static char enc_mode_aes[]             = {ENC_MODE_AES};
static char legacy_unknown_rep[]       = {LEGACY_UNKNOWN_REP};
static char legacy_msg_class_rep[]     = {LEGACY_MSG_CLASS_REP};
static char modern_login_msg_id[]      = {MODERN_LOGIN_MSG_ID};
static char modern_login_msg_len[]     = {MODERN_LOGIN_MSG_LEN};
static char modern_payload_offset[]    = {MODERN_PAYLOAD_OFFSET};
static char modern_msg_class_req[]     = {MODERN_MSG_CLASS_REQ};
static char modern_msg_class_rep[]     = {MODERN_MSG_CLASS_REP};
static char modern_enc_offset[]        = {MODERN_ENC_OFFSET};
static char modern_stat_code_rep[]     = {MODERN_STAT_CODE_REP};
static char ping_msg_id[]              = {PING_MSG_ID};
static char talk_ability_msg_id[]      = {TALK_ABILITY_MSG_ID};
static char talk_config_msg_id[]       = {TALK_CONFIG_MSG_ID};
static char talk_config_stat_code_rep[]= {TALK_CONFIG_STAT_CODE_REP};
static char talk_msg_id[]              = {TALK_MSG_ID};
static char alarm_event_list_msg_id[]  = {ALARM_EVENT_LIST_MSG_ID};
static char alarm_enc_offset[]         = {ALARM_ENC_OFFSET};
static char talk_ability[]             = {REO_TALK_ABILITY};
static char reo_iv[]                   = {REO_IV};

struct reo_priv 
{
    __uint128_t state;
    uint8_t enc_offset;
    char *nonce;
    char key[17];

    struct reo_session *rs;

    struct iv_avl_node an;
    struct iv_timer ping_timeout;
    struct iv_timer talk_timeout;
    struct iv_timer alarm_timeout;
};

static void alarm_event_list_read(struct bb_message_channel *bbmc);

static void legacy_login_write(struct bb_message_channel *bbmc);
static void legacy_login_read(struct bb_message_channel *bbmc);

static void modern_login_write(struct bb_message_channel *bbmc);
static void modern_login_read(struct bb_message_channel *bbmc);

static void talk_ability_write(struct bb_message_channel *bbmc);
static void talk_ability_read(struct bb_message_channel *bbmc);

static void talk_config_write(struct bb_message_channel *bbmc);
static void talk_config_read(struct bb_message_channel *bbmc);

static void talk_write(struct bb_message_channel *bbmc);
static void talk_read(struct bb_message_channel *bbmc);

static void not_supported_read(struct bb_message_channel *bbmc);
static void not_supported_write(struct bb_message_channel *bbmc);

static void not_implemented_read(struct bb_message_channel *bbmc);
static void not_implemented_write(struct bb_message_channel *bbmc);

static struct state_fp st_talk =
{
    .st_read = talk_read,
    .st_write = talk_write
};

static struct state_fp st_talk_ability =
{
    .st_read = talk_ability_read,
    .st_write = talk_ability_write
};

static struct state_fp st_talk_config =
{
    .st_read = talk_config_read,
    .st_write = talk_config_write
};

static struct state_fp st_modern_login =
{
    .st_read = modern_login_read,
    .st_write = modern_login_write
};

static struct state_fp st_legacy_login =
{
    .st_read = legacy_login_read,
    .st_write = legacy_login_write
};

static struct state_fp st_not_implemented = 
{
    .st_read = not_implemented_read,
    .st_write = not_implemented_write
};

static struct state_fp st_not_supported =
{
    .st_read = not_supported_read,
    .st_write = not_supported_write
};

static struct state_fp st_alarm_event_list = 
{
    .st_read = alarm_event_list_read,
    .st_write = not_supported_write
};

static struct state_fp *st_fp_table[] = 
{
    /*ST_NOT_SUPPORTED                  */  &st_not_supported,
    /*ST_WIFI_SIGNAL                    */  &st_not_implemented,
    /*ST_VIDEO_INPUT_WRITE              */  &st_not_implemented,
    /*ST_VIDEO_INPUT_EXTENDED           */  &st_not_implemented,
    /*ST_VIDEO_INPUT_NEW                */  &st_not_implemented,
    /*ST_VIDEO_INPUT                    */  &st_not_implemented,
    /*ST_VERSION_INFO                   */  &st_not_implemented,
    /*ST_TALK_CONFIG                    */  &st_talk_config,
    /*ST_TALK_ABILITY                   */  &st_talk_ability,
    /*ST_TALK                           */  &st_talk,
    /*ST_SYSTEM_GENERAL                 */  &st_not_implemented,
    /*ST_SUPPORT                        */  &st_not_implemented,
    /*ST_STREAM_INFO_LIST               */  &st_not_implemented,
    /*ST_STREAM                         */  &st_not_implemented,
    /*ST_STOP_REVIEW                    */  &st_not_implemented,
    /*ST_START_MOTION_ALARM             */  &st_not_implemented,
    /*ST_SHELTER_EXTENDED               */  &st_not_implemented,
    /*ST_SHELTER_BASIC                  */  &st_not_implemented,
    /*ST_SERIAL                         */  &st_not_implemented,
    /*ST_RF_ALARM_CFG                   */  &st_not_implemented,
    /*ST_RF_ALARM                       */  &st_not_implemented,
    /*ST_RECORD_WRITE                   */  &st_not_implemented,
    /*ST_RECORD_CFG_WRITE               */  &st_not_implemented,
    /*ST_RECORD_CFG                     */  &st_not_implemented,
    /*ST_RECORD                         */  &st_not_implemented,
    /*ST_REBOOT                         */  &st_not_implemented,
    /*ST_PTZ_PRESET                     */  &st_not_implemented,
    /*ST_PTZ_CONTROL                    */  &st_not_implemented,
    /*ST_OSD_CHANNEL_NAME_WRITE         */  &st_not_implemented,
    /*ST_OSD_CHANNEL_NAME               */  &st_not_implemented,
    /*ST_MODERN_LOGIN                   */  &st_modern_login,
    /*ST_LOGOUT                         */  &st_not_implemented,
    /*ST_LINK_TYPE                      */  &st_not_implemented,
    /*ST_LEGACY_LOGIN                   */  &st_legacy_login,
    /*ST_IP_WRITE                       */  &st_not_implemented,
    /*ST_IP                             */  &st_not_implemented,
    /*ST_HDD_INFO_LIST                  */  &st_not_implemented,
    /*ST_FLOOD_LIGHT_TASK_WRITE         */  &st_not_implemented,
    /*ST_FLOOD_LIGHT_TASK_READ_EXTENDED */  &st_not_implemented,
    /*ST_FLOOD_LIGHT_TASK_READ          */  &st_not_implemented,
    /*ST_FLOOD_LIGHT_MANUAL             */  &st_not_implemented,
    /*ST_CONFIG_FILE_INFO               */  &st_not_implemented,
    /*ST_COMPRESSION_WRITE              */  &st_not_implemented,
    /*ST_COMPRESSION                    */  &st_not_implemented,
    /*ST_AUDIO_CFG_WRITE                */  &st_not_implemented,
    /*ST_ALARM_EVENT_LIST               */  &st_alarm_event_list,
    /*ST_ABILITY_SUPPORT                */  &st_not_implemented,
    /*ST_ABILITY_INFO                   */  &st_not_implemented,
    /*ST_UNKNOWN                        */  &st_not_implemented,
    /*ST_LED_STATE                      */  &st_not_implemented,
    /*ST_LED_STATE_WRITE                */  &st_not_implemented
};

//given a state, we can lookup the corresponding state id
//the state id can be used to determin if we are "in" this state 
static __uint128_t state_to_state_id[] =
{
    ST_ID_NOT_SUPPORTED,
    ST_ID_WIFI_SIGNAL,
    ST_ID_VIDEO_INPUT_WRITE,
    ST_ID_VIDEO_INPUT_EXTENDED,
    ST_ID_VIDEO_INPUT_NEW,
    ST_ID_VIDEO_INPUT,
    ST_ID_VERSION_INFO,
    ST_ID_TALK_CONFIG,
    ST_ID_TALK_ABILITY,
    ST_ID_TALK,
    ST_ID_SYSTEM_GENERAL,
    ST_ID_SUPPORT,
    ST_ID_STREAM_INFO_LIST,
    ST_ID_STREAM,
    ST_ID_STOP_REVIEW,
    ST_ID_START_MOTION_ALARM,
    ST_ID_SHELTER_EXTENDED,
    ST_ID_SHELTER_BASIC,
    ST_ID_SERIAL,
    ST_ID_RF_ALARM_CFG,
    ST_ID_RF_ALARM,
    ST_ID_RECORD_WRITE,
    ST_ID_RECORD_CFG_WRITE,
    ST_ID_RECORD_CFG,
    ST_ID_RECORD,
    ST_ID_REBOOT,
    ST_ID_PTZ_PRESET,
    ST_ID_PTZ_CONTROL,
    ST_ID_OSD_CHANNEL_NAME_WRITE,
    ST_ID_OSD_CHANNEL_NAME,
    ST_ID_MODERN_LOGIN,
    ST_ID_LOGOUT,
    ST_ID_LINK_TYPE,
    ST_ID_LEGACY_LOGIN,
    ST_ID_IP_WRITE,
    ST_ID_IP,
    ST_ID_HDD_INFO_LIST,
    ST_ID_FLOOD_LIGHT_TASK_WRITE,
    ST_ID_FLOOD_LIGHT_TASK_READ_EXTENDED,
    ST_ID_FLOOD_LIGHT_TASK_READ,
    ST_ID_FLOOD_LIGHT_MANUAL,
    ST_ID_CONFIG_FILE_INFO,
    ST_ID_COMPRESSION_WRITE,
    ST_ID_COMPRESSION,
    ST_ID_AUDIO_CFG_WRITE,
    ST_ID_ALARM_EVENT_LIST,
    ST_ID_ABILITY_SUPPORT,
    ST_ID_ABILITY_INFO,
    ST_ID_UNKNOWN,
    ST_ID_LED_STATE,
    ST_ID_LED_STATE_WRITE
};

static uint32_t state_msg_id[] =
{
    /*ST_NOT_SUPPORTED                  0*/     0x00000000,
    /*ST_WIFI_SIGNAL                    1*/     0x00000073,
    /*ST_VIDEO_INPUT_WRITE              2*/     0x00000019,
    /*ST_VIDEO_INPUT_EXTENDED           3*/     0x0000004E,
    /*ST_VIDEO_INPUT_NEW                4*/     0x00000084,
    /*ST_VIDEO_INPUT                    5*/     0x0000001A,
    /*ST_VERSION_INFO                   6*/     0x00000050,
    /*ST_TALK_CONFIG                    7*/     0x000000C9,
    /*ST_TALK_ABILITY                   8*/     0x0000000A,
    /*ST_TALK                           9*/     0x000000CA,
    /*ST_SYSTEM_GENERAL                 10*/    0x00000068,
    /*ST_SUPPORT                        11*/    0x000000C7,
    /*ST_STREAM_INFO_LIST               12*/    0x00000092,
    /*ST_STREAM                         13*/    0x00000003,
    /*ST_STOP_REVIEW                    14*/    0x00000004,
    /*ST_START_MOTION_ALARM             15*/    0x0000001F,
    /*ST_SHELTER_EXTENDED               16*/    0x00000035,
    /*ST_SHELTER_BASIC                  17*/    0x00000034,
    /*ST_SERIAL                         18*/    0x0000004F,
    /*ST_RF_ALARM_CFG                   19*/    0x000000CC,
    /*ST_RF_ALARM                       20*/    0x00000085,
    /*ST_RECORD_WRITE                   21*/    0x00000052,
    /*ST_RECORD_CFG_WRITE               22*/    0x00000037,
    /*ST_RECORD_CFG                     23*/    0x00000036,
    /*ST_RECORD                         24*/    0x00000051,
    /*ST_REBOOT                         25*/    0x00000017,
    /*ST_PTZ_PRESET                     26*/    0x000000BE,
    /*ST_PTZ_CONTROL                    27*/    0x00000012,
    /*ST_OSD_CHANNEL_NAME_WRITE         28*/    0x0000002D,
    /*ST_OSD_CHANNEL_NAME               29*/    0x0000002C,
    /*ST_MODERN_LOGIN                   30*/    0x00000001,
    /*ST_LOGOUT                         31*/    0x00000002,
    /*ST_LINK_TYPE                      32*/    0x0000005D,
    /*ST_LEGACY_LOGIN                   33*/    0x00000001,
    /*ST_IP_WRITE                       34*/    0x0000004D,
    /*ST_IP                             35*/    0x0000004C,
    /*ST_HDD_INFO_LIST                  36*/    0x00000066,
    /*ST_FLOOD_LIGHT_TASK_WRITE         37*/    0x00000122,
    /*ST_FLOOD_LIGHT_TASK_READ_EXTENDED 38*/    0x000001B6,
    /*ST_FLOOD_LIGHT_TASK_READ          39*/    0x00000123,
    /*ST_FLOOD_LIGHT_MANUAL             40*/    0x00000120,
    /*ST_CONFIG_FILE_INFO               41*/    0x00000043,
    /*ST_COMPRESSION_WRITE              42*/    0x00000039,
    /*ST_COMPRESSION                    43*/    0x00000038,
    /*ST_AUDIO_CFG_WRITE                44*/    0x00000108,
    /*ST_ALARM_EVENT_LIST               45*/    0x00000021,
    /*ST_ABILITY_SUPPORT                46*/    0x0000003A,
    /*ST_ABILITY_INFO                   47*/    0x000000A7,
    /*ST_UNKNOWN                        48*/    0x000000C0,
    /*ST_LED_STATE                      49*/    0x000000D0,
    /*ST_LED_STATE_WRITE                50*/    0x000000D1
};

//this table corresponds to message ids, we can easily lookup a state id here
//the state id can then be used to check if we are actually "in" this state
//by using bitwise operations 
static uint32_t msg_id_to_state[] = 
{
    /* 0x00 */ ST_NOT_SUPPORTED,
    /* 0x01 */ ST_LEGACY_LOGIN,
    /* 0x02 */ ST_LOGOUT,
    /* 0x03 */ ST_STREAM,
    /* 0x04 */ ST_STOP_PREVIEW,
    /* 0x05 */ ST_NOT_SUPPORTED,
    /* 0x06 */ ST_NOT_SUPPORTED,
    /* 0x07 */ ST_NOT_SUPPORTED,
    /* 0x08 */ ST_AUDIO_CFG_WRITE,
    /* 0x09 */ ST_NOT_SUPPORTED,
    /* 0x0A */ ST_TALK_ABILITY,
    /* 0x0B */ ST_TALK_ABILITY,
    /* 0x0C */ ST_TALK_ABILITY,
    /* 0x0D */ ST_TALK_ABILITY,
    /* 0x0E */ ST_TALK_ABILITY,
    /* 0x0F */ ST_TALK_ABILITY,
    /* 0x10 */ ST_NOT_SUPPORTED,
    /* 0x11 */ ST_NOT_SUPPORTED,
    /* 0x12 */ ST_PTZ_CONTROL,
    /* 0x13 */ ST_NOT_SUPPORTED,
    /* 0x14 */ ST_NOT_SUPPORTED,
    /* 0x15 */ ST_NOT_SUPPORTED,
    /* 0x16 */ ST_NOT_SUPPORTED,
    /* 0x17 */ ST_REBOOT,
    /* 0x18 */ ST_NOT_SUPPORTED,
    /* 0x19 */ ST_VIDEO_INPUT_WRITE,
    /* 0x1A */ ST_VIDEO_INPUT,
    /* 0x1B */ ST_NOT_SUPPORTED,
    /* 0x1C */ ST_NOT_SUPPORTED,
    /* 0x1D */ ST_NOT_SUPPORTED,
    /* 0x1E */ ST_NOT_SUPPORTED,
    /* 0x1F */ ST_START_MOTION_ALARM,
    /* 0x20 */ ST_FLOOD_LIGHT_MANUAL,
    /* 0x21 */ ST_ALARM_EVENT_LIST,
    /* 0x22 */ ST_FLOOD_LIGHT_TASK_WRITE,
    /* 0x23 */ ST_FLOOD_LIGHT_TASK_READ,
    /* 0x24 */ ST_NOT_SUPPORTED,
    /* 0x25 */ ST_NOT_SUPPORTED,
    /* 0x26 */ ST_NOT_SUPPORTED,
    /* 0x27 */ ST_NOT_SUPPORTED,
    /* 0x28 */ ST_NOT_SUPPORTED,
    /* 0x29 */ ST_NOT_SUPPORTED,
    /* 0x2A */ ST_NOT_SUPPORTED,
    /* 0x2B */ ST_NOT_SUPPORTED,
    /* 0x2C */ ST_OSD_CHANNEL_NAME,
    /* 0x2D */ ST_OSD_CHANNEL_NAME_WRITE,
    /* 0x2E */ ST_NOT_SUPPORTED,
    /* 0x2F */ ST_NOT_SUPPORTED,
    /* 0x30 */ ST_NOT_SUPPORTED,
    /* 0x31 */ ST_NOT_SUPPORTED,
    /* 0x32 */ ST_NOT_SUPPORTED,
    /* 0x33 */ ST_NOT_SUPPORTED,
    /* 0x34 */ ST_SHELTER_BASIC,
    /* 0x35 */ ST_SHELTER_EXTENDED,
    /* 0x36 */ ST_RECORD_CFG,
    /* 0x37 */ ST_RECORD_CFG_WRITE,
    /* 0x38 */ ST_COMPRESSION,
    /* 0x39 */ ST_COMPRESSION_WRITE,
    /* 0x3A */ ST_ABILITY_SUPPORT,
    /* 0x3B */ ST_NOT_SUPPORTED,
    /* 0x3C */ ST_NOT_SUPPORTED,
    /* 0x3D */ ST_NOT_SUPPORTED,
    /* 0x3E */ ST_NOT_SUPPORTED,
    /* 0x3F */ ST_NOT_SUPPORTED,
    /* 0x40 */ ST_NOT_SUPPORTED,
    /* 0x41 */ ST_NOT_SUPPORTED,
    /* 0x42 */ ST_NOT_SUPPORTED,
    /* 0x43 */ ST_CONFIG_FILE_INFO,
    /* 0x44 */ ST_NOT_SUPPORTED,
    /* 0x45 */ ST_NOT_SUPPORTED,
    /* 0x46 */ ST_NOT_SUPPORTED,
    /* 0x47 */ ST_NOT_SUPPORTED,
    /* 0x48 */ ST_NOT_SUPPORTED,
    /* 0x49 */ ST_NOT_SUPPORTED,
    /* 0x4A */ ST_NOT_SUPPORTED,
    /* 0x4B */ ST_NOT_SUPPORTED,
    /* 0x4C */ ST_IP,
    /* 0x4D */ ST_IP_WRITE,
    /* 0x4E */ ST_VIDEO_INPUT_EXTENDED,
    /* 0x4F */ ST_SERIAL,
    /* 0x50 */ ST_VERSION_INFO,
    /* 0x51 */ ST_RECORD,
    /* 0x52 */ ST_RECORD_WRITE,
    /* 0x53 */ ST_NOT_SUPPORTED,
    /* 0x54 */ ST_NOT_SUPPORTED,
    /* 0x55 */ ST_NOT_SUPPORTED,
    /* 0x56 */ ST_NOT_SUPPORTED,
    /* 0x57 */ ST_NOT_SUPPORTED,
    /* 0x58 */ ST_NOT_SUPPORTED,
    /* 0x59 */ ST_NOT_SUPPORTED,
    /* 0x5A */ ST_NOT_SUPPORTED,
    /* 0x5B */ ST_NOT_SUPPORTED,
    /* 0x5C */ ST_NOT_SUPPORTED,
    /* 0x5D */ ST_LINK_TYPE,
    /* 0x5E */ ST_NOT_SUPPORTED,
    /* 0x5F */ ST_NOT_SUPPORTED,
    /* 0x60 */ ST_NOT_SUPPORTED,
    /* 0x61 */ ST_NOT_SUPPORTED,
    /* 0x62 */ ST_NOT_SUPPORTED,
    /* 0x63 */ ST_NOT_SUPPORTED,
    /* 0x64 */ ST_NOT_SUPPORTED,
    /* 0x65 */ ST_NOT_SUPPORTED,
    /* 0x66 */ ST_HDD_INFO_LIST,
    /* 0x67 */ ST_NOT_SUPPORTED,
    /* 0x68 */ ST_SYSTEM_GENERAL,
    /* 0x69 */ ST_NOT_SUPPORTED,
    /* 0x6A */ ST_NOT_SUPPORTED,
    /* 0x6B */ ST_NOT_SUPPORTED,
    /* 0x6C */ ST_NOT_SUPPORTED,
    /* 0x6D */ ST_NOT_SUPPORTED,
    /* 0x6E */ ST_NOT_SUPPORTED,
    /* 0x6F */ ST_NOT_SUPPORTED,
    /* 0x70 */ ST_NOT_SUPPORTED,
    /* 0x71 */ ST_NOT_SUPPORTED,
    /* 0x72 */ ST_NOT_SUPPORTED,
    /* 0x73 */ ST_WIFI_SIGNAL,
    /* 0x74 */ ST_NOT_SUPPORTED,
    /* 0x75 */ ST_NOT_SUPPORTED,
    /* 0x76 */ ST_NOT_SUPPORTED,
    /* 0x77 */ ST_NOT_SUPPORTED,
    /* 0x78 */ ST_NOT_SUPPORTED,
    /* 0x79 */ ST_NOT_SUPPORTED,
    /* 0x7A */ ST_NOT_SUPPORTED,
    /* 0x7B */ ST_NOT_SUPPORTED,
    /* 0x7C */ ST_NOT_SUPPORTED,
    /* 0x7D */ ST_NOT_SUPPORTED,
    /* 0x7E */ ST_NOT_SUPPORTED,
    /* 0x7F */ ST_NOT_SUPPORTED,
    /* 0x80 */ ST_NOT_SUPPORTED,
    /* 0x81 */ ST_NOT_SUPPORTED,
    /* 0x82 */ ST_NOT_SUPPORTED,
    /* 0x83 */ ST_NOT_SUPPORTED,
    /* 0x84 */ ST_VIDEO_INPUT_NEW,
    /* 0x85 */ ST_RF_ALARM,
    /* 0x86 */ ST_NOT_SUPPORTED,
    /* 0x87 */ ST_NOT_SUPPORTED,
    /* 0x88 */ ST_NOT_SUPPORTED,
    /* 0x89 */ ST_NOT_SUPPORTED,
    /* 0x8A */ ST_NOT_SUPPORTED,
    /* 0x8B */ ST_NOT_SUPPORTED,
    /* 0x8C */ ST_NOT_SUPPORTED,
    /* 0x8D */ ST_NOT_SUPPORTED,
    /* 0x8E */ ST_NOT_SUPPORTED,
    /* 0x8F */ ST_NOT_SUPPORTED,
    /* 0x90 */ ST_NOT_SUPPORTED,
    /* 0x91 */ ST_NOT_SUPPORTED,
    /* 0x92 */ ST_STREAM_INFO_LIST,
    /* 0x93 */ ST_NOT_SUPPORTED,
    /* 0x94 */ ST_NOT_SUPPORTED,
    /* 0x95 */ ST_NOT_SUPPORTED,
    /* 0x96 */ ST_NOT_SUPPORTED,
    /* 0x97 */ ST_ABILITY_INFO,
    /* 0x98 */ ST_NOT_SUPPORTED,
    /* 0x99 */ ST_NOT_SUPPORTED,
    /* 0x9A */ ST_NOT_SUPPORTED,
    /* 0x9B */ ST_NOT_SUPPORTED,
    /* 0x9C */ ST_NOT_SUPPORTED,
    /* 0x9D */ ST_NOT_SUPPORTED,
    /* 0x9E */ ST_NOT_SUPPORTED,
    /* 0x9F */ ST_NOT_SUPPORTED,
    /* 0xA0 */ ST_NOT_SUPPORTED,
    /* 0xA1 */ ST_NOT_SUPPORTED,
    /* 0xA2 */ ST_NOT_SUPPORTED,
    /* 0xA3 */ ST_NOT_SUPPORTED,
    /* 0xA4 */ ST_NOT_SUPPORTED,
    /* 0xA5 */ ST_NOT_SUPPORTED,
    /* 0xA6 */ ST_NOT_SUPPORTED,
    /* 0xA7 */ ST_NOT_SUPPORTED,
    /* 0xA8 */ ST_NOT_SUPPORTED,
    /* 0xA9 */ ST_NOT_SUPPORTED,
    /* 0xAA */ ST_NOT_SUPPORTED,
    /* 0xAB */ ST_NOT_SUPPORTED,
    /* 0xAC */ ST_NOT_SUPPORTED,
    /* 0xAD */ ST_NOT_SUPPORTED,
    /* 0xAE */ ST_NOT_SUPPORTED,
    /* 0xAF */ ST_NOT_SUPPORTED,
    /* 0xB0 */ ST_NOT_SUPPORTED,
    /* 0xB1 */ ST_NOT_SUPPORTED,
    /* 0xB2 */ ST_NOT_SUPPORTED,
    /* 0xB3 */ ST_NOT_SUPPORTED,
    /* 0xB4 */ ST_NOT_SUPPORTED,
    /* 0xB5 */ ST_NOT_SUPPORTED,
    /* 0xB6 */ ST_FLOOD_LIGHT_TASK_READ_EXTENDED,
    /* 0xB7 */ ST_NOT_SUPPORTED,
    /* 0xB8 */ ST_NOT_SUPPORTED,
    /* 0xB9 */ ST_NOT_SUPPORTED,
    /* 0xBA */ ST_NOT_SUPPORTED,
    /* 0xBB */ ST_NOT_SUPPORTED,
    /* 0xBC */ ST_NOT_SUPPORTED,
    /* 0xBD */ ST_NOT_SUPPORTED,
    /* 0xBE */ ST_PTZ_PRESET,
    /* 0xBF */ ST_NOT_SUPPORTED,
    /* 0xC0 */ ST_UNKNOWN,
    /* 0xC1 */ ST_NOT_SUPPORTED,
    /* 0xC2 */ ST_NOT_SUPPORTED,
    /* 0xC3 */ ST_NOT_SUPPORTED,
    /* 0xC4 */ ST_NOT_SUPPORTED,
    /* 0xC5 */ ST_NOT_SUPPORTED,
    /* 0xC6 */ ST_NOT_SUPPORTED,
    /* 0xC7 */ ST_SUPPORT,
    /* 0xC8 */ ST_NOT_SUPPORTED,
    /* 0xC9 */ ST_TALK_CONFIG,
    /* 0xCA */ ST_TALK,
    /* 0xCB */ ST_NOT_SUPPORTED,
    /* 0xCC */ ST_RF_ALARM_CFG,
    /* 0xCD */ ST_NOT_SUPPORTED,
    /* 0xCE */ ST_NOT_SUPPORTED,
    /* 0xCF */ ST_NOT_SUPPORTED,
    /* 0xD0 */ ST_LED_STATE,
    /* 0xD1 */ ST_LED_STATE_WRITE,
    /* 0xD2 */ ST_NOT_SUPPORTED,
    /* 0xD3 */ ST_NOT_SUPPORTED,
    /* 0xD4 */ ST_NOT_SUPPORTED,
    /* 0xD5 */ ST_NOT_SUPPORTED,
    /* 0xD6 */ ST_NOT_SUPPORTED,
    /* 0xD7 */ ST_NOT_SUPPORTED,
    /* 0xD8 */ ST_NOT_SUPPORTED,
    /* 0xD9 */ ST_NOT_SUPPORTED,
    /* 0xDA */ ST_NOT_SUPPORTED,
    /* 0xDB */ ST_NOT_SUPPORTED,
    /* 0xDC */ ST_NOT_SUPPORTED,
    /* 0xDD */ ST_NOT_SUPPORTED,
    /* 0xDE */ ST_NOT_SUPPORTED,
    /* 0xDF */ ST_NOT_SUPPORTED,
    /* 0xE0 */ ST_NOT_SUPPORTED,
    /* 0xE1 */ ST_NOT_SUPPORTED,
    /* 0xE2 */ ST_NOT_SUPPORTED,
    /* 0xE3 */ ST_NOT_SUPPORTED,
    /* 0xE4 */ ST_NOT_SUPPORTED,
    /* 0xE5 */ ST_NOT_SUPPORTED,
    /* 0xE6 */ ST_NOT_SUPPORTED,
    /* 0xE7 */ ST_NOT_SUPPORTED,
    /* 0xE8 */ ST_NOT_SUPPORTED,
    /* 0xE9 */ ST_NOT_SUPPORTED,
    /* 0xEA */ ST_NOT_SUPPORTED,
    /* 0xEB */ ST_NOT_SUPPORTED,
    /* 0xEC */ ST_NOT_SUPPORTED,
    /* 0xED */ ST_NOT_SUPPORTED,
    /* 0xEE */ ST_NOT_SUPPORTED,
    /* 0xEF */ ST_NOT_SUPPORTED,
    /* 0xF0 */ ST_NOT_SUPPORTED,
    /* 0xF1 */ ST_NOT_SUPPORTED,
    /* 0xF2 */ ST_NOT_SUPPORTED,
    /* 0xF3 */ ST_NOT_SUPPORTED,
    /* 0xF4 */ ST_NOT_SUPPORTED,
    /* 0xF5 */ ST_NOT_SUPPORTED,
    /* 0xF6 */ ST_NOT_SUPPORTED,
    /* 0xF7 */ ST_NOT_SUPPORTED,
    /* 0xF8 */ ST_NOT_SUPPORTED,
    /* 0xF9 */ ST_NOT_SUPPORTED,
    /* 0xFA */ ST_NOT_SUPPORTED,
    /* 0xFB */ ST_NOT_SUPPORTED,
    /* 0xFC */ ST_NOT_SUPPORTED,
    /* 0xFD */ ST_NOT_SUPPORTED,
    /* 0xFE */ ST_NOT_SUPPORTED,
    /* 0xFF */ ST_NOT_SUPPORTED,
};

#endif
