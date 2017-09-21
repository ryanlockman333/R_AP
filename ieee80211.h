// Macro
#ifndef IEEE80211_H
#define IEEE80211_H
#endif

// Headers
#include <linux/igmp.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
// Cyclical Redundency Check Table(CRC32) For Frame Check Sequence(FCS)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Packing, Alignments, Offsets, Conversion, And (Un)Likely Defines
#ifndef __packed
#define __packed           __attribute__((packed)) // pack
#endif

#ifndef __aligned
#define __aligned(x)       __attribute__((aligned(x))) // align
#endif

#ifndef __aligned_tpacket
#define __aligned_tpacket  __attribute__((aligned(TPACKET_ALIGNMENT))) // tpacket align
#endif

#ifndef __align_tpacket
#define __align_tpacket(x) __attribute__((aligned(TPACKET_ALIGN(x)))) // tpacket align x
#endif

#define PKT_OFFSET (TPACKET_ALIGN(sizeof(tpacket2_hdr)) + \
                    TPACKET_ALIGN(sizeof(sockaddr_ll))) // packet offset from start

#define RTAP_ALIGN_OFFSET(offset, width) \
    ((((offset) + ((width) - 1)) & (~((width) - 1))) - offset) // radiotap, next data offset


// Convert Little Endian To CPU(Host) For IEEE802.11
#define pletohs(ptr) ((unsigned short)                                 \
                     ((unsigned short)*((cuchar_cptr)(ptr) + 1) << 8 | \
                      (unsigned short)*((cuchar_cptr)(ptr) + 0) << 0))

// Convert CPU(Host) To Little Endian For IEEE802.11
#define phtoles(p, v) {                 \
    (p)[0] = (unsigned char)((v) >> 0); \
    (p)[1] = (unsigned char)((v) >> 8); \
}

// Defines For V3 Packet, Likely/Unlikely
#ifndef likely
# define likely(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
# define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
// Channels
#define CHAN_1  2412
#define CHAN_2  2417
#define CHAN_3  2422
#define CHAN_4  2427
#define CHAN_5  2432
#define CHAN_6  2437
#define CHAN_7  2442
#define CHAN_8  2447
#define CHAN_9  2452
#define CHAN_10 2457
#define CHAN_11 2462
#define CHAN_12 2467 // No North America
#define CHAN_13 2472 // No North America
#define CHAN_14 2484 // only japan(11b only)

// Basic Rate
#define	IEEE80211_RATE_BASIC 0x80
#define	IEEE80211_RATE_VAL	 0x7f

// For Below
#define us unsigned short
#define BIT(x) (1 << (x)) // bitshifting

// LLC And IP Bitmask Parsing Defines
#define CHECKBIT_LLC(p, x) ((*(unsigned*)(p)) & BIT(x))
#define CHECKBIT_IP(p, x)  (ntohs(*(us*)(p))  & BIT(x))

// Spanning Tree Protocol Header, Ethernet And 802.1d And 802.1w And 802.1Q
#define GET_STP_PRIORITY(x) ((x) & (unsigned short)(0xFFFF000000000000 >> 48)
#define GET_STP_ID(x)       ((x) & 0x0000FFFFFFFFFFFF)

// ieee8022 Header And Radiotap Bit Parsing Shit Below
// Shifting And Bit Checking For Both Rtap And ieee802.11 Headers
#define CHECKBIT(p, x) (le16toh((*(us*)(p))) & BIT(x)) // check bit in little endian

// Radiotap Bitmask Defines
// Radiotap Header Bit Locations
#define _TSFT          0
#define _FLAGS         1
#define _RATE          2
#define _CHANNEL       3
#define _FHSS          4
#define _ANTSIGNAL     5
#define _ANTNOISE      6
#define _LOCKQUALITY   7
#define _TX_ATTEN      8
#define _DB_TX_ATTEN   9
#define _DBM_TXPWR    10
#define _ANTENNA      11
#define _DB_ANTSIG    12
#define _DB_ANTNOISE  13
#define _RX_FLAGS     14
#define _TX_FLAGS     15
#define _RTS_RETRIES  16
#define _DATA_RETRIES 17
#define _MCS          19
#define _AMPDU_STATS  20
#define _VHT          21
#define _RTAP_NSPACE  29 // 29 + 32*n
#define _VEND_NSPACE  30 // 30 + 32*n
#define _BITMAP_EXT   31 // 31 + 32*n

// Radiotap Present Bitmask Boolean Checks
#define _GET_TSFT(p)         (CHECKBIT(p, _TSFT))
#define _GET_FLAGS(p)        (CHECKBIT(p, _FLAGS))
#define _GET_RATE(p)         (CHECKBIT(p, _RATE))
#define _GET_CHANNEL(p)      (CHECKBIT(p, _CHANNEL))
#define _GET_FHSS(p)         (CHECKBIT(p, _FHSS))
#define _GET_ANTSIGNAL(p)    (CHECKBIT(p, _ANTSIGNAL))
#define _GET_ANTNOISE(p)     (CHECKBIT(p, _ANTNOISE))
#define _GET_LOCKQUALITY(p)  (CHECKBIT(p, _LOCKQUALITY))
#define _GET_TX_ATTEN(p)     (CHECKBIT(p, _TX_ATTEN))
#define _GET_DB_TX_ATTEN(p)  (CHECKBIT(p, _DB_TX_ATTEN))
#define _GET_DBM_TXPWR(p)    (CHECKBIT(p, _DBM_TXPWR))
#define _GET_ANTENNA(p)      (CHECKBIT(p, _ANTENNA))
#define _GET_DB_ANTSIG(p)    (CHECKBIT(p, _DB_ANTSIG))
#define _GET_DB_ANTNOISE(p)  (CHECKBIT(p, _DB_ANTNOISE))
#define _GET_RX_FLAGS(p)     (CHECKBIT(p, _RX_FLAGS))
#define _GET_TX_FLAGS(p)     (CHECKBIT(p, _TX_FLAGS))
#define _GET_RTS_RETRIES(p)  (CHECKBIT(p, _RTS_RETRIES))
#define _GET_DATA_RETRIES(p) (CHECKBIT(p, _DATA_RETRIES))
#define _GET_MCS(p)          (CHECKBIT(p, _MCS))
#define _GET_AMPDU_STATS(p)  (CHECKBIT(p, _AMPDU_STATS))
#define _GET_VHT(p)          (CHECKBIT(p, _VHT))
#define _GET_RTAP_NSPACE(p)  (CHECKBIT(p, _RTAP_NSPACE))
#define _GET_VEND_NSPACE(p)  (CHECKBIT(p, _VEND_NSPACE))
#define _GET_BITMAP_EXT(p)   (CHECKBIT(p, _BITMAP_EXT))

// Enumerations For Mostly 802.11 MGMT Frame Parameters
// Authentication Algorithms
#define WLAN_AUTH_OPEN       0
#define WLAN_AUTH_SHARED_KEY 1
#define WLAN_AUTH_FT         2
#define WLAN_AUTH_SAE        3
#define WLAN_AUTH_LEAP       128
 
#define WLAN_AUTH_CHALLENGE_LEN 128

#define WLAN_CAPABILITY_ESS  (1<<0)
#define WLAN_CAPABILITY_IBSS (1<<1)

// Information Elements
enum ieee80211_info_elementes {
    WLAN_MGMT_IE_SSID             = 0,
    WLAN_MGMT_IE_RATES            = 1,
    WLAN_MGMT_IE_FH_PARAM         = 2,
    WLAN_MGMT_IE_DS_PARAM         = 3,
    WLAN_MGMT_IE_CF_PARAM         = 4,
    WLAN_MGMT_IE_TIM              = 5,
    WLAN_MGMT_IE_IBSS_PARAM       = 6,
    WLAN_MGMT_IE_COUNTRY          = 7,  // 802.11d
    WLAN_MGMT_IE_HOP_PARAM        = 8,  // 802.11d
    WLAN_MGMT_IE_HOP_TABLE        = 9,  // 802.11d
    WLAN_MGMT_IE_REQUEST          = 10, // 802.11d
    WLAN_MGMT_IE_QBSS_LOAD        = 11,
    WLAN_MGMT_IE_EDCA_PARAM       = 12,
    WLAN_MGMT_IE_TSPEC            = 13,
    WLAN_MGMT_IE_TCLAS            = 14,
    WLAN_MGMT_IE_SCEDULE          = 15,
    WLAN_MGMT_IE_CHALLENGE_TEXT   = 16,
    WLAN_MGMT_IE_POWER_CONSTRAINT_OLD = 32, // 802.11h
    WLAN_MGMT_IE_POWER_CAPAB      = 33,  // 802.11h
    WLAN_MGMT_IE_TPC_REQUEST      = 34,  // 802.11h
    WLAN_MGMT_IE_TPC_REPORT       = 35,  // 802.11h
    WLAN_MGMT_IE_CHANNELS         = 36,  // 802.11h
    WLAN_MGMT_IE_CHANNEL_SWITCH   = 37,  // 802.11h
    WLAN_MGMT_IE_MEASURE_REQUEST  = 38,  // 802.11h
    WLAN_MGMT_IE_MEASURE_REPORT   = 39,  // 802.11h
    WLAN_MGMT_IE_QUITE            = 40,  // 802.11h
    WLAN_MGMT_IE_IBSS_DFS         = 41,  // 802.11h
    WLAN_MGMT_IE_ERP_INFO         = 42,  // 802.11g
    WLAN_MGMT_IE_TS_DELAY         = 43,
    WLAN_MGMT_IE_TCLAS_PROCESSING = 44,
    WLAN_MGMT_IE_HT_CAPABILITY    = 45,  // 802.11n
    WLAN_MGMT_IE_QOS_CAPABILITY   = 46,
    WLAN_MGMT_IE_ERP              = 47,  // 802.11g
    WLAN_MGMT_IE_RSN              = 48,  // 802.11i
    WLAN_MGMT_IE_EXT_RATES        = 50,  // 802.11g
    WLAN_MGMT_IE_POWER_CONSTRAINT = 52,  // 802.11h
    WLAN_MGMT_IE_MOBILITY_DOMAIN  = 54,  // 802.11r
    WLAN_MGMT_IE_HT_OPERATION     = 61,  // 802.11n
    WLAN_MGMT_IE_RM_ENABLED_CAPAB = 70,
    WLAN_MGMT_IE_20_40_BSS_COEX   = 72,  // 802.11n
    WLAN_MGMT_IE_OVERLAP_BSS_SCAN = 74,  // 802.11n
    WLAN_MGMT_IE_EXT_CAPABILITY   = 127,
    WLAN_MGMT_IE_CISCO_PROPERTY   = 133, // cisco proprietary
    WLAN_MGMT_IE_CISCO_SYSTEMS    = 150, // cisco systems
    WLAN_MGMT_IE_VHT_CAPABILITY   = 191, // 802.11ac
    WLAN_MGMT_IE_VHT_OPERATION    = 192, // 802.11ac
    WLAN_MGMT_IE_VHT_TRANSMIT_PWR = 195, // 802.11ac
    WLAN_MGMT_IE_VENDOR           = 221, // vendor specific
};

// Status Codes
enum ieee80211_statuscode {
    WLAN_STATUS_SUCCESS = 0,
    WLAN_STATUS_UNSPECIFIED_FAILURE = 1,
    WLAN_STATUS_CAPS_UNSUPPORTED = 10,
    WLAN_STATUS_REASSOC_NO_ASSOC = 11,
    WLAN_STATUS_ASSOC_DENIED_UNSPEC = 12,
    WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG = 13,
    WLAN_STATUS_UNKNOWN_AUTH_TRANSACTION = 14,
    WLAN_STATUS_CHALLENGE_FAIL = 15,
    WLAN_STATUS_AUTH_TIMEOUT = 16,
    WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA = 17,
    WLAN_STATUS_ASSOC_DENIED_RATES = 18,
    // 802.11b
    WLAN_STATUS_ASSOC_DENIED_NOSHORTPREAMBLE = 19,
    WLAN_STATUS_ASSOC_DENIED_NOPBCC = 20,
    WLAN_STATUS_ASSOC_DENIED_NOAGILITY = 21,
    // 802.11h
    WLAN_STATUS_ASSOC_DENIED_NOSPECTRUM = 22,
    WLAN_STATUS_ASSOC_REJECTED_BAD_POWER = 23,
    WLAN_STATUS_ASSOC_REJECTED_BAD_SUPP_CHAN = 24,
    // 802.11g
    WLAN_STATUS_ASSOC_DENIED_NOSHORTTIME = 25,
    WLAN_STATUS_ASSOC_DENIED_NODSSSOFDM = 26,
    // 802.11w
    WLAN_STATUS_ASSOC_REJECTED_TEMPORARILY = 30,
    WLAN_STATUS_ROBUST_MGMT_FRAME_POLICY_VIOLATION = 31,
    // 802.11i
    WLAN_STATUS_INVALID_IE = 40,
    WLAN_STATUS_INVALID_GROUP_CIPHER = 41,
    WLAN_STATUS_INVALID_PAIRWISE_CIPHER = 42,
    WLAN_STATUS_INVALID_AKMP = 43,
    WLAN_STATUS_UNSUPP_RSN_VERSION = 44,
    WLAN_STATUS_INVALID_RSN_IE_CAP = 45,
    WLAN_STATUS_CIPHER_SUITE_REJECTED = 46,
    // 802.11e
    WLAN_STATUS_UNSPECIFIED_QOS = 32,
    WLAN_STATUS_ASSOC_DENIED_NOBANDWIDTH = 33,
    WLAN_STATUS_ASSOC_DENIED_LOWACK = 34,
    WLAN_STATUS_ASSOC_DENIED_UNSUPP_QOS = 35,
    WLAN_STATUS_REQUEST_DECLINED = 37,
    WLAN_STATUS_INVALID_QOS_PARAM = 38,
    WLAN_STATUS_CHANGE_TSPEC = 39,
    WLAN_STATUS_WAIT_TS_DELAY = 47,
    WLAN_STATUS_NO_DIRECT_LINK = 48,
    WLAN_STATUS_STA_NOT_PRESENT = 49,
    WLAN_STATUS_STA_NOT_QSTA = 50,
    // 802.11s
    WLAN_STATUS_ANTI_CLOG_REQUIRED = 76,
    WLAN_STATUS_FCG_NOT_SUPP = 78,
    WLAN_STATUS_STA_NO_TBTT = 78,
    // 802.11ad
    WLAN_STATUS_REJECTED_WITH_SUGGESTED_CHANGES = 39,
    WLAN_STATUS_REJECTED_FOR_DELAY_PERIOD = 47,
    WLAN_STATUS_REJECT_WITH_SCHEDULE = 83,
    WLAN_STATUS_PENDING_ADMITTING_FST_SESSION = 86,
    WLAN_STATUS_PERFORMING_FST_NOW = 87,
    WLAN_STATUS_PENDING_GAP_IN_BA_WINDOW = 88,
    WLAN_STATUS_REJECT_U_PID_SETTING = 89,
    WLAN_STATUS_REJECT_DSE_BAND = 96,
    WLAN_STATUS_DENIED_WITH_SUGGESTED_BAND_AND_CHANNEL = 99,
    WLAN_STATUS_DENIED_DUE_TO_SPECTRUM_MANAGEMENT = 103,
};

// Reason Codes
enum ieee80211_reasoncode {
    WLAN_REASON_UNSPECIFIED = 1,
    WLAN_REASON_PREV_AUTH_NOT_VALID = 2,
    WLAN_REASON_DEAUTH_LEAVING = 3,
    WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY = 4,
    WLAN_REASON_DISASSOC_AP_BUSY = 5,
    WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA = 6,
    WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA = 7,
    WLAN_REASON_DISASSOC_STA_HAS_LEFT = 8,
    WLAN_REASON_STA_REQ_ASSOC_WITHOUT_AUTH = 9,
    // 802.11h
    WLAN_REASON_DISASSOC_BAD_POWER = 10,
    WLAN_REASON_DISASSOC_BAD_SUPP_CHAN = 11,
    // 802.11i
    WLAN_REASON_INVALID_IE = 13,
    WLAN_REASON_MIC_FAILURE = 14,
    WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT = 15,
    WLAN_REASON_GROUP_KEY_HANDSHAKE_TIMEOUT = 16,
    WLAN_REASON_IE_DIFFERENT = 17,
    WLAN_REASON_INVALID_GROUP_CIPHER = 18,
    WLAN_REASON_INVALID_PAIRWISE_CIPHER = 19,
    WLAN_REASON_INVALID_AKMP = 20,
    WLAN_REASON_UNSUPP_RSN_VERSION = 21,
    WLAN_REASON_INVALID_RSN_IE_CAP = 22,
    WLAN_REASON_IEEE8021X_FAILED = 23,
    WLAN_REASON_CIPHER_SUITE_REJECTED = 24,
    // TDLS 802.11z
    WLAN_REASON_TDLS_TEARDOWN_UNREACHABLE = 25,
    WLAN_REASON_TDLS_TEARDOWN_UNSPECIFIED = 26,
    // 802.11e
    WLAN_REASON_DISASSOC_UNSPECIFIED_QOS = 32,
    WLAN_REASON_DISASSOC_QAP_NO_BANDWIDTH = 33,
    WLAN_REASON_DISASSOC_LOW_ACK = 34,
    WLAN_REASON_DISASSOC_QAP_EXCEED_TXOP = 35,
    WLAN_REASON_QSTA_LEAVE_QBSS = 36,
    WLAN_REASON_QSTA_NOT_USE = 37,
    WLAN_REASON_QSTA_REQUIRE_SETUP = 38,
    WLAN_REASON_QSTA_TIMEOUT = 39,
    WLAN_REASON_QSTA_CIPHER_NOT_SUPP = 45,
    // 802.11s
    WLAN_REASON_MESH_PEER_CANCELED = 52,
    WLAN_REASON_MESH_MAX_PEERS = 53,
    WLAN_REASON_MESH_CONFIG = 54,
    WLAN_REASON_MESH_CLOSE = 55,
    WLAN_REASON_MESH_MAX_RETRIES = 56,
    WLAN_REASON_MESH_CONFIRM_TIMEOUT = 57,
    WLAN_REASON_MESH_INVALID_GTK = 58,
    WLAN_REASON_MESH_INCONSISTENT_PARAM = 59,
    WLAN_REASON_MESH_INVALID_SECURITY = 60,
    WLAN_REASON_MESH_PATH_ERROR = 61,
    WLAN_REASON_MESH_PATH_NOFORWARD = 62,
    WLAN_REASON_MESH_PATH_DEST_UNREACHABLE = 63,
    WLAN_REASON_MAC_EXISTS_IN_MBSS = 64,
    WLAN_REASON_MESH_CHAN_REGULATORY = 65,
    WLAN_REASON_MESH_CHAN = 66,
};

// Action Categories
enum ieee80211_category {
    WLAN_CATEGORY_SPECTRUM_MGMT = 0,
    WLAN_CATEGORY_QOS = 1,
    WLAN_CATEGORY_DLS = 2,
    WLAN_CATEGORY_BACK = 3,
    WLAN_CATEGORY_PUBLIC = 4,
    WLAN_CATEGORY_RADIO_MEASUREMENT = 5,
    WLAN_CATEGORY_FAST_BSS_TRANSITION = 6,
    WLAN_CATEGORY_HT = 7, // 802.11n
    WLAN_CATEGORY_SA_QUERY = 8,
    WLAN_CATEGORY_PROTECTED_DUAL_OF_ACTION = 9,
    WLAN_CATEGORY_TDLS = 12, // 802.11z
    WLAN_CATEGORY_MESH_ACTION = 13, // 802.11s
    WLAN_CATEGORY_MULTIHOP_ACTION = 14,
    WLAN_CATEGORY_SELF_PROTECTED = 15,
    WLAN_CATEGORY_DMG = 16,
    WLAN_CATEGORY_WMM = 17,
    WLAN_CATEGORY_FST = 18,
    WLAN_CATEGORY_UNPROT_DMG = 20,
    WLAN_CATEGORY_VHT = 21, // 802.11ac
    WLAN_CATEGORY_VENDOR_SPECIFIC_PROTECTED = 126,
    WLAN_CATEGORY_VENDOR_SPECIFIC = 127,
};

// SPECTRUM_MGMT Action Codes
enum ieee80211_spectrum_mgmt_actioncode {
    WLAN_ACTION_SPCT_MSR_REQ = 0,
    WLAN_ACTION_SPCT_MSR_RPRT = 1,
    WLAN_ACTION_SPCT_TPC_REQ = 2,
    WLAN_ACTION_SPCT_TPC_RPRT = 3,
    WLAN_ACTION_SPCT_CHL_SWITCH = 4,
};

// QOS_MGMT Action Codes
enum ieee80211_qos_mgmt_actioncode {
    WLAN_ACTION_QOS_ADDTS_REQ = 0,
    WLAN_ACTION_QOS_ADDTS_RESP = 1,
    WLAN_ACTION_QOS_DELTS = 2,
    WLAN_ACTION_QOS_SHEDULE = 3,
    WLAN_ACTION_QOS_MAP_CONFIGURE = 4,
};

// DLS_MGMT Action Codes
enum ieee80211_dls_mgmt_actioncode {
    WLAN_ACTION_DLS_REQ = 0,
    WLAN_ACTION_DLS_RESP = 1,
    WLAN_ACTION_DLS_TEARDOWN = 2,
};

// BACK_MGMT Action Codes
enum ieee80211_back_mgmt_actioncode {
    WLAN_ACTION_BACK_ADDBA_REQ = 0,
    WLAN_ACTION_BACK_ADDBA_RESP = 1,
    WLAN_ACTION_BACK_ADDBA_DELBA = 2,
};

// Public_MGMT Action Codes
enum ieee80211_pub_actioncode {
    WLAN_PUB_ACTION_EXT_CHANSW_ANN = 4,
    WLAN_PUB_ACTION_TDLS_DISCOVER_RES = 14,
};

// RADIO_MEASUREMENT_MGMT Action Codes
enum ieee80211_radio_meas_mgmt_actioncode {
    WLAN_ACTION_RADIO_MEAS_REQ = 0,
    WLAN_ACTION_RADIO_MEAS_RPRT = 1,
    WLAN_ACTION_RADIO_MEAS_LINK_MEAS_REQ = 2,
    WLAN_ACTION_RADIO_MEAS_LINK_MEAS_RPRT = 3,
    WLAN_ACTION_RADIO_MEAS_NEIGHBOR_RPRT_REQ = 4,  // 802.11k
    WLAN_ACTION_RADIO_MEAS_NEIGHBOR_RPRT_RESP = 5, // 802.11k
};

// FAST_BSS_TRANSITION_MGMT Action Codes
enum ieee80211_fbsst_mgmt_actioncode {
    WLAN_ACTION_FAST_BSS_T_RESERVED = 0,
    WLAN_ACTION_FAST_BSS_T_REQ = 1,
    WLAN_ACTION_FAST_BSS_T_RESP = 2,
    WLAN_ACTION_FAST_BSS_T_CONFIRM = 3,
    WLAN_ACTION_FAST_BSS_T_ACK = 4,
};

// HT_MGMT Action Codes
enum ieee80211_ht_actioncode { // 802.11n
    WLAN_HT_ACTION_NOTIFY_CHANWIDTH = 0,
    WLAN_HT_ACTION_SMPS = 1,
    WLAN_HT_ACTION_PSMP = 2,
    WLAN_HT_ACTION_PCO_PHASE = 3,
    WLAN_HT_ACTION_CSI = 4,
    WLAN_HT_ACTION_NONCOMPRESSED_BF = 5,
    WLAN_HT_ACTION_COMPRESSED_BF = 6,
    WLAN_HT_ACTION_ASEL_IDX_FEEDBACK = 7,
};

// SA_Query_MGMT Action Codes
enum ieee80211_sa_query_action {
    WLAN_ACTION_SA_QUERY_REQUEST = 0,
    WLAN_ACTION_SA_QUERY_RESPONSE = 1,
};

// Protected_Dual_Of_Action_MGMT Action Codes
enum ieee80211_protect_dual_actioncode {

};

// TDLS_MGMT Action Codes
enum ieee80211_tdls_actioncode { // 802.11z
    WLAN_TDLS_SETUP_REQUEST = 0,
    WLAN_TDLS_SETUP_RESPONSE = 1,
    WLAN_TDLS_SETUP_CONFIRM = 2,
    WLAN_TDLS_TEARDOWN = 3,
    WLAN_TDLS_PEER_TRAFFIC_INDICATION = 4,
    WLAN_TDLS_CHANNEL_SWITCH_REQUEST = 5,
    WLAN_TDLS_CHANNEL_SWITCH_RESPONSE = 6,
    WLAN_TDLS_PEER_PSM_REQUEST = 7,
    WLAN_TDLS_PEER_PSM_RESPONSE = 8,
    WLAN_TDLS_PEER_TRAFFIC_RESPONSE = 9,
    WLAN_TDLS_DISCOVERY_REQUEST = 10,
};

// Mesh_MGMT Action Codes
enum ieee80211_mesh_actioncode { // 802.11s
    WLAN_MESH_ACTION_LINK_METRIC_REPORT,
    WLAN_MESH_ACTION_HWMP_PATH_SELECTION,
    WLAN_MESH_ACTION_GATE_ANNOUNCEMENT,
    WLAN_MESH_ACTION_CONGESTION_CONTROL_NOTIFICATION,
    WLAN_MESH_ACTION_MCCA_SETUP_REQUEST,
    WLAN_MESH_ACTION_MCCA_SETUP_REPLY,
    WLAN_MESH_ACTION_MCCA_ADVERTISEMENT_REQUEST,
    WLAN_MESH_ACTION_MCCA_ADVERTISEMENT,
    WLAN_MESH_ACTION_MCCA_TEARDOWN,
    WLAN_MESH_ACTION_TBTT_ADJUSTMENT_REQUEST,
    WLAN_MESH_ACTION_TBTT_ADJUSTMENT_RESPONSE,
};

// Multihop_MGMT Action Codes
enum ieee80211_multihop_actioncode {

};

// Self_Protected_MGMT Action Codes
enum ieee80211_self_protected_actioncode {
    WLAN_SP_RESERVED = 0,
    WLAN_SP_MESH_PEERING_OPEN = 1,
    WLAN_SP_MESH_PEERING_CONFIRM = 2,
    WLAN_SP_MESH_PEERING_CLOSE = 3,
    WLAN_SP_MGK_INFORM = 4,
    WLAN_SP_MGK_ACK = 5,
};

// DMG_MGMT Action Codes
enum ieee80211_dmg_actioncode {

};

// WMM_MGMT Action Codes
enum ieee80211_wmm_actioncode {

};

// FST_MGMT Action Codes
enum ieee80211_fst_actioncode {

};

// Unprotected_DMG_MGMT Action Codes
enum ieee80211_unproc_dmg_actioncode {

};

// VHT_MGMT Action Codes
enum ieee80211_vht_actioncode { // 802.11ac
    WLAN_VHT_ACTION_COMPRESSED_BF = 0,
    WLAN_VHT_ACTION_GROUPID_MGMT = 1,
    WLAN_VHT_ACTION_OPMODE_NOTIF = 2,
};

// Vendor_Specific_Protected_MGMT Action Codes
enum ieee80211_vendor_spec_proc_actioncode {

};

// Vendor_Specific_MGMT Action Codes
enum ieee80211_vendor_spec_actioncode {

};

// ieee80211, Frame Control Bitmask Parsing Defines And Enumerations
// Frame Type Bit Locations
#define _CTRL_FRAME 2
#define _DATA_FRAME 3

// 802.11 Frame Control Bit Locations
#define _TODS      8
#define _FROMDS    9
#define _MORE     10
#define _RETRY    11
#define _PWRMGT   12
#define _MOREDATA 13
#define _PRIVACY  14
#define _ORDER    15

// Frame Types For Comparison                 LSB     LSB   MSB  TOTAL
enum WIFI_FRAME { //          LSB             Bin  -> Dec | Dec  Dec
    WIFI_MGMT_FRAME = (0              ), // 0 0 0 0  : 0  | 0  = 0
    WIFI_CTRL_FRAME = (         BIT(2)), // 0 1 0 0  : 4  | 0  = 4
    WIFI_DATA_FRAME = (BIT(3)         ), // 1 0 0 0  : 8  | 0  = 8
    WIFI_EXT_FRAME  = (BIT(3) | BIT(2)), // 1 1 0 0  : 12 | 0  = 12 // Wrapper
}; // last 2 bits masked off since type is 2 bits long, really mgmt dec = 0, ctrl dec = 1, data dec = 2, ext dec = 3

// Frame Subtypes For Comparison
enum WIFI_SUBTYPE { //                                                                    MSB     MSB   LSB TOTAL(SUM)
    // Management Frames                      MSB                       LSB               Bin  -> Dec | Dec Dec
    WIFI_ASSOCREQ           = (0                                 | WIFI_MGMT_FRAME), // 0 0 0 0  : 0  | 0 = 0
    WIFI_ASSOCRSP           = (                           BIT(4) | WIFI_MGMT_FRAME), // 0 0 0 1  : 1  | 0 = 16
    WIFI_REASSOCREQ         = (                  BIT(5)          | WIFI_MGMT_FRAME), // 0 0 1 0  : 2  | 0 = 32
    WIFI_REASSOCRSP         = (                  BIT(5) | BIT(4) | WIFI_MGMT_FRAME), // 0 0 1 1  : 3  | 0 = 48
    WIFI_PROBEREQ           = (         BIT(6)                   | WIFI_MGMT_FRAME), // 0 1 0 0  : 4  | 0 = 64
    WIFI_PROBERSP           = (         BIT(6)          | BIT(4) | WIFI_MGMT_FRAME), // 0 1 0 1  : 5  | 0 = 80
    WIFI_BEACON             = (BIT(7)                            | WIFI_MGMT_FRAME), // 1 0 0 0  : 8  | 0 = 96
    WIFI_ATIM               = (BIT(7)                   | BIT(4) | WIFI_MGMT_FRAME), // 1 0 0 1  : 9  | 0 = 112
    WIFI_DISASSOC           = (BIT(7)          | BIT(5)          | WIFI_MGMT_FRAME), // 1 0 1 0  : 10 | 0 = 128
    WIFI_AUTH               = (BIT(7)          | BIT(5) | BIT(4) | WIFI_MGMT_FRAME), // 1 0 1 1  : 11 | 0 = 144
    WIFI_DEAUTH             = (BIT(7) | BIT(6)                   | WIFI_MGMT_FRAME), // 1 1 0 0  : 12 | 0 = 160
    WIFI_ACTION             = (BIT(7) | BIT(6)          | BIT(4) | WIFI_MGMT_FRAME), // 1 1 0 1  : 13 | 0 = 176
    // Control Frames
    WIFI_CTL_EXT            = (         BIT(6) | BIT(5) | BIT(4) | WIFI_CTRL_FRAME), // 0 1 1 1  : 7  | 4 = 116 // Wrapper, 802.11n
    WIFI_BACK_REQ           = (BIT(7)                            | WIFI_CTRL_FRAME), // 1 0 0 0  : 8  | 4 = 132 // BAR
    WIFI_BACK               = (BIT(7)                   | BIT(4) | WIFI_CTRL_FRAME), // 1 0 0 1  : 9  | 4 = 148
    WIFI_PSPOLL             = (BIT(7)          | BIT(5)          | WIFI_CTRL_FRAME), // 1 0 1 0  : 10 | 4 = 164
    WIFI_RTS                = (BIT(7)          | BIT(5) | BIT(4) | WIFI_CTRL_FRAME), // 1 0 1 1  : 11 | 4 = 180
    WIFI_CTS                = (BIT(7) | BIT(6)                   | WIFI_CTRL_FRAME), // 1 1 0 0  : 12 | 4 = 196
    WIFI_ACK                = (BIT(7) | BIT(6)          | BIT(4) | WIFI_CTRL_FRAME), // 1 1 0 1  : 13 | 4 = 212
    WIFI_CFEND              = (BIT(7) | BIT(6) | BIT(5)          | WIFI_CTRL_FRAME), // 1 1 1 0  : 14 | 4 = 228
    WIFI_CFEND_CFACK        = (BIT(7) | BIT(6) | BIT(5) | BIT(4) | WIFI_CTRL_FRAME), // 1 1 1 1  : 15 | 4 = 244
    // Data Frames
    WIFI_DATA               = (0                                 | WIFI_DATA_FRAME), // 0 0 0 0  : 0  | 8 = 8
    WIFI_DATA_CFACK         = (                           BIT(4) | WIFI_DATA_FRAME), // 0 0 0 1  : 1  | 8 = 24
    WIFI_DATA_CFPOLL        = (                  BIT(5)          | WIFI_DATA_FRAME), // 0 0 1 0  : 2  | 8 = 40
    WIFI_DATA_CFACKPOLL     = (                  BIT(5) | BIT(4) | WIFI_DATA_FRAME), // 0 0 1 1  : 3  | 8 = 56
    WIFI_DATA_NULL          = (         BIT(6)                   | WIFI_DATA_FRAME), // 0 1 0 0  : 4  | 8 = 72
    WIFI_CFACK              = (         BIT(6)          | BIT(4) | WIFI_DATA_FRAME), // 0 1 0 1  : 5  | 8 = 88
    WIFI_CFPOLL             = (         BIT(6) | BIT(5)          | WIFI_DATA_FRAME), // 0 1 1 0  : 6  | 8 = 104
    WIFI_CFACKPOLL          = (         BIT(6) | BIT(5) | BIT(4) | WIFI_DATA_FRAME), // 0 1 1 1  : 7  | 8 = 120
    // Quality Of Service Data Frames
    WIFI_QOS_DATA           = (BIT(7)                            | WIFI_DATA_FRAME), // 1 0 0 0  : 8  | 8 = 136
    WIFI_QOS_DATA_CFACK     = (BIT(7)                   | BIT(4) | WIFI_DATA_FRAME), // 1 0 0 1  : 9  | 8 = 152
    WIFI_QOS_DATA_CFPOLL    = (BIT(7)          | BIT(5)          | WIFI_DATA_FRAME), // 1 0 1 0  : 10 | 8 = 168
    WIFI_QOS_DATA_CFACKPOLL = (BIT(7)          | BIT(5) | BIT(4) | WIFI_DATA_FRAME), // 1 0 1 1  : 11 | 8 = 184
    WIFI_QOS_NULL           = (BIT(7) | BIT(6)                   | WIFI_DATA_FRAME), // 1 1 0 0  : 12 | 8 = 200
    WIFI_QOS_CFACK          = (BIT(7) | BIT(6)          | BIT(4) | WIFI_DATA_FRAME), // 1 1 0 1  : 13 | 8 = 216
    WIFI_QOS_CFPOLL         = (BIT(7) | BIT(6) | BIT(5)          | WIFI_DATA_FRAME), // 1 1 1 0  : 14 | 8 = 232
    WIFI_QOS_CFACKPOLL      = (BIT(7) | BIT(6) | BIT(5) | BIT(4) | WIFI_DATA_FRAME), // 1 1 1 1  : 15 | 8 = 248   
};

// Frame Type Octets
#define GetFTypeBit1(p) (CHECKBIT(p, 2)) // first  bit
#define GetFTypeBit2(p) (CHECKBIT(p, 3)) // second bit

// Get Frame Boolean Checks Through Bitshifting
#define GetMGMTF(p) (!GetFTypeBit1(p) && !GetFTypeBit2(p)) // 0x00, management
#define GetCTRLF(p) ( GetFTypeBit1(p) && !GetFTypeBit2(p)) // 0x01, control
#define GetDATAF(p) (!GetFTypeBit1(p) &&  GetFTypeBit2(p)) // 0x10, data
#define GetEXTF(p)  ( GetFTypeBit1(p) &&  GetFTypeBit2(p)) // 0x11, ext

// Expirimentals////////////////////////////////
#define GetCTRL(p) (CHECKBIT(p, _CTRL_FRAME))
#define GetDATA(p) (CHECKBIT(p, _DATA_FRAME))
#define GetMGMT(p) (!GetCTRL(p) && !GetDATA(p))
////////////////////////////////////////////////

#define GetFrameType(p)      ((le16toh(*(us*)(p))) & (BIT(2) | BIT(3)))
#define GetFrameSubType(p)   ((le16toh(*(us*)(p))) & (BIT(2) | BIT(3) | \
                                                      BIT(4) | BIT(5) | \
                                                      BIT(6) | BIT(7)))
#define GetJustFSubType(p)   ((le16toh(*(us*)(p))) & (BIT(4) | BIT(5) | \
                                                      BIT(6) | BIT(7)))
#define GetProtocol(p)       ((le16toh(*(us*)(p))) & (BIT(0) | BIT(1)))
#define GET_IE_RATE(p)       (((u8)p) & (BIT(0) | BIT(1) | BIT(2) | BIT(3) \
                                         BIT(4) | BIT(5) | BIT(6)))
#define GET_IE_RATE_BASIC(p) (((u8)p) & (BIT(7)))

#define GetToDS(p)     (CHECKBIT(p, _TODS))     // To Distribution System
#define GetFromDS(p)   (CHECKBIT(p, _FROMDS))   // From DS
#define GetMoreFlag(p) (CHECKBIT(p, _MORE))     // More
#define GetRetry(p)    (CHECKBIT(p, _RETRY))    // Retry
#define GetPwrMgt(p)   (CHECKBIT(p, _PWRMGT))   // Power Management
#define GetMoreData(p) (CHECKBIT(p, _MOREDATA)) // More Data
#define GetPrivacy(p)  (CHECKBIT(p, _PRIVACY))  // Encryption (WPA/WEP)
#define GetOrder(p)    (CHECKBIT(p, _ORDER))    // Order

// Get Sequence And Fragment
#define FRAG_NUM(x) (le16toh(x)  & 0x000F)
#define SEQ_NUM(x)  ((le16toh(x) & 0xFFF0) >> 4)

// Is Multicast Destination
#define MCAST(da) ((*da) & 0x01)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Presentation Length Defines
#define HARDWARE_PRINT_LEN            8 + 8 + 7 + 1
#define ETH_PRINT_LEN                 6 + 6 + 5 + 1
#define IP_PRINT_LEN                  3 + 1 + 3 + 1 + 3 + 1 + 3 + 1
#define IP_PRINT_LEN_6                8 * 4 + 7 + 1                     // 39 + 1 for null
#define IPV4_IN_IPV6_PRINT_LEN        (6 * 4 + 5) + 1 + (4 * 3 + 3) + 1 // 45 + 1 for null
#define OUI_PRINT_LEN                 3 + 3 + 2 + 1
#define IPV6_FLOW_LBL_PRINT_LEN       3 + 3 + 2 + 1
#define WLAN_SA_QUERY_TR_ID_PRINT_LEN 2 + 2 + 1 + 1

// Regular Length Defines
#define IP_ALEN           4
#define OUI_LEN           3
#define IPV6_FLOW_LBL_LEN 3

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Rx Packet Defines
#define RING_FRAMES 128 // number of frames in ring

// Rx Packet Static Globals
const long pagesize = sysconf(_SC_PAGESIZE); // pagesize, make sure to check
                                             // against -1, if using this

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Typedefs For Radio, ieee80211 Headers
typedef   signed char      s8;
typedef unsigned char      u8;
typedef   signed short     s16;
typedef unsigned short     u16;
typedef   signed /*int*/   s32;
typedef unsigned /*int*/   u32;
typedef   signed long long s64;
typedef unsigned long long u64;

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Local Data Structure Header Defines
#ifndef WLAN_SA_QUERY_TR_ID_LEN
#define WLAN_SA_QUERY_TR_ID_LEN 2
#endif

// OUI's
u8 oui_rfc1042[OUI_LEN]   = {0x00, 0x00, 0x00}; // ethernet encapsulation(rfc1042)
u8 oui_cisco[OUI_LEN]     = {0x00, 0x0B, 0x85}; // Cisco Systems, Inc.
u8 oui_cisco2[OUI_LEN]    = {0x00, 0x40, 0x96}; // Cisco Systems, Inc.
u8 oui_apple[OUI_LEN]     = {0x00, 0x17, 0xF2}; // Apple
u8 oui_microsoft[OUI_LEN] = {0x00, 0x50, 0xF2}; // Microsoft Corp.
u8 oui_broadcom[OUI_LEN]  = {0x00, 0x10, 0x18}; // Broadcom Corp.
u8 oui_samsung[OUI_LEN]   = {0x00, 0x16, 0x32}; // Samsung Electronics CO., LTD.
u8 oui_atheros[OUI_LEN]   = {0x00, 0x03, 0x7F}; // Atheros Communications, Inc.
u8 oui_aerohive[OUI_LEN]  = {0x00, 0x19, 0x77}; // Aerohive Networks, Inc.
u8 oui_ieee80211[OUI_LEN] = {0x00, 0x0F, 0xAC}; // IEEE 802.11, Used Mainly For RSN IE

// Some OUI's ether_type
u16 CISCO_OTAP_ETHER_TYPE    = 0xCCCD; // OTAP Cisco ether_type, with cisco[] oui
u16 CISCO_AIRONET_ETHER_TYPE = 0x0000; // Aironet Cisco ether_type with cisco2[] oui

// Radio Frequency Header, Regular
typedef struct {
    u8     it_version,    // should be zero
           it_pad;
    __le16 it_len;
    __le32 it_present;
}__packed ie80211_rtaphdr;

// Radiotap Header, For RX
typedef struct {
    u8     it_version,    // should be zero
           it_pad;
    __le16 it_len;
    __le32 it_present;    // bitmask presents
    u64    rt_tsft;       // mactime(micro secs)
    u8     rt_flags,
           rt_rate;       // RX(500 Kbps)
    u16    rt_chan,       // MHz/GHz
           rt_chan_flags;
    s8     rt_antsignal,  // RF dBm
           rt_antnoise;   // RF dBm //////////////////////////////////////////////////////////////////////mite not need this
    u8     rt_antenna,    // antenna index
           rt_pad[3];     // pad for 4 byte boundary
}__packed ie80211_rtaphdr_rx;

// Radiotap Header, For TX
typedef struct {
    u8     it_version,    // should be zero
           it_pad;        // pad for len
    __le16 it_len;
    __le32 it_present;
    u8     rt_rate,       // TX(500 Kbps)
           rt_pad;        // pad for chan
    u16    rt_chan,       // MHz/GHz
           rt_chan_flags;
    s8     rt_antsignal;  // RF dBm
    u8     rt_antenna;    // antenna index
}__packed ie80211_rtaphdr_tx;

// 802.11 Frame Check Sequence
typedef struct {
    __le16 fcs;
} ieee80211_fcs_hdr;

// 802.11 Frame Header, 3 Addresses
typedef struct {
    __le16 frame_control,
           duration_id;
    u8     addr1[ETH_ALEN],
           addr2[ETH_ALEN],
           addr3[ETH_ALEN];
    __le16 seq_ctrl;
}__packed __aligned(2) ieee80211_hdr3; // alligned 2 byte boundary

//  802.11 Frame Header, 4 Addresses
typedef struct {
    __le16 frame_control,
           duration_id;
    u8     addr1[ETH_ALEN],
           addr2[ETH_ALEN],
           addr3[ETH_ALEN];
    __le16 seq_ctrl;
    u8     addr4[ETH_ALEN];
}__packed __aligned(2) ieee80211_hdr4;

// 802.11 Frame Header, Control Frames
typedef struct {
    __le16 frame_control,
           duration;
    u8     ra[ETH_ALEN],
           ta[ETH_ALEN];
}__packed __aligned(2) ieee80211_rts_hdr,      // RTS, (NAV)
                       ieee80211_cfendack_hdr; // CF-End + CF-Ack, (PCF)

typedef struct {
    __le16 frame_control,
           duration;
    u8     ra[ETH_ALEN];
}__packed __aligned(2) ieee80211_cts_hdr,   // CTS, (NAV)
                       ieee80211_cfend_hdr, // CF-End, (PCF)
                       ieee80211_ack_hdr;   // Ack

typedef struct {
    __le16 frame_control,
           aid;
    u8     bssid[ETH_ALEN],
           ta[ETH_ALEN];
}__packed __aligned(2) ieee80211_pspoll_hdr; // PS-Poll

typedef struct {
    __le16 frame_control,
           duration;
    u8     ra[ETH_ALEN],
           ta[ETH_ALEN];
    __le16 bar_ctrl,
           start_seq_ctrl;
}__packed __aligned(2) ieee80211_backreq_hdr; // BAR(BACK-Req)

typedef struct {
    __le16 frame_control,
           duration;
    u8     ra[ETH_ALEN],
           ta[ETH_ALEN];
    __le16 bar_ctrl,
           start_seq_ctrl;
    __le64 bitmap;
}__packed __aligned(2) ieee80211_back_hdr; // BACK

typedef struct {
    __le16 frame_control,
           duration;
    u8     ra[ETH_ALEN];
    __le16 carried_frame_ctrl,
           ht_ctrl;
}__packed __aligned(2) ieee80211_ctrlext_hdr; // Control Wrapper EXT

// 802.11 Frame Header, Management Action Frame IEs
typedef struct {
    u8 mode,
       new_operating_class,
       new_ch_num,
       count;
}__packed ieee80211_ext_chansw_ie;

typedef struct {
    u8 token,
       mode,
       type,
       request[0];
}__packed ieee80211_msrment_ie;

typedef struct {
    u8 tx_power,
       link_margin;
}__packed ieee80211_tpc_report_ie;

/* Information Elements Following ieee80211 MGMT Frames */
// SSID IE
typedef struct {
    u8 id,
       len,
       ssid[0];
}__packed ieee80211_ie_ssid;

// Rates IE
typedef struct {
    u8 id,
       len,
       rates[0];
}__packed ieee80211_ie_rates;

// Request IE
typedef struct {
    u8 id,
       len,
       request[0];
}__packed ieee80211_ie_request;

// Challenge Text IE(Shared Key Authentication)
typedef struct {
    u8 id,
       len,
       challenge_text[0];
}__packed ieee80211_ie_challenge;

// Power Constraint IE
typedef struct {
    u8 id,
       len,
       pwr_constraint;
}__packed ieee80211_ie_pwr_constraint;

// ERP IE(PHY Level Flags)
typedef struct {
    u8 id,
       len,
       erp_info;
}__packed ieee80211_ie_erp_info;

// Vendor Specific IE
typedef struct {
    u8     id,
           len;
    __le32 oui;
    u8     data[0];
}__packed ieee80211_ie_vendor;

// Robust Security Network(WPA) IE
typedef struct {
    u8     id,
           len,
           version;
    __le32 group_cipher; // for multicast/broadcast
    __le16 pairwise_count; // unicast cipher count
    __le32 pairwise_cipher[0]; // unicast cipher ID list
    __le16 auth_count; // authentication types supported count
    __le32 auth_list[0]; // authentication types list
    __le16 rsn_capab; // security capabilities, rsn only
    __le16 pmkid_count; // PMKIDs count, association frames only
    u8     pmkid_list[0]; // PMKIDs list, 16-byte SHA1 type
}__packed ieee80211_ie_rsn;

// Channels IE Channel Band Tuple
typedef struct ieee80211_ie_channels_channel_band {
    u8 first_channel,
       nr_channels;
}__packed ieee80211_ie_channels_channel_band;

typedef struct ieee80211_ie_channels {
    u8 id,
       len;
    ieee80211_ie_channels_channel_band channels[0];
}__packed ieee80211_ie_channels;

// Direct Spectrum(Channel Number) IE
typedef struct {
    u8 id,
       len,
       cur_chan;
}__packed ieee80211_ie_ds_param;

// Country IE Regulatory Extension Triplet
typedef struct {
    u8 reg_ext_id,
       reg_class_id,
       coverage_class;
}__packed ieee80211_ie_country_ext_triplet;
 
// Country IE Regulatory Band Triplet
typedef struct {
    u8 first_channel,
       nr_channels,
       max_txpwr;
}__packed ieee80211_ie_country_band_triplet;

// Country IE Regulatory Triplet
/* Band triplet if the first byte < 200, extension triplet otherwise */
typedef union {
    u8 first; // differentiator between band and ext triplets
    ieee80211_ie_country_band_triplet band;
    ieee80211_ie_country_ext_triplet  ext;
} ieee80211_ie_country_triplet;

// Country IE
#define IE_COUNTRY_CODE_LEN 2
typedef struct {
    u8 id,
       len,
       name[IE_COUNTRY_CODE_LEN], // ISO Alpha2 country code
       in_out;  // 'I' for indoor, 'O' for outdoor
    ieee80211_ie_country_triplet triplet[0]; // regulatory triplet list
}__packed ieee80211_ie_country;

// Power Capabilities IE
typedef struct {
    u8 id,
       len,
       min_txpwr,
       max_txpwr;
}__packed ieee80211_ie_power_capab;

// Traffic Indication Map
typedef struct {
    u8 id,
       len,
       DTIM_count,
       DTIM_period,
       bitmap_ctrl,
       partial_virtual_bitmap;
}__packed ieee80211_ie_tim;

typedef struct {
    u8 id,
       len,
       tx_power,
       link_margin;
}__packed ieee80211_ie_tpc;

typedef struct { // 802.11n D1.10
    u8     id,
           len;
    __le16 capab_info;
    u8     a_mpdu_param;
    u8     mcs_set[16]; // supported modulation and codeing scheme
    __le16 extended_capab;
    __le32 trans_beamform_capab; // (TxBF)
    u8     antenna_capab; // antenna selection(ASEL)
}__packed ieee80211_ie_ht_capab;

// Generic IE For Our Union Below
typedef struct {
    u8 id,
       len;
    union {
        u8 ssid[0],
           rates[0],
           request[0],
           challenge_text[0],
           power_constraint,
           erp_info;
        ieee80211_ie_channels_channel_band channels[0];
    };
}__packed ieee80211_ie_generic;

// Used In Place Of variable[0] in MGMT Sub-Frames
typedef union {
    // Generic Information Element
    ieee80211_ie_generic ie_gen;

    // DS Parameters
    ieee80211_ie_ds_param ds_param;

    // TIM
    ieee80211_ie_tim tim;

    // TPC Report
    ieee80211_ie_tpc tpc_report;

    // Country Info
    ieee80211_ie_country country;

    // Power Capabilities
    ieee80211_ie_power_capab power_capab;
 
    // Security Info
    ieee80211_ie_rsn rsn;

    // HT Capabilities
    ieee80211_ie_ht_capab ht_capab;

    // Vendor Specific
    ieee80211_ie_vendor vendor;

    // Add More
} ieee80211_ie;

// 802.11 Frame Header, Management Frame
/* using own ieee80211_ie union as c-hack flexible array instead of variable[0] */
typedef struct {
    __le16 frame_control,
           duration;
    u8     da[ETH_ALEN],
           sa[ETH_ALEN],
           bssid[ETH_ALEN];
    __le16 seq_ctrl;
    
    union {
        struct {
            __le16 auth_alg,
                   auth_transaction,
                   status_code;
            /* challenge text possible */
            ieee80211_ie ie[0];
        }__packed auth;
        
        struct {
            __le16 reason_code;
        }__packed deauth;
        
        struct {
            __le16 capab_info,
                   listen_interval;
            /* SSID and supported rates */
            ieee80211_ie ie[0];
        }__packed assoc_req;
        
        struct {
            __le16 capab_info,
                   status_code,
                   aid;
            /* supported rates */
            ieee80211_ie ie[0];
        }__packed assoc_resp, reassoc_resp;
        
        struct {
            __le16 capab_info,
                   listen_interval;
            u8     current_ap[ETH_ALEN];
            /* SSID and supported rates */
            ieee80211_ie ie[0];
        }__packed reassoc_req;

        struct {
            __le16 reason_code;
        }__packed disassoc;

        struct {
            __le64 timestamp;
            __le16 beacon_int,
                   capab_info;
            /* SSID, supported rates, FH params, DS params, CF params, IBSS params, TIM */
            ieee80211_ie ie[0];
        }__packed beacon;

        struct {
            /* SSID, supported rates */
            ieee80211_ie ie[0];
        }__packed probe_req;
        
        struct {
            __le64 timestamp;
            __le16 beacon_int,
                   capab_info;
            /* SSID, supported rates, FH params, DS params, CF params, IBSS params */
            ieee80211_ie ie[0];
        }__packed probe_resp;
        
        struct {
            u8 category; // differentiator for action
            
            union {
                struct {
                    u8 action_code,
                       dialog_token,
                       status_code,
                       variable[0];
                }__packed wme_action;

                struct {
                    u8 action_code,
                       variable[0];
                }__packed chan_switch;
                
                struct {
                    u8 action_code;
                    ieee80211_ext_chansw_ie data;
                    u8 variable[0];
                }__packed ext_chan_switch;

                struct {
                    u8 action_code,
                       dialog_token,
                       element_id,
                       length;
                    ieee80211_msrment_ie msr_elem;
                }__packed measurement;
                
                struct {
                    u8     action_code,
                           dialog_token;
                    __le16 capab,
                           timeout,
                           start_seq_num;
                }__packed addba_req;
                
                struct {
                    u8     action_code,
                           dialog_token;
                    __le16 status,
                           capab,
                           timeout;
                }__packed addba_resp;
                
                struct {
                    u8     action_code;
                    __le16 params,
                           reason_code;
                }__packed delba;
                
                struct {
                    u8 action_code,
                       variable[0];
                }__packed self_prot;
                
                struct {
                    u8 action_code,
                       variable[0];
                }__packed mesh_action;

                struct {
                    u8 action_code,
                       trans_id[WLAN_SA_QUERY_TR_ID_LEN];
                }__packed sa_query;
                
                struct {
                    u8 action_code,
                       smps_control;
                }__packed ht_smps;
                
                struct {
                    u8 action_code,
                       chanwidth;
                }__packed ht_notify_cw;
                
                struct {
                    u8     action_code,
                           dialog_token;
                    __le16 capability;
                    u8     variable[0];
                }__packed tdls_discover_resp;

                struct {
                    u8 action_code,
                       operating_mode;
                }__packed vht_opmode_notif;
                
                struct {
                    u8 action_code,
                       dialog_token,
                       tpc_elem_id,
                       tpc_elem_length;
                    ieee80211_tpc_report_ie tpc;
                }__packed tpc_report;
            } u;
        }__packed action;
    } u;
}__packed __aligned(2) ieee80211_mgmt_hdr;

// MGMT Type Structs, Seperate
typedef struct {
    __le16 auth_alg,
           auth_transaction,
           status_code;
    /* challenge text possible */
    ieee80211_ie ie[0];
}__packed ieee80211_auth;
        
typedef struct {
    __le16 reason_code;
}__packed ieee80211_deauth;
        
typedef struct {
    __le16 capab_info,
           listen_interval;
    /* SSID and supported rates */
    ieee80211_ie ie[0];
}__packed iee80211_assoc_req;
        
typedef struct {
    __le16 capab_info,
           status_code,
           aid;
    /* supported rates */
    ieee80211_ie ie[0];
}__packed ieee80211_assoc_resp, ieee80211_reassoc_resp;
        
typedef struct {
    __le16 capab_info,
           listen_interval;
    u8     current_ap[ETH_ALEN];
    /* SSID and supported rates */
    ieee80211_ie ie[0];
}__packed ieee80211_reassoc_req;

typedef struct {
    __le16 reason_code;
}__packed ieee80211_disassoc;

typedef struct {
    __le64 timestamp;
    __le16 beacon_int,
           capab_info;
    /* SSID, supported rates, FH params, DS params, CF params, IBSS params, TIM */
    ieee80211_ie ie[0];
}__packed ieee80211_beacon;

typedef struct {
    /* SSID, supported rates */
    ieee80211_ie ie[0];
}__packed ieee80211_probe_req;

typedef struct {
    __le64 timestamp;
    __le16 beacon_int,
           capab_info;
    /* SSID, supported rates, FH params, DS params, CF params, IBSS params */
    ieee80211_ie ie[0];
}__packed ieee80211_probe_resp;

// 802.11 Frame Header, Quality Of Service Frames
typedef struct {
    __le16 frame_control,
           duration_id;
    u8     addr1[ETH_ALEN],
           addr2[ETH_ALEN],
           addr3[ETH_ALEN];
    __le16 seq_ctrl,
           qos_ctrl;
}__packed __aligned(2) ieee80211_qos_hdr3; // 3 addrs

typedef struct {
    __le16 frame_ctl,
           duration_id;
    u8     addr1[ETH_ALEN],
           addr2[ETH_ALEN],
           addr3[ETH_ALEN];
    __le16 seq_ctrl;
    u8     addr4[ETH_ALEN];
    __le16 qos_ctrl;
}__packed __aligned(2) ieee80211_qos_hdr4; // 4 addrs

// 802.11 Frame Header, QOS HT Frames, Order Bit=1
typedef struct {
    __le16 frame_control,
           duration_id;
    u8     addr1[ETH_ALEN],
           addr2[ETH_ALEN],
           addr3[ETH_ALEN];
    __le16 seq_ctrl,
           qos_ctrl;
    __le32 ht_ctrl;
}__packed __aligned(2) ieee80211_ht_hdr3; // 3 addrs

typedef struct {
    __le16 frame_ctl,
           duration_id;
    u8     addr1[ETH_ALEN],
           addr2[ETH_ALEN],
           addr3[ETH_ALEN];
    __le16 seq_ctrl;
    u8     addr4[ETH_ALEN];
    __le16 qos_ctrl;
    __le32 ht_ctrl;
}__packed __aligned(2) ieee80211_ht_hdr4; // 4 addrs

// Union Our ieee80211 Frame Headers
typedef union {                    
    ieee80211_hdr3         ieee80211_3;        // generic 3 addrs
    ieee80211_hdr4         ieee80211_4;        // generic 4 addrs
    ieee80211_rts_hdr      ieee80211_rts;      // RTS Control
    ieee80211_cts_hdr      ieee80211_cts;      // CTS Control
    ieee80211_ack_hdr      ieee80211_ack;      // ACK Control
    ieee80211_cfend_hdr    ieee80211_cfend;    // CF-End Control
    ieee80211_cfendack_hdr ieee80211_cfendack; // CF-End + CF_Ack Control
    ieee80211_back_hdr     ieee80211_back;     // BACK Control
    ieee80211_backreq_hdr  ieee80211_backreq;  // BAR(BACK-Req) Control
    ieee80211_ctrlext_hdr  ieee80211_ctrlext;  // Ctrl-Ext(Control Extension) Wrapper
    ieee80211_pspoll_hdr   ieee80211_pspoll;   // PS-Poll Control
    ieee80211_mgmt_hdr     ieee80211_mgmt;     // Management
    ieee80211_qos_hdr3     ieee80211_qos_3;    // Quality Of Service Data 3 addrs
    ieee80211_qos_hdr4     ieee80211_qos_4;    // Quality Of Service Data 4 addrs
    ieee80211_ht_hdr3      ieee80211_ht_3;     // QOS HT 3 addrs
    ieee80211_ht_hdr4      ieee80211_ht_4;     // QOS HT 4 addrs
    const unsigned char    ieee80211_craw;     // const raw header
          unsigned char    ieee80211_raw;      // raw raw header, carefual not to mutate data
} u_ieee80211_hdrs;

// Logical Link Control(upper data-link) Frame Header, 802.2
typedef struct {
    // LLC Header Start
    u8 dsap,       // destination service access point
       ssap,       // source      service access point
       ctrl1;      // LLC control field frame type, 1st octet (U-format)
     //ctrl2;      //                             , 2nd octet (I/S-formats)
}__packed llc_hdr;

// SubNetwork Access Protocol(upper data-link LLC extension) Frame Header
#define IEEE80211_SNAP_ETH_802_3_ON  true  // for printing the headers
#define IEEE80211_SNAP_ETH_802_3_OFF false

typedef struct {
    // SNAP Extension Header Start
    u8     oui[OUI_LEN]; // organizationally unique identifier, 3 octets
    __be16 ether_type;   // for backwards compatability with ethernet II frame
}__packed snap_hdr;

// LLC + SNAP Frame Header
typedef struct {
    // LLC Header Start
    u8     dsap,         // destination service access point
           ssap,         // source      service access point
           ctrl1;        // LLC control field frame type, 1st octet
         //ctrl2;        //                             , 2nd octet
    // SNAP Extension Header Start
    u8     oui[OUI_LEN]; // organizationally unique identifier
    __be16 ether_type;   // for backwards compatability with ethernet II frame
}__packed llc_snap_hdr; // combined LLC + SNAP Extension

typedef struct {
    u16 protoID;
    u8  version,
        msg_type,
        flags;
    u8  rootID[8];   // 16 bit priority, 48 bit mac
    u32 root_pathCost;
    u8  bridgeID[8]; // 16 but priority, 48 bit mac
    u16 portID,
        msg_age,
        max_time,
        hello_time,
        fwrd_delay;
} __packed stphdr;

// Declare Our Own ARP Header For Non-Commented Out Addresses
typedef struct {
    __be16 ar_hrd,
           ar_pro;
    u8     ar_hln,
           ar_pln;
    __be16 ar_op;
    u8     ar_sha[ETH_ALEN],
           ar_sip[IP_ALEN],
           ar_tha[ETH_ALEN],
           ar_tip[IP_ALEN];
} arphdr2;
 
// Declare Our Own SCTP Header
typedef struct {
    __be16 source,
           dest;
    __be32 vtag,
           checksum;
} sctphdr2;
 
// Declare Our Own SCTP Chunk Header
typedef struct {
    u8     type,
           flags;
    __be16 length;
} sctp_chunkhdr2;

// Declare Out Own IPv6 Header
typedef struct {
#if defined(__LITTLE_ENDIAN_BITFIELD) // bitfields
    u8 priority:4,                    // 4 bits(nibble)
       version :4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    u8 version :4,
       priority:4;
#else
#error "fix <asm/byteorder.h>"
#endif

    u8       flow_lbl[IPV6_FLOW_LBL_LEN];
    __be16   payload_len;
    u8       nexthdr,
             hop_limit;
    in6_addr saddr,
             daddr;
} ipv6hdr;

typedef struct {
    u8  type,
        code;
    u16 cksum;

    /*union { // need if directly adding data through memcpy...
        u32 u_data32[1];
        u16 u_data16[2];
        u8  u_data8[4];
    } udata;*/
} icmpv6hdr;

// Extensible Authentication Protocol, PAE 802.1X
typedef struct {
    u8  code,
        eapid;
    u16 length; ///////////////////////////////////////////////////////////////////////////////////fix eap
}__packed EAP_hdr;

// Extensible Authentication Protocol Over LAN, EAPoL
typedef struct {
    u8  version,
        type;
    u16 length;
}__packed eapolhdr;

enum eap_type {
    EAP_PACKET = 0,
    EAPOL_START,
    EAPOL_LOGOFF,
    EAPOL_KEY,
    EAPOL_ENCAP_ASF_ALERT
};

