/** 
 * Header file containing structures and defines for creating files in the pcap ng format. Designed for import into Wireshark
 */

#ifndef _PCAP_NG_HEADER_
#define _PCAP_NG_HEADER_

struct pcap_ng_block_header {
	uint32_t block_type;
	uint32_t block_total_length;
}; // __attribute__((packed));

struct pcap_ng_block_footer {
	uint32_t block_total_length;
} __attribute__((packed));;

#define BLOCK_TYPE_SECTION_HEADER_BLOCK 0x0A0D0D0A

struct pcap_ng_minimal_section_header_block {
	struct pcap_ng_block_header block_header;
	uint32_t byte_order_magic;
	uint16_t major_version;
	uint16_t minor_version;
	uint64_t section_length;
	//uint8 options
	struct pcap_ng_block_footer block_footer; 
} __attribute__((packed)); 
#define SECTION_HEADER_MAGIC 0x1a2b3c4d
#define SECTION_HEADER_MAJOR_VER 0
#define SECTION_HEADER_MINOR_VER 1
typedef struct { 
	uint16_t  code;
	uint16_t  length;
	uint8_t   data[1];
} BLOCK_OPTION_HEADER_T;
	
struct pcap_ng_options_flag { 
	uint16_t  code;
	uint16_t  length;
	uint32_t  options_flag;
} __attribute((packed));

#define OPTIONS_EPB_FLAG 0x2
#define OPTIONS_INBOUND  0x1
#define OPTIONS_OUTBOUND  0x2

#define SECTION_LENGTH_UNKNOWN 0xFFFFFFFFFFFFFFFF

struct pcap_ng_minimal_interface_description_block {
	struct pcap_ng_block_header block_header;
	uint16_t link_type;
	uint16_t reserved;
	uint32_t snap_len;
	//uint8  options
	struct pcap_ng_block_footer block_footer;
} __attribute__((packed)); 

struct pcap_ng_enhanced_packet_block_header {
	struct pcap_ng_block_header block_header;
	uint32_t interface_id;
	uint32_t timestamp_high;
	uint32_t timestamp_low;
	uint32_t captured_packet_length;
	uint32_t original_packet_length;
	//uint32_t packet_data[21];
	//struct pcap_ng_block_footer block_footer;
} __attribute__((packed));

typedef enum {
	SECTION_HEADER_BLOCK = 0x0A0D0D0A,
	INTERFACE_DESCRIPTION = 0x00000001, 
	ENHANCED_PACKET = 6 ,
} block_type;

typedef enum {
	LINK_TYPE_ETHERNET  = 1,
	LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201,
	LINKTYPE_NFC_LLCP = 245,
	LINKTYPE_ISO_14443 = 265
} link_type;

#endif // _PCAP_NG_HEADER_
