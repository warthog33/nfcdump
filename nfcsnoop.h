/** 
 * Structure of records stored in the default AOSP implementation of the NFC log
 */
#ifndef _DEBUG_NFCSNOOP_
#define _DEBUG_NFCSNOOP_

#include <stdint.h>


#define NFCSNOOZ_CURRENT_VERSION 0x01

// The preamble is stored un-encrypted as the first part
// of the file.
typedef struct nfcsnooz_preamble_t {
  uint8_t version;
  uint64_t last_timestamp_ms;
} __attribute__((__packed__)) nfcsnooz_preamble_t;

// One header for each NCI packet
typedef struct nfcsnooz_header_t {
  uint16_t length;
  uint32_t delta_time_ms;
  uint8_t is_received;
} __attribute__((__packed__)) nfcsnooz_header_t;

#endif /* _DEBUG_NFCSNOOP_ */
