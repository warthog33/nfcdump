#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <zlib.h>
#include <time.h>
#include <openssl/aes.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <resolv.h>

#include "nfcsnoop.h"
#include "pcapng.h"


/* NCI Command and Notification Format:
 * 3 byte message header:
 * byte 0: MT PBF GID
 * byte 1: OID
 * byte 2: Message Length */
/* MT: Message Type (byte 0) */
#define NCI_MT_MASK         0xE0
#define NCI_MT_SHIFT        5
#define NCI_MT_DATA         0x00
#define NCI_MT_CMD          1   /* (NCI_MT_CMD << NCI_MT_SHIFT) = 0x20 */
#define NCI_MT_RSP          2   /* (NCI_MT_RSP << NCI_MT_SHIFT) = 0x40 */
#define NCI_MT_NTF          3   /* (NCI_MT_NTF << NCI_MT_SHIFT) = 0x60 */
#define NCI_MT_CFG          4   /* (NCI_MT_CFG << NCI_MT_SHIFT) = 0x80 */

#define NCI_MTS_CMD         0x20
#define NCI_MTS_RSP         0x40
#define NCI_MTS_NTF         0x60
#define NCI_MTS_CFG         0x80

/* GID: Group Identifier (byte 0) */
#define NCI_GID_MASK        0x0F
#define NCI_GID_SHIFT       0
#define NCI_GID_CORE        0x00    /* 0000b NCI Core group */
#define NCI_GID_RF_MANAGE   0x01    /* 0001b RF Management group */
#define NCI_GID_EE_MANAGE   0x02    /* 0010b NFCEE Management group */
#define NCI_GID_PROP        0x0F    /* 1111b Proprietary */

/* OID: Opcode Identifier (byte 1) */
#define NCI_OID_MASK        0x3F
#define NCI_OID_SHIFT       0

/**********************************************
 * NCI Core Group Opcode        - 0
 **********************************************/
#define NCI_MSG_CORE_RESET              0
#define NCI_MSG_CORE_INIT               1
#define NCI_MSG_CORE_SET_CONFIG         2
#define NCI_MSG_CORE_GET_CONFIG         3
#define NCI_MSG_CORE_CONN_CREATE        4
#define NCI_MSG_CORE_CONN_CLOSE         5
#define NCI_MSG_CORE_CONN_CREDITS       6
#define NCI_MSG_CORE_GEN_ERR_STATUS     7
#define NCI_MSG_CORE_INTF_ERR_STATUS    8
#define NCI_MSG_CORE_SET_POWER_SUB_STATE 9

/**********************************************
 * RF MANAGEMENT Group Opcode    - 1
 **********************************************/
#define NCI_MSG_RF_DISCOVER_MAP         0
#define NCI_MSG_RF_SET_ROUTING          1
#define NCI_MSG_RF_GET_ROUTING          2
#define NCI_MSG_RF_DISCOVER             3
#define NCI_MSG_RF_DISCOVER_SELECT      4
#define NCI_MSG_RF_INTF_ACTIVATED       5
#define NCI_MSG_RF_DEACTIVATE           6
#define NCI_MSG_RF_FIELD                7
#define NCI_MSG_RF_T3T_POLLING          8
#define NCI_MSG_RF_EE_ACTION            9
#define NCI_MSG_RF_EE_DISCOVERY_REQ     10
#define NCI_MSG_RF_PARAMETER_UPDATE     11
#define NCI_MSG_RF_ISO_DEP_NAK_PRESENCE 16
/**********************************************
 * NFCEE MANAGEMENT Group Opcode - 2
 **********************************************/
#define NCI_MSG_NFCEE_DISCOVER          0
#define NCI_MSG_NFCEE_MODE_SET          1


bool outputpcap = false;

const char* GetGid ( unsigned char gid )
{
	static char buffer[100];
	if ( gid == NCI_GID_CORE )
		return "Core";
	else if ( gid == NCI_GID_RF_MANAGE )
		return "RF Manage";
	else if ( gid == NCI_GID_EE_MANAGE )
		return "EE Manage";
	else if ( gid == NCI_GID_PROP )
		return "Proprietary";
	else
		snprintf ( buffer, sizeof(buffer), " **Unknown** (%02x)", gid ); 
	return buffer;
}

const char* GetOid ( unsigned char oid, unsigned char gid )
{
	static char buffer[100];
	if ( gid == NCI_GID_CORE )
	{
	switch ( oid )
	{
	case NCI_MSG_CORE_RESET:
		return "Core Reset";
	case NCI_MSG_CORE_INIT:
		return "Core Init";
	case NCI_MSG_CORE_SET_CONFIG:
		return "Core Set Config";
	case NCI_MSG_CORE_GET_CONFIG:
		return "Core Get Config";
	case NCI_MSG_CORE_CONN_CREATE:
		return "Core Conn Create";
	case NCI_MSG_CORE_CONN_CLOSE:
		return "Core Conn Close";
	case NCI_MSG_CORE_CONN_CREDITS:
		return "Core Conn Credits";
	case NCI_MSG_CORE_GEN_ERR_STATUS:
		return "Core Gen Err Status";
	case NCI_MSG_CORE_INTF_ERR_STATUS:
		return "Core Intf Err Status";
	case NCI_MSG_CORE_SET_POWER_SUB_STATE:
		return "Core Set Power Sub State";
	}
	}
	else if ( gid == NCI_GID_RF_MANAGE )
	{
	switch ( oid )
	{
	case NCI_MSG_RF_DISCOVER_MAP:
		return "RF Discover Map";
	case NCI_MSG_RF_SET_ROUTING:
		return "RF Set Routing";
	case NCI_MSG_RF_GET_ROUTING:
		return "RF Get Routing";
	case NCI_MSG_RF_DISCOVER:
		return "RF Discover";
	case NCI_MSG_RF_DISCOVER_SELECT:
		return "RF Discover Select";
	case NCI_MSG_RF_INTF_ACTIVATED :
		return "RF Intf Activated";
	case NCI_MSG_RF_DEACTIVATE:
		return "RF Deactivate";
	case NCI_MSG_RF_FIELD:
		return "RF Field";
	case NCI_MSG_RF_T3T_POLLING:
		return "RF T3T Polling";
	case NCI_MSG_RF_EE_ACTION:
		return "RF EE Action";
	case NCI_MSG_RF_EE_DISCOVERY_REQ:
		return "RF EE Discovery";
	case NCI_MSG_RF_PARAMETER_UPDATE:
		return "RF Param Update";
	case NCI_MSG_RF_ISO_DEP_NAK_PRESENCE:
		return "RF ISO DEP NAK Prescence";
	}
	}
	else if ( gid == NCI_GID_EE_MANAGE )
	{
	switch (oid)
	{
	case NCI_MSG_NFCEE_DISCOVER: 
		return "NFC EE Discover";
	case NCI_MSG_NFCEE_MODE_SET:
		return "NFC EE Mode Set";
	}
	}
	else if ( gid == NCI_GID_PROP)
	{
	switch (oid)
	{
	case 5: 
		return "Proprietary(5)";
	}
	}
	snprintf ( buffer, sizeof(buffer), "**Unknown** (%02x)", oid );
	return buffer;
}


void OutputPcapHeader ()
{
	struct pcap_ng_minimal_section_header_block shb;
	shb.block_header.block_type = SECTION_HEADER_BLOCK;
	shb.block_header.block_total_length = sizeof(shb);
	shb.byte_order_magic = SECTION_HEADER_MAGIC;
	shb.major_version = SECTION_HEADER_MAJOR_VER;
	shb.major_version = SECTION_HEADER_MINOR_VER;
	shb.section_length = SECTION_LENGTH_UNKNOWN;
	shb.block_footer.block_total_length = sizeof(shb);
	
	write ( STDOUT_FILENO, &shb, sizeof(shb));

	struct pcap_ng_minimal_interface_description_block idb;
	idb.block_header.block_type = INTERFACE_DESCRIPTION;
	idb.block_header.block_total_length = sizeof(idb);
	idb.link_type = LINKTYPE_NFC_LLCP; //LINKTYPE_ISO_14443; //LINKTYPE_NFC_LLCP; //LINK_TYPE_BLUETOOTH; //LINK_TYPE_ETHERNET;
	idb.reserved = 0;
	idb.snap_len = 0x40000;
	idb.block_footer.block_total_length = sizeof(idb);

	write ( STDOUT_FILENO, &idb, sizeof(idb));
}


void OutputPcapRecord ( uint64_t timestamp, int captured_length, int original_length, uint8_t* data, uint32_t optionsflag)
{
	int alignedlength = (( captured_length + 3 + 2) & 0xFFFFC );

	//fprintf ( stderr, "OutputPcapRecord ts=%li cl=%i ol=%i op=%i\n", timestamp, captured_length, original_length, optionsflag );
	//fflush(stdout);

	int recordlen = sizeof(struct pcap_ng_enhanced_packet_block_header) 
		+ alignedlength 
		+ sizeof ( struct pcap_ng_options_flag )
		+ sizeof ( struct pcap_ng_block_footer );

	uint8_t* record = (uint8_t*)calloc ( recordlen, 1 );

	struct pcap_ng_enhanced_packet_block_header* epb = 
		(struct pcap_ng_enhanced_packet_block_header*)record;

	epb->block_header.block_type = ENHANCED_PACKET;
	epb->block_header.block_total_length = recordlen;
	epb->interface_id = 0;
	epb->timestamp_high = timestamp >> 32;
	epb->timestamp_low = (uint32_t)timestamp;
	epb->captured_packet_length = captured_length + 2;// + sizeof(epb->reserved);
	epb->original_packet_length = original_length + 2;// + sizeof(epb->reserved);
	//epb->reserved = 0;

	memset ( record + sizeof(struct pcap_ng_enhanced_packet_block_header), 0, 2 );
	memcpy ( record + sizeof(struct pcap_ng_enhanced_packet_block_header) + 2, data, captured_length );

	struct pcap_ng_options_flag* of = (struct pcap_ng_options_flag*)(record+
		sizeof(struct pcap_ng_enhanced_packet_block_header) + alignedlength );

	of->code = OPTIONS_EPB_FLAG;
	of->length = sizeof(of->options_flag);
	of->options_flag = optionsflag;

	struct pcap_ng_block_footer* ft = 
		(struct pcap_ng_block_footer*)(record+recordlen-sizeof(struct pcap_ng_block_footer));
	//ft->null_options = 0;
	ft->block_total_length = recordlen;

	write ( STDOUT_FILENO, record, recordlen);

	free ( record);
}

/*int base64_decode ( char* input, int inputlen, unsigned char* output, int outputlen )
{
	int l = 0;
	for ( int i = 0; i < inputlen; i+= 3 )
		;//l = b64_pton ( input+i, output+i );
	return l;
}*/

int Decrypt()
{
	return 0;
}

int Decompress (unsigned char* input, int inputlen, unsigned char* output, int maxoutputlen)
{
	z_stream zs;
	zs.avail_in = Z_NULL;
	zs.next_in = Z_NULL;
	zs.zalloc = Z_NULL;
	zs.zfree = Z_NULL;
	zs.opaque = Z_NULL;

	int iirc = inflateInit(&zs );
	if ( iirc != Z_OK )
		fprintf ( stderr, "inflateInit = %i\n", iirc );
	
	zs.next_in = input; //+sizeof(nfcsnooz_preamble_t) ;
	zs.avail_in = inputlen; //-sizeof(nfcsnooz_preamble_t);
	zs.avail_out = maxoutputlen;
	zs.next_out = output;

	//int err = deflate(&zs, (i == num_blocks - 1) ? Z_FINISH : Z_NO_FLUSH);

	int err = inflate ( &zs, Z_NO_FLUSH); 
	if ( err != Z_STREAM_END )
		fprintf ( stderr, "err = %i zs.avail_out=%i\n", err, zs.avail_out );
		
	return maxoutputlen - zs.avail_out; 
}

int IsText ( unsigned char* input, int inputlen )
{
	for ( int i = 0; i < inputlen; i++ )
	{
		if ( isascii(input[i]) == 0 && input[i] != 0xc2 /* copyright character*/ && input[i] != 0xA0) 
		{
			fprintf ( stderr, "Non asii %02x found at offset %i\n", input[i], i ); 
			return false;
		}
	}
	return true;
}

bool IsSamsungLog (char* input, int inputlen )
{
	char* offset1 = strstr ( input, "PERSIST LOG START" );
       	char* offset2 = strstr ( input, "PERSIST LOG END" );

	//fprintf (stderr, "offset1=%p offset2=%p\n", offset1, offset2 );
	//printf ( "input=%s", input );
	if ( offset1 == NULL || offset2 == NULL )
	 return false;

	return offset2 > offset1;
}

bool IsLogCatLog (char* input, int inputlen)
{
	char* offset1 = strstr ( input, "NxpNciX : len =" );
	char* offset2 = strstr ( input, "NxpNciR : len =" );
	if ( offset1 == NULL || offset2 == NULL )
		return false;
	return true;
}


bool IsDefaultLog (char* input, int inputlen )
{
	char* offset1 =  strstr ( input, "SUMMARY START" );
       	char* offset2 = strstr (input, "LOG SUMMARY END" );
	if ( offset1 == NULL || offset2 == NULL )
	 return false;

	return offset2 > offset1;
}

bool IsNfcSnoopLog (char* input, int inputlen )
{
	char* offset1 =  strstr ( input, "BEGIN:NFCSNOOP_LOG_SUMMARY" );
       	char* offset2 = strstr (input, "END:NFCSNOOP_LOG_SUMMARY" );
	if ( offset1 == NULL || offset2 == NULL )
	 return false;

	return offset2 > offset1;
}
/////////////////////////////////////////////////////////////////////
//
//
int DecodeSamsungLog (char* input, unsigned char* output, int maxlen)
{
	int outputlen = 0;
	bool foundStart = false;
	for ( char* line = strtok ( input, "\r\n" ); line != NULL; line = strtok (NULL, "\r\n" ))
	{
		if ( foundStart == false )
		{
			if (strcmp (line, "PERSIST LOG START" ) == 0)
				foundStart = true;
		}
		else
		{
			if (strcmp(line, "PERSIST LOG END" ) == 0 )
				break;
				
			int decodedLineLen = b64_pton(line, output+outputlen, maxlen-outputlen);
			if ( decodedLineLen > 0 )
				outputlen += decodedLineLen;
			else
				printf ( "Error in base 64 decode %s %i\n", line, maxlen-outputlen );
		}
	}
	return outputlen;
}

int DecryptSamsungLog (unsigned char* input, int inputlen, unsigned char* output, int maxlen )
{
	//unsigned char decrypted[sizeof(input)];
	AES_KEY wctx;

	const char* b64_keys[] = { "vhvewKp0tNyweZQ+cFKAlg==", "bVpxNHQ3dyF6JUMqRi1KQA==" };

	for ( int j = 0; j < sizeof(b64_keys)/sizeof(b64_keys[0]); j++ )
	{
		
		unsigned char key[100]; 
	//int keylen = b64_pton("vhvewKp0tNyweZQ+cFKAlg==", key, sizeof(key));
		int keylen = b64_pton(b64_keys[j], key, sizeof(key));

	//fprintf ( stderr, "key (%i)%02x %02x %02x %02x %02x %02x %02x %02x", keylen, key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7] );
	//fprintf ( stderr, " %02x %02x %02x %02x %02x %02x %02x %02x\n", key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15] );

		if ( inputlen > maxlen ) {
			printf ( "Input length too long for DecryptSamsungLog\n" );
			return 0;
		}
	
		if ( AES_set_decrypt_key ( key, keylen*8, &wctx ) != 0 )
			printf ( "Error setting key\n" );

		if ( inputlen % 16 )
			printf ( "Input not multiple of 16, %i , %i\n", inputlen, inputlen%16);
	//AES_cbc_encrypt ( input, output, inputlen, &wctx, NULL, AES_DECRYPT ); 
	//
	
		for ( int i = 0; i < inputlen; i+=16 )	
	//AES_decrypt ( input, output, &wctx );
			AES_decrypt ( input+i, output+i, &wctx );

	// Remove Padding
		int outputLen = inputlen - output[inputlen-1];
		output[outputLen] = '\0';


	//for ( int i = 0; i < 100; i++ )
	//	printf ( "%02x ", output[i]);
	//
		if ( IsText ( output, outputLen ))
			return outputLen;
	}
	printf ( "Unable to decrypt log" );
	return 0;
	

        //AES_encrypt(input, decrypted, &wctx);

	//for ( int i = 0 ; i < 100; i++)
	//	printf ( "%02x ", decrypted[i] );
}

int DecodeNfcSnoopLog (char* input, unsigned char* output, int maxlen)
{
	int outputlen = 0;
	bool foundStart = false;
	for ( char* line = strtok ( input, "\r\n" ); line != NULL; line = strtok (NULL, "\r\n" ))
	{
		if ( foundStart == false )
		{
			if (strstr (line, "BEGIN:NFCSNOOP_LOG_SUMMARY" ) != 0)
				foundStart = true;
		}
		else
		{
			if (strstr(line, "END:NFCSNOOP_LOG_SUMMARY" ) != 0 )
				break;
				
			int decodedLineLen = b64_pton(line, output+outputlen, maxlen-outputlen);
			if ( decodedLineLen > 0 )
				outputlen += decodedLineLen;
			else
				printf ( "Error in base 64 decode %s %i\n", line, maxlen-outputlen );
		}
	}
	return outputlen;
}

void DumpNciMessage ( unsigned char* input, int inputlen , timeval* tv, bool isincoming)
{
	unsigned char* currpos = input;

	//printf ( "%02x %02x  %02x %02x %02x %02x  %02x Len=%i Delta_Time_ms=%u IsRcvd=%i\n", currpos[0], currpos[1], currpos[2], currpos[3], currpos[4], currpos[5], currpos[6], hdr->length, hdr->delta_time_ms, hdr->is_received );   

	unsigned char* payload = (unsigned char*)input; 

	printf ( "%li.%li:  %02x %02x %02x              ", tv->tv_sec, (long)tv->tv_usec, payload[0], payload[1], payload[2] );

	switch ( payload[0] >> NCI_MT_SHIFT)
	{
	case NCI_MT_DATA:
		printf ( "NCI_MT_DATA ConnId=%x    Len=%02x", payload[0]&0xf, payload[2]);
		if ( payload[1] )
			printf ( " RFU=%02x", payload[1] );
		break;
	case  NCI_MT_CMD:
		printf ( "NCI_MT_CMD Oid=\'%s\' Len=%02x ", GetOid(payload[1], payload[0]&NCI_GID_MASK), payload[2] ); 
		break;
	case NCI_MT_RSP:
		printf ( "NCI_MT_RSP Oid=\'%s\' Len=%02x ", GetOid(payload[1], payload[0]&NCI_GID_MASK), payload[2] ); 
		break;
	case NCI_MT_NTF:
		printf ( "NCI_MT_NTF Oid=\'%s\' Len=%02x ", GetOid( payload[1], payload[0]&NCI_GID_MASK), payload[2] ); 
		break;
	case NCI_MT_CFG:
		printf ( "NCI_MT_CFG ");
		break;
	default:
		printf ( "NCI_Unknown" );
		break;
	}

	if ( payload[0]>>4 & 1 )
		printf ( " PBF ");	

	//printf ( "PBF=%01x Info=%x OID=%02x Len=%02x ", payload[0]>>4 & 0x1, payload[0]&0xF,  payload[1], payload[2] ); 

	if ( inputlen > 3 )	
	{
		printf ( "\n  " );	
		for ( int j = 3; j < inputlen; j++ )
			printf ( "%02x ", payload[j]);
	}

	printf ( "\n" );
}

void DumpNciLog ( unsigned char* input, int inputlen )
{
	if ( outputpcap )
		OutputPcapHeader();

	unsigned char* currpos = input;
	while ( currpos  < input + inputlen ) 
	//for ( int i = 0; i<100;  i++)
	{
		nfcsnooz_header_t* hdr = (nfcsnooz_header_t*)currpos;	
		unsigned char* payload = (unsigned char*)&hdr[1]; 

		if ( outputpcap )
		{
			OutputPcapRecord ( hdr->delta_time_ms, hdr->length, 3+payload[2], payload, hdr->is_received==1? OPTIONS_INBOUND : OPTIONS_OUTBOUND );
		}
		else
		{
			printf ( "%02x %02x  %02x %02x %02x %02x  %02x Len=%i Delta_Time_ms=%u IsRcvd=%i\n", currpos[0], currpos[1], currpos[2], currpos[3], currpos[4], currpos[5], currpos[6], hdr->length, hdr->delta_time_ms, hdr->is_received );   
			printf ( " %02x %02x %02x              ", payload[0], payload[1], payload[2] );
			switch ( payload[0] >> NCI_MT_SHIFT)
			{
			case NCI_MT_DATA:
				printf ( "NCI_MT_DATA ConnId=%x    Len=%02x", payload[0]&0xf, payload[2]);
				if ( payload[1] )
					printf ( " RFU=%02x", payload[1] );
				break;
			case  NCI_MT_CMD:
				printf ( "NCI_MT_CMD Oid='%s' Len=%02x ", GetOid(payload[1], payload[0]&NCI_GID_MASK), payload[2] ); 
				break;
			case NCI_MT_RSP:
				printf ( "NCI_MT_RSP Oid='%s' Len=%02x ", GetOid(payload[1], payload[0]&NCI_GID_MASK), payload[2] ); 
				break;
			case NCI_MT_NTF:
				printf ( "NCI_MT_NTF Oid='%s' Len=%02x ", GetOid( payload[1], payload[0]&NCI_GID_MASK), payload[2] ); 
				break;
			case NCI_MT_CFG:
				printf ( "NCI_MT_CFG ");
				break;
			default:
				printf ( "NCI_Unknown" );
				break;
			}

			if ( payload[0]>>4 & 1 )
				printf ( " PBF ");	
			if ( hdr->length > 3 )	
			{
				printf ( "\n  " );	
				for ( int j = 3; j < hdr->length; j++ )
					printf ( "%02x ", payload[j]);
			}

			printf ( "\n" );
		}
		
		//printf ( "PBF=%01x Info=%x OID=%02x Len=%02x ", payload[0]>>4 & 0x1, payload[0]&0xF,  payload[1], payload[2] ); 

		
		//hdr = (nfcsnooz_header_t*)((char*)hdr + hdr->length + sizeof(nfcsnooz_header_t));
		currpos += sizeof(nfcsnooz_header_t)+hdr->length;
		
	} 
}
bool IsBinaryDefaultLog ( unsigned char* input, int inputLen )
{
	if ( inputLen < sizeof(nfcsnooz_header_t))
		return false;

	nfcsnooz_preamble_t* hdr = (nfcsnooz_preamble_t*)input;	
	if ( hdr->version == 1 )
		return true;
	return false;
}
int DecodeBinaryDefaultLog ( unsigned char* input, int inputlen )
{
	//nfcsnooz_header_t* hdr = (nfcsnooz_header_t*)input;	
	//unsigned char* payload = (unsigned char*)&hdr[1]; 
	//printf ( "Len=%02i TimeOffset=%08i is_received=%i ", hdr->length, hdr->delta_time_ms, hdr->is_received );

	nfcsnooz_preamble_t* pre = (nfcsnooz_preamble_t*)input;
	fprintf ( stderr, "inputlen=%i\n", inputlen );
	fprintf ( stderr, "nfcsnooz_preamble.version=%i nfcsnooz_preamble.last_timestamp_ms=%lui\n", pre->version, (unsigned long)pre->last_timestamp_ms );

	unsigned char output[1000000] = {0xFF};
	int outputlen = Decompress ( input+sizeof(nfcsnooz_preamble_t), inputlen-sizeof(nfcsnooz_preamble_t), output, sizeof(output));


	fprintf ( stderr, "Decompressed size=%i\n", outputlen );
	//for ( int i = 0 ; i < outputlen; i++)
	//	printf ( "%02x ", output[i] );

	DumpNciLog ( output, outputlen );	

        //AES_set_encrypt_key(key, 128, &wctx);
	//Decrypt();
	return outputlen;
}




typedef void (*LOGNCIPACKET)(uint8_t * rawncimessage, int len, timeval* tv, bool isinbound );

void SamsungTextLogToBinary ( char* input, int inputlen, LOGNCIPACKET functocall )
{
	char line[1000];
	//char time2[100];
	int millsecs;
	char direc[100];
	int  len;
	struct timeval tv = {0};
	char remainder[1000];
	uint8_t bytes[1000];
	//struct tm t = {0};
	time_t tt;
	time(&tt);
	struct tm* t = localtime(&tt);
	
	for ( char* line = strtok ( input, "\r\n" ); line != NULL; line = strtok (NULL, "\r\n" ))
	{
		//printf ( "line=%s\n", line );
		t = localtime(&tt); 
		int rc = sscanf ( line, "%2d-%2d %2d:%2d:%2d.%i%[^(](%i) %[^\n]\n", 
			&t->tm_mon, &t->tm_mday, &t->tm_hour, &t->tm_min, &t->tm_sec,
			&millsecs, direc, &len, remainder );

		//printf ( "mon=%i mday=%i hour=%i min=%i sec=%i\n", t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec );
		// Check for full line
		if ( rc != 9 )
			continue;

		char* token;
    		char* rest = remainder;
		int i = 0;

		//fprintf ( stderr, "remainder=%s\n", rest );

    		while ((token = strtok_r(rest, " ", &rest)))
		{
			fprintf ( stderr, "i=%i b=%s", i, token);
			bytes[i++] = strtoul ( token, NULL, 16 );
		}
		if ( i != len )
			fprintf ( stderr, "Error parsing chars\n" );

		
		//len = 76;
		timeval tv = {mktime(t), millsecs}; 	
		//int64_t timestamp = (int64_t)((int32_t)mktime(&t)) * 1000 + millsecs;
		fprintf ( stderr, "Direct=%s", direc);
		functocall ( bytes, len, &tv, direc[0]=='R'? true: false );

			//OutputPcapRecord ( timestamp, len, len, bytes, direc[0]=='R'? OPTIONS_INBOUND : OPTIONS_OUTBOUND );

		//fprintf ( stdout, "rc=%i ts=%li direc=%s len=%i r=%s bytes[0]=%02x\n", rc, timestamp, direc, len, remainder, bytes[0] );


	}
}
void SamsungLogToPcap ( char* input, int inputlen )
{
	char line[1000];
	char time[100];
	int millsecs;
	char direc[100];
	int  len;
	struct tm t = {0};
	char remainder[1000];
	uint8_t bytes[1000];
	
	OutputPcapHeader ();

	for ( char* line = strtok ( input, "\r\n" ); line != NULL; line = strtok (NULL, "\r\n" ))
	{
		fprintf ( stderr, "line=%s\n", line );
		int rc = sscanf ( line, "%2d-%2d %2d:%2d:%2d.%i  %[^(](%i) %[^\n]\n", 
			&t.tm_mon, &t.tm_mday, &t.tm_hour, &t.tm_min, &t.tm_sec,
			&millsecs, direc, &len, remainder );

		//fprintf ( stderr, "mon=%i mday=%i hour=%i min=%i sec=%i rc=%i\n", t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, rc );
		// Check for full line
		if ( rc == 9 )
		{
			char* token;
    			char* rest = remainder;
			int i = 0;


    			while ((token = strtok_r(rest, " ", &rest)))
			{
				//fprintf ( stderr, "i=%i b=%s", i, token );
				bytes[i++] = strtoul ( token, NULL, 16 );
			}
			if ( i != len )
				fprintf ( stderr, "Error parsing chars\n" );

		
			//len = 76;	
			int64_t timestamp = (int64_t)((int32_t)mktime(&t)) * 1000 + millsecs;

			fprintf ( stderr, "D=%s", direc);
			OutputPcapRecord ( timestamp, len, len, bytes, direc[0]=='R'? OPTIONS_INBOUND : OPTIONS_OUTBOUND );
			
		}

		//fprintf ( stdout, "rc=%i ts=%li direc=%s len=%i r=%s bytes[0]=%02x\n", rc, timestamp, direc, len, remainder, bytes[0] );
		rc = sscanf ( line, "%2d-%2d %2d:%2d:%2d.%i  NxpNci%c%i > %[^\n]\n", 
			&t.tm_mon, &t.tm_mday, &t.tm_hour, &t.tm_min, &t.tm_sec,
			&millsecs, direc, &len, remainder );
		if ( rc == 9 )
		{
			int i;
			char temp[3];
			for ( i = 0; remainder[i*2] >= '0'; i++ )
			{
				//fprintf ( stderr, "remainder[i*2] = %02x,%02x i=%i\n", remainder[i*2], remainder[i*2+1],i);
				temp[0] = remainder[i*2];
				temp[1] = remainder[i*2+1];
				temp[2] = '\0';
				
				bytes[i] = strtoul(temp, NULL, 16 );
			}
			if ( i != len )
				fprintf ( stderr, "Error parsing chars i=%i len=%i bytes[0]=%x\n", i, len, bytes[0] );

			int64_t timestamp = (int64_t)((int32_t)mktime(&t)) * 1000 + millsecs;

			//fprintf ( stderr, "D=%s", direc);
			OutputPcapRecord ( timestamp, len, len, bytes, direc[0]=='R'? OPTIONS_INBOUND : OPTIONS_OUTBOUND );
		}

	}
}

void LogCatToPcap ( char* input, int inputlen )
{
	char line[1000];
	char time[100];
	int millsecs;
	int pid;
	int tid;
	char priority;
	char direc[100];
	int  len;
	struct tm t = {0};
	int txcount = 0, rxcount = 0;
	char remainder[1000];

	uint8_t bytes[1000];
	
	OutputPcapHeader ();

	for ( char* line = strtok ( input, "\r\n" ); line != NULL; line = strtok (NULL, "\r\n" ))
	{
		//fprintf ( stderr, "line=%s\n", line );
		int rc = sscanf ( line, "%2d-%2d %2d:%2d:%2d.%i  %i %i %c NxpNci%s : len =%i > %s", 
			&t.tm_mon, &t.tm_mday, &t.tm_hour, &t.tm_min, &t.tm_sec,
			&millsecs, &pid, &tid, &priority, direc, &len, remainder );
		//fprintf ( stderr, "LogCatToPcap line=%s rc=%i\n", line, rc );
		if ( rc < 12 )
			continue;
		//fprintf ( stderr, "LogCatToPcap line=%s rc=%i\n", line, rc );

		int i;
		char temp[3];
		for ( i = 0; remainder[i*2] >= '0'; i++ )
		{
			//fprintf ( stderr, "remainder[i*2] = %02x,%02x i=%i\n", remainder[i*2], remainder[i*2+1],i);
			temp[0] = remainder[i*2];
			temp[1] = remainder[i*2+1];
			temp[2] = '\0';
			
			bytes[i] = strtoul(temp, NULL, 16 );
		}
		if ( i != len )
			fprintf ( stderr, "Error parsing chars i=%i len=%i bytes[0]=%x\n", i, len, bytes[0] );

		int64_t timestamp = (int64_t)((int32_t)mktime(&t)) * 1000 + millsecs;

		OutputPcapRecord ( timestamp, len, len, bytes, direc[0]=='R'? OPTIONS_INBOUND : OPTIONS_OUTBOUND );
		direc[0] == 'R' ? rxcount++ : txcount++;
			
	}
	fprintf ( stderr, "LogCatToPcap TX Count=%i RX Counter=%i\n", txcount, rxcount );
}


int ReadInput ( unsigned char* input, int maxlen )
{
	unsigned int availableSpace = maxlen;	
	int inputlen = 0;
		
	//int inputlen = fread ( input, sizeof(input), STD_IN );

	int readlen;
	while (1) {	
		int readlen = read(STDIN_FILENO, input+inputlen, availableSpace);

		if ( readlen < 0 ) 
		{
			fprintf ( stderr, "Unable to read file, erro=%i", errno );
			return 0;
		}
		if ( readlen == availableSpace )
		{
			fprintf ( stderr, "Input log too large\n" );
			return 0;
		}
		if ( readlen == 0 )
			break;
		availableSpace -= readlen;
		inputlen += readlen; 	
	}; 

	return inputlen;
}
int main(int argc, char** argv)
{
	int opt;
	while ((opt = getopt(argc, argv, "p")) != -1) {
               switch (opt) {
               case 'p':
                   outputpcap = true;
                   break;
               /*case 't':
                   nsecs = atoi(optarg);
                   tfnd = 1;
                   break;*/
               default: /* '?' */
                   fprintf(stderr, "Usage: %s [-p] < <input filename>\n  -p Output in pcapng format\n",
                           argv[0]);
                   exit(EXIT_FAILURE);
               }
           }


	//printf ( "Hello World\n" );

	unsigned int maxlogsize = 100000000;
	unsigned char* input = (unsigned char*)malloc ( maxlogsize ); 
	unsigned char* output = (unsigned char*)malloc ( maxlogsize );

	unsigned int inputlen;
	inputlen = ReadInput ( input, maxlogsize );

	if (inputlen <= 0 )
		return 0;	

	
	if ( IsText (input, MIN(inputlen,100)))
	{
		if ( IsSamsungLog ((char*)input, inputlen ))
		{
			fprintf ( stderr, "IsSamsungLog=true\n" );
			int outputLen = DecodeSamsungLog ( (char*)input, output, maxlogsize);
			if ( outputLen > 0 )
			{
				fprintf ( stderr, "outputLen=%i\n", outputLen );
				int decryptedLen = DecryptSamsungLog ( output, outputLen, input, maxlogsize);

				if (!outputpcap )
					printf ( "Log=%i(%i)\n%*s\n", outputpcap, decryptedLen, decryptedLen, input );
				else
				{
					SamsungLogToPcap ( (char*)input, decryptedLen );
				}

				//SamsungTextLogToBinary ((char*) input, decryptedLen, DumpNciMessage );
				//SamsungLogToPcap ( (char*)input, outputLen );
			}
				
		}
		else if ( IsLogCatLog ((char*)input, inputlen ))
		{
			LogCatToPcap ( (char*)input, inputlen );
		}
		else if ( IsNfcSnoopLog((char*)input, inputlen ))
		{
			int outputlen = DecodeNfcSnoopLog ((char*)input, output, maxlogsize);
			printf ( "Default log detected len=%i", outputlen);
			DecodeBinaryDefaultLog(output, outputlen);
			
		}
		else
		{
			printf ( "Unknown Text Format" );
		}
	}
	else
	{
		if ( IsBinaryDefaultLog (input, inputlen ))
		{
			OutputPcapHeader ();
			DecodeBinaryDefaultLog ( input, inputlen );
		}
		else
		{
			printf ( "Unknown Binary Format\n" );
		}
	}
}


