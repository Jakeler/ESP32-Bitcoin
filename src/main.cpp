#include <Arduino.h>
#include "mbedtls/md.h"

// Print sha256 in little endian
void printHash(unsigned char* string) {
  for(int i=31; i>=0; i--){
    char str[3];

    sprintf(str, "%02x", (int)string[i]);
    Serial.print(str);
  }
  Serial.println();
}

// check if first 9 bytes are zero
bool checkHash(unsigned char* string) {
  bool valid = true;
  for(uint8_t i=31; i>22; i--) {
    if(string[i] != 0)
      valid = false;
  }
  return valid;
}
 
void setup(){
 
  Serial.begin(9600);
  Serial.println();
 
  // Header of Bitcoin block nr. 563333
  byte payload[] = {
    0x0, 0x0, 0x0, 0x20, // version
    0xa2, 0x17, 0x62, 0x4e, 0xf7, 0x72, 0x1b, 0x95, 0x4c, 0x7d, 0x93, 0x75, 0xaa, 0x85, 0xc1, 0x34, 0xe5, 0xb7, 0x66, 0xd2, 0x26, 0xa, 0x2c, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // prev hash
    0xa5, 0x12, 0x42, 0x48, 0xfa, 0x62, 0xcb, 0xef, 0x22, 0xc1, 0x26, 0x8c, 0xc0, 0x24, 0x86, 0xec, 0xfb, 0x5, 0xc2, 0x6d, 0x45, 0xba, 0x42, 0xff, 0x7e, 0x9b, 0x34, 0x6c, 0x0, 0xdf, 0x60, 0xaf, // merkle root
    0x5d, 0x80, 0x68, 0x5c, // time (2019-02-16)
    0x88, 0x6f, 0x2e, 0x17, // difficulty bits
    0x94, 0x4b, 0x40, 0x19 // nonce
  };
  const size_t payloadLength = 80;    
  
  byte interResult[32]; // 256 bit
  byte shaResult[32]; // 256 bit
 
  uint32_t nonce = 423644052; // 0x19404b94
  payload[76] = (nonce >> 0) & 0xFF;
  payload[77] = (nonce >> 8) & 0xFF;
  payload[78] = (nonce >> 16) & 0xFF;
  payload[79] = (nonce >> 24) & 0xFF;

  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
 
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);


  uint32_t t1 = micros();
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, payload, payloadLength);
  mbedtls_md_finish(&ctx, interResult);
  uint32_t t2 = micros();
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, interResult, 32);
  mbedtls_md_finish(&ctx, shaResult);
  uint32_t t3 = micros();

  mbedtls_md_free(&ctx);
 
  printHash(interResult);
  printHash(shaResult);


  Serial.println("1: " + String(t2-t1));
  Serial.println("2: " + String(t3-t2));
  Serial.println(nonce);

  Serial.println(checkHash(shaResult)? "Valid Hash!" : "no valid block...");
}
 
void loop(){}
