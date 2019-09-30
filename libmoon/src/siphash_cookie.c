#include "siphash.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>


struct sipkey *mg_siphash_cookie_init() {
	struct sipkey *key = malloc(sizeof(struct sipkey));
	key = sip_tokey(key, "e9dbc39fd2ca7acc777275304ddc8b8b");
	return key;
}

uint32_t mg_siphash_cookie_hash(struct sipkey *key, uint32_t ip_src, uint32_t ip_dst, uint16_t tcp_src, uint16_t tcp_dst, uint32_t ts) {
	struct siphash state;

	sip24_init(&state, key);

	sip24_update(&state, "c36fe2169a1c9cc9178d781a688ab07f", 16); // salt
	sip24_update(&state, sip_binof(ip_src), 4);
	sip24_update(&state, sip_binof(ip_dst), 4);
	sip24_update(&state, sip_binof(tcp_src), 2);
	sip24_update(&state, sip_binof(tcp_dst), 2);
	sip24_update(&state, sip_binof(ts), 4);

	uint32_t result = (uint32_t) sip24_final(&state);
	result &= 0x000fffff; // 20 bits
	return result;
}
