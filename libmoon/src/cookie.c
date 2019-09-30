#include <rte_config.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_errno.h>
#include <sys/mman.h>
#include <rte_cycles.h>
#include <stdint.h>
#include "siphash_cookie.h"

void calculate_cookies_batched(struct rte_mbuf *pkts[], uint32_t num, struct sipkey *key) {
	// get timestamp once for this batch and process it
	uint64_t t = rte_rdtsc()/rte_get_tsc_hz();
	// 64 seconds resolution
	t = t >> 6;
	// 5 bits
	t = t % 32;

	// for each buffer of the batch
	uint16_t i;
	for(i = 0; i < num; i++) {
		struct rte_mbuf *pkt = pkts[i];
		uint8_t *data = (uint8_t *) pkt->buf_addr + pkt->data_off;
		// get data: 0-13 eth, 14-33 ip4, >34 tcp
		// we already work on the TX buffer, hence src and dst (mac/ip/port) is already interchanged!
		uint32_t ip_dst = ((uint32_t) data[26] << 24) + ((uint32_t) data[27] << 16) + ((uint32_t) data[28] << 8) + (uint32_t) data[29];
		uint32_t ip_src = ((uint32_t) data[30] << 24) + ((uint32_t) data[31] << 16) + ((uint32_t) data[32] << 8) + (uint32_t) data[33];
		uint16_t tcp_dst = ((uint16_t) data[34] << 8) + (uint16_t) data[35];
		uint16_t tcp_src = ((uint16_t) data[36] << 8) + (uint16_t) data[37];

		// calculate hash
		uint32_t hash = mg_siphash_cookie_hash(key, ip_src, ip_dst, tcp_src, tcp_dst, t);

		// finish cookie
		uint8_t byte1 = (data[38] & 0x07) + ((uint8_t) t << 3);
		uint8_t byte2 = (hash >> 16) + (data[39] & 0xf0);
		uint8_t byte3 = (uint8_t) (hash >> 8);
		uint8_t byte4 = (uint8_t) hash;

		// write the cookie
		data[38] = byte1;
		data[39] = byte2;
		data[40] = byte3;
		data[41] = byte4;
	}
}

void calculate_auth_cookies_batched(struct rte_mbuf *pkts[], uint32_t num, struct sipkey *key) {
	// get timestamp once for this batch and process it
	uint64_t t = 0;

	// for each buffer of the batch
	uint16_t i;
	for(i = 0; i < num; i++) {
		struct rte_mbuf *pkt = pkts[i];
		uint8_t *data = (uint8_t *) pkt->buf_addr + pkt->data_off;
		// get data: 0-13 eth, 14-33 ip4, >34 tcp
		// we already work on the TX buffer, hence src and dst (mac/ip/port) is already interchanged!
		uint32_t ip_dst = ((uint32_t) data[26] << 24) + ((uint32_t) data[27] << 16) + ((uint32_t) data[28] << 8) + (uint32_t) data[29];
		uint32_t ip_src = ((uint32_t) data[30] << 24) + ((uint32_t) data[31] << 16) + ((uint32_t) data[32] << 8) + (uint32_t) data[33];
		uint16_t tcp_dst = ((uint16_t) data[34] << 8) + (uint16_t) data[35];
		uint16_t tcp_src = ((uint16_t) data[36] << 8) + (uint16_t) data[37];

		// calculate hash
		uint32_t hash = mg_siphash_cookie_hash(key, ip_src, ip_dst, tcp_src, tcp_dst, t);

		// finish cookie
		uint8_t byte1 = (data[38] & 0x07) + ((uint8_t) t << 3);
		uint8_t byte2 = (hash >> 16) + (data[39] & 0xf0);
		uint8_t byte3 = (uint8_t) (hash >> 8);
		uint8_t byte4 = (uint8_t) hash;

		// write the cookie
		data[38] = byte1;
		data[39] = byte2;
		data[40] = byte3;
		data[41] = byte4;
	}
}
