#include <iostream> // for std::endl
#include <time.h>
#include <cstring>
#include <thread>
#include <unistd.h>

#define unlikely(x)     __builtin_expect(!!(x), 0)

typedef struct __attribute__((__packed__)) bit_map_auth_ttl_map {
	uint8_t bucket[1073741824]; // each bucket holds 2 ts bits for a total of each 4 IPs
	uint8_t ttls[4][1073741824]; //
} bit_map_auth_ttl_map;

using namespace std;

extern "C" {

	void mg_bit_map_auth_ttl_gc(bit_map_auth_ttl_map *m) {
		while(true) {
			sleep(300);
			for (uint32_t b = 0; b < sizeof(*m); b += 5) { // only every 5th bucket stores bits (rest is TTLs)
				for (uint8_t i = 0; i < 4; i++) {
					if (m->bucket[b] & (1 << (i * 2))) {
						m->bucket[b] ^= (1 << (i * 2));
					} else if (m->bucket[b] & (1 << ((i * 2) + 1))) {
						m->bucket[b] ^= (1 << ((i * 2) + 1));
						m->bucket[b + 1 + i] = 0; // delete TTL value
					}
				}
			}
		}
	}

	bit_map_auth_ttl_map* mg_bit_map_auth_ttl_create(){
		bit_map_auth_ttl_map *map = new bit_map_auth_ttl_map;
		std::memset(map, 0, sizeof(*map));
		
		thread gc(mg_bit_map_auth_ttl_gc, map);
		gc.detach();

		return map;
	}
	
	bool mg_bit_map_auth_ttl_update(bit_map_auth_ttl_map *map, uint32_t k, bool forced, uint8_t ttl, uint8_t range) {
		uint32_t bucket = k >> 2; // division by four rounded down to determin bucket
		uint8_t idx = k & 3; // 2 least significant bits -> %4 as index within bucket	
		// bits are ts1 (idx*2) and ts2 (idx * 2 + 1)
		// ts1 gets deleted first, so only check for ts2
		// if bit is set, simply update it
		// otherwise, if it is a RST (forced) and the TTLs match, whitelist the host
		bool ts2 = map->bucket[bucket] & (1 << ((idx * 2) + 1));
		if (ts2 || (forced && abs(map->ttls[idx][bucket] - ttl) <= range)) {
			map->bucket[bucket] |= (3 << (idx * 2));
		}

		return ts2;
	};
	
	bool mg_bit_map_auth_ttl_update_syn(bit_map_auth_ttl_map *map, uint32_t k, uint8_t ttl) {
		uint32_t bucket = k >> 2; // division by four rounded down to determin bucket
		uint8_t idx = k & 3; // 2 least significant bits -> %4 as index within bucket	
		// bits are ts1 (idx*2) and ts2 (idx * 2 + 1)
		// ts1 gets deleted first, so only check for ts2
		bool ts2 = map->bucket[bucket] & (1 << ((idx * 2) + 1));
		if (ts2) {
			map->bucket[bucket] |= (3 << (idx * 2));
		} else {
			// store the TTL to compare later
			map->ttls[idx][bucket] = ttl;
		}
		return ts2;
	};
}
