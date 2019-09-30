#include <unordered_map>
#include <cstring> // for memcmp 
#include "nmmintrin.h" // for sse4.2 hardware crc checksum
#include <rte_config.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_errno.h>
#include <rte_spinlock.h>
#include <map>
#include <iostream> // for std::endl
#include <string>
#include <sparsehash/sparse_hash_map>
#include <time.h>
#include "siphash_cookie.h"

typedef struct sparse_hash_map_cookie_key {
	uint32_t ip_src;
	uint32_t ip_dst;		
	uint16_t tcp_src;
	uint16_t tcp_dst;
		
		
	bool operator==(const sparse_hash_map_cookie_key& rhs) const {
		return 
       	this->ip_src == rhs.ip_src &&
       	this->ip_dst == rhs.ip_dst &&
       	this->tcp_src == rhs.tcp_src &&
        this->tcp_dst == rhs.tcp_dst
        ;
    }
} sparse_hash_map_cookie_key;

struct eq_sparse_hash_map_cookie_key{
	bool operator()(const sparse_hash_map_cookie_key& lhs, const sparse_hash_map_cookie_key& rhs) const {
		return 
       	lhs.ip_src == rhs.ip_src &&
       	lhs.ip_dst == rhs.ip_dst &&
       	lhs.tcp_src == rhs.tcp_src &&
        lhs.tcp_dst == rhs.tcp_dst
        ;
	}
};

namespace std {
	template <> struct hash<sparse_hash_map_cookie_key>{
		struct sipkey *key = sip_tokey((struct sipkey *) malloc(sizeof(struct sipkey)), "9c16887667f84fd8b81c9ae6cfb3f569");

   		inline size_t operator()(const sparse_hash_map_cookie_key& ft) const {
			// fastest hash possible, but no perf increase
			//uint32_t hash = 0;
			//hash = _mm_crc32_u32(hash, ft.ip_src);
			//hash = _mm_crc32_u32(hash, ft.ip_dst);
			//hash = _mm_crc32_u16(hash, ft.tcp_dst);
			//hash = _mm_crc32_u16(hash, ft.tcp_src);
			//return hash;
		
			// crypto hash, slower but more resilient to certain attacks	
			struct siphash state;

			sip24_init(&state, key);

			unsigned char * dst = new unsigned char[8]();

			sip24_update(&state, "2796094800294027ef5d4ab7a6bff233", 16); // salt
			sip24_update(&state, sip_tobin(dst, ft.ip_src), 4);
			sip24_update(&state, sip_tobin(dst, ft.ip_dst), 4);
			sip24_update(&state, sip_tobin(dst, ft.tcp_src), 2);
			sip24_update(&state, sip_tobin(dst, ft.tcp_dst), 2);

			uint32_t result = (uint32_t) sip24_final(&state);
			return result;
		}
	};
}

// the flags
#define RESET 	0x01
#define CLOSED 	0x02
#define L_VER	0x04
#define R_VER	0x08
#define L_FIN	0x10
#define R_FIN	0x20
#define STALLED	0x40
typedef struct sparse_hash_map_cookie_value {
	uint32_t diff;
	uint8_t flags;
	void* stalled; // pointer to stalled mbuf
} sparse_hash_map_cookie_value;

using sparse_hash_map_cookie = google::sparse_hash_map<sparse_hash_map_cookie_key, sparse_hash_map_cookie_value*, std::hash<sparse_hash_map_cookie_key> , eq_sparse_hash_map_cookie_key>;
using namespace std;

typedef struct sparse_hash_maps_cookie {
	sparse_hash_map_cookie *current;
	sparse_hash_map_cookie *old;
	clock_t last_swap;
} sparse_hash_maps_cookie;

extern "C" {
	/* Google HashMap Sparsehash */
#define	SWAP_INTERVAL 30
	void mg_sparse_hash_map_cookie_swap(sparse_hash_maps_cookie *maps) {
		clock_t time = clock();
		if ( ((double) time - maps->last_swap) > ((double) SWAP_INTERVAL * CLOCKS_PER_SEC) ) {
			printf("swapping\n");
			
			printf("%f freeing unsent stalled mbufs %f\n", (double) clock(), (double) maps->old->size());
			// free mbufs in old map that will not be sent to prevent memory leaks
			auto it = maps->old->begin();
			while (!(it == maps->old->end())) {
				// only free the buf when there actually is a stalled buf
				if (it->second->flags & STALLED && it->second->stalled) {
					// only free the buf it wasnt copied to current -> perform lookup
					if (maps->current->find(it->first) != maps->current->end()) {
						it->second->flags ^= STALLED;
						rte_pktmbuf_free((rte_mbuf*)it->second->stalled);
						it->second->stalled = NULL;
					}
				}
				it++;
			}
			printf("%f done freeing\n", (double) clock());
			
			delete maps->old;
			maps->old = maps->current;
			maps->current = new sparse_hash_map_cookie(0);
			maps->last_swap = time;
			printf("done swapping\n");
		}
	}

	sparse_hash_maps_cookie* mg_sparse_hash_map_cookie_create(uint32_t size){
		sparse_hash_maps_cookie *maps = new sparse_hash_maps_cookie;	

		sparse_hash_map_cookie *tmp = new sparse_hash_map_cookie(size);
		sparse_hash_map_cookie_key k;
		memset(&k, 0, sizeof(sparse_hash_map_cookie_key));
		tmp->set_deleted_key(k);

		maps->current = tmp;
		
		tmp = new sparse_hash_map_cookie(size);
		memset(&k, 0, sizeof(sparse_hash_map_cookie_key));
		tmp->set_deleted_key(k);

		maps->old = tmp;

		maps->last_swap = clock();

		return maps;
	}

	/* Insert on setLeftVerified
	 * Always insert into current
	 * Stores the Ack Number for later calculation of the diff in the diff field
	 * Sets the leftVerified flag
	 * If entry already present:
	 *  connection is already left verified, 
	 *  hence, this packet and the syn we send next is duplicated
	 *  option A: drop it
	 *  		disadvantage: original syn might have gotten lost (server busy, ...)
	 *  option B (chosen): send again
	 *  		we assume the Ack number has not changed (which it obviously shouldn't)
	 * 		if it has changed, something is wrong
	 * 		hence, we assume the first Ack number to be the correct one and don't update it here
	 */
	void mg_sparse_hash_map_cookie_insert(sparse_hash_maps_cookie *maps, sparse_hash_map_cookie_key *k, uint32_t ack) {
		//printf("insert %d\n", k->tcp_src);
		auto m = maps->current;
		auto it = m->find(*k);
		// not existing yet
        if (it == m->end() ){
 			sparse_hash_map_cookie_value *tmp = new sparse_hash_map_cookie_value;
			tmp->diff = ack;
			tmp->flags = L_VER;
			tmp->stalled = 0;
			(*m)[*k] = tmp;
			//printf("Entry: %d %d %p\n", tmp->diff, tmp->flags, tmp->stalled);
			mg_sparse_hash_map_cookie_swap(maps);
			return;
		} else {
			//printf("NOT inserted, but reused\n");
			// entry exists, but was not verified (connections closed)

 			sparse_hash_map_cookie_value *tmp = (*m)[*k];
			tmp->diff = ack;
			tmp->flags = L_VER;
			tmp->stalled = 0;
			//printf("Entry: %d %d %p\n", tmp->diff, tmp->flags, tmp->stalled);
			
			mg_sparse_hash_map_cookie_swap(maps);
		}

    };

	/* Finalize an entry on setRightVerified
	 * Find the entry and check that flags are correct (only leftVerified set)
	 * Calculate and store diff from seq number and stored ack number
	 * Set rightVerified flag
	 */
	sparse_hash_map_cookie_value* mg_sparse_hash_map_cookie_finalize(sparse_hash_maps_cookie *maps, sparse_hash_map_cookie_key *k, uint32_t seq) {
		//printf("finalize %d\n", k->tcp_src);
		auto m = maps->current;
		auto it = m->find(*k);
		if (it == m->end() ) {
			//printf("fin not found in current, checking old\n");
			m = maps->old;
			it = m->find(*k);
			if (unlikely(it == m->end())) {
				//printf("fin also not found here\n");
				mg_sparse_hash_map_cookie_swap(maps);
				return 0;
			}
			// copy and proceed normally
			//printf("right found-> copy\n");
			(*(maps->current))[*k] = (*m)[*k];
		}

 		sparse_hash_map_cookie_value *tmp = (*m)[*k];
		
		// Check that flags are correct
		// Only leftVerified must be set
		if ( unlikely((tmp->flags & (L_VER | R_VER)) != L_VER) ) {
			mg_sparse_hash_map_cookie_swap(maps);
			//printf("ignoring second syn ack\n");
			return tmp;
		}
		
		tmp->diff = seq - tmp->diff + 1;
		tmp->flags = tmp->flags | R_VER;
		//printf("Entry: %d %d\n", tmp->diff, tmp->flags);
		//printf("Got a stalled buf: %p flags %d\n", tmp->stalled, tmp->flags & STALLED);	
		mg_sparse_hash_map_cookie_swap(maps);
		return tmp;
	};

	/* Find and update on isVerified
	 * If it is verified, update the timestamp bits
	 * Return the value struct
	 */	
	sparse_hash_map_cookie_value* mg_sparse_hash_map_cookie_find_update(sparse_hash_maps_cookie *maps, sparse_hash_map_cookie_key *k, bool reset, bool left_fin, bool right_fin, bool ack) {
		//printf("is verified %d\n", k->tcp_src);
		auto m = maps->current;
		auto it = m->find(*k);
		if (it == m->end() ) {
			//printf("upd not found in current, checking old\n");
			m = maps->old;
			it = m->find(*k);
			if (unlikely(it == m->end())) {
				//printf("upd also not found here\n");
				mg_sparse_hash_map_cookie_swap(maps);
				//printf("not existing\n");
				return 0;
			}
			// copy and proceed normally
			//printf("find found-> copy\n");
			(*(maps->current))[*k] = (*m)[*k];
		}
		
		sparse_hash_map_cookie_value *tmp = (*m)[*k];
		
		// if only left verified we are waiting for right verified
		// in this case stall, indicated by setting flags in a new struct to 0
		if (unlikely((tmp->flags & (L_VER | R_VER)) == L_VER)) {
			if (unlikely(tmp->flags & STALLED)) {
				//printf("already got stalled buf\n");
				return 0;
			}
			mg_sparse_hash_map_cookie_swap(maps);
			tmp->flags = tmp->flags | STALLED;
			return tmp;
		}
		// Check verified flags (both 4 8 must be set)
		if (unlikely((tmp->flags & (L_VER | R_VER)) != (L_VER | R_VER))) {
			mg_sparse_hash_map_cookie_swap(maps);
			//printf("wrong flags\n");
			return 0;
		}

		// check reset flag
		// if it is set the connection is dead and we do nothing
		if (unlikely(tmp->flags & RESET)) {
			//printf("RESET set, act as if not verified\n");
			return 0;
		}
		// set reset flag
		if (unlikely(reset)) {
			tmp->flags = tmp->flags | RESET;
		}

		// check whether conenction was closed via teardown
		if (unlikely(tmp->flags & CLOSED)) {
			//printf("closed via teardown, return\n");
			return 0;
		}
		//check fin flags
		// if both are set and this is an ack, assume this is the last ack of the teardown
		if (unlikely(((tmp->flags & (L_FIN | R_FIN)) == (L_FIN | R_FIN)) && ack)) {
			//printf("final ack of connection, next will be discarded\n");
			tmp->flags = tmp->flags | CLOSED; // close connection
		}

		// set fin flags
		if (unlikely(left_fin)) {
			//printf("set left fin\n");
			tmp->flags = tmp->flags | L_FIN;
		}
		if (unlikely(right_fin)) {
			//printf("set right fin\n");
			tmp->flags = tmp->flags | R_FIN;
		}

		mg_sparse_hash_map_cookie_swap(maps);

		return tmp;
	};
}
