/* ==========================================================================
 * siphash.h - SipHash-2-4 in a single header file
 * --------------------------------------------------------------------------
 * Derived by William Ahern from the reference implementation[1] published[2]
 * by Jean-Philippe Aumasson and Daniel J. Berstein. Licensed in kind.
 *
 * 1. https://www.131002.net/siphash/siphash24.c
 * 2. https://www.131002.net/siphash/
 * --------------------------------------------------------------------------
 * HISTORY:
 *
 * 2012-11-04 - Born.
 * --------------------------------------------------------------------------
 * USAGE:
 *
 * SipHash-2-4 takes as input two 64-bit words as the key, some number of
 * message bytes, and outputs a 64-bit word as the message digest. This
 * implementation employs two data structures: a struct sipkey for
 * representing the key, and a struct siphash for representing the hash
 * state.
 *
 * For converting a 16-byte unsigned char array to a key, use either the
 * macro sip_keyof or the routine sip_tokey. The former instantiates a
 * compound literal key, while the latter requires a key object as a
 * parameter.
 *
 * 	unsigned char secret[16];
 * 	arc4random_buf(secret, sizeof secret);
 * 	struct sipkey *key = sip_keyof(secret);
 *
 * For hashing a message, use either the convenience macro siphash24 or the
 * routines sip24_init, sip24_update, and sip24_final.
 *
 * 	struct siphash state;
 * 	void *msg;
 * 	size_t len;
 * 	uint64_t hash;
 *
 * 	sip24_init(&state, key);
 * 	sip24_update(&state, msg, len);
 * 	hash = sip24_final(&state);
 *
 * or
 *
 * 	hash = siphash24(msg, len, key);
 *
 * To convert the 64-bit hash value to a canonical 8-byte little-endian
 * binary representation, use either the macro sip_binof or the routine
 * sip_tobin. The former instantiates and returns a compound literal array,
 * while the latter requires an array object as a parameter.
 * --------------------------------------------------------------------------
 * NOTES:
 *
 * o Neither sip_keyof, sip_binof, nor siphash24 will work with compilers
 *   lacking compound literal support. Instead, you must use the lower-level
 *   interfaces which take as parameters the temporary state objects.
 *
 * o Uppercase macros may evaluate parameters more than once. Lowercase
 *   macros should not exhibit any such side effects.
 * ==========================================================================
 */
#ifndef SIPHASH_H
#define SIPHASH_H

#include <stddef.h> /* size_t */
#include <stdint.h> /* uint64_t uint32_t uint8_t */


#define SIP_ROTL(x, b) (uint64_t)(((x) << (b)) | ( (x) >> (64 - (b))))

#define SIP_U32TO8_LE(p, v) \
	(p)[0] = (uint8_t)((v) >>  0); (p)[1] = (uint8_t)((v) >>  8); \
	(p)[2] = (uint8_t)((v) >> 16); (p)[3] = (uint8_t)((v) >> 24);

#define SIP_U64TO8_LE(p, v) \
	SIP_U32TO8_LE((p) + 0, (uint32_t)((v) >>  0)); \
	SIP_U32TO8_LE((p) + 4, (uint32_t)((v) >> 32));

#define SIP_U8TO64_LE(p) \
	(((uint64_t)((p)[0]) <<  0) | \
	 ((uint64_t)((p)[1]) <<  8) | \
	 ((uint64_t)((p)[2]) << 16) | \
	 ((uint64_t)((p)[3]) << 24) | \
	 ((uint64_t)((p)[4]) << 32) | \
	 ((uint64_t)((p)[5]) << 40) | \
	 ((uint64_t)((p)[6]) << 48) | \
	 ((uint64_t)((p)[7]) << 56))


#define SIPHASH_INITIALIZER { 0, 0, 0, 0, { 0 }, 0, 0 }

struct siphash {
	uint64_t v0, v1, v2, v3;

	unsigned char buf[8], *p;
	uint64_t c;
}; /* struct siphash */


#define SIP_KEYLEN 16

struct sipkey {
	uint64_t k[2];
}; /* struct sipkey */

#define sip_keyof(k) sip_tokey(&(struct sipkey){ { 0 } }, (k))

static inline struct sipkey *sip_tokey(struct sipkey *key, const void *src) {
	key->k[0] = SIP_U8TO64_LE((const unsigned char *)src);
	key->k[1] = SIP_U8TO64_LE((const unsigned char *)src + 8);
	return key;
} /* sip_tokey() */


#define sip_binof(v) sip_tobin((unsigned char[8]){ 0 }, (v))

static inline void *sip_tobin(void *dst, uint64_t u64) {
	SIP_U64TO8_LE((unsigned char *)dst, u64);
	return dst;
} /* sip_tobin() */


static inline void sip_round(struct siphash *H, const int rounds) {
	int i;

	for (i = 0; i < rounds; i++) {
		H->v0 += H->v1;
		H->v1 = SIP_ROTL(H->v1, 13);
		H->v1 ^= H->v0;
		H->v0 = SIP_ROTL(H->v0, 32);

		H->v2 += H->v3;
		H->v3 = SIP_ROTL(H->v3, 16);
		H->v3 ^= H->v2;

		H->v0 += H->v3;
		H->v3 = SIP_ROTL(H->v3, 21);
		H->v3 ^= H->v0;

		H->v2 += H->v1;
		H->v1 = SIP_ROTL(H->v1, 17);
		H->v1 ^= H->v2;
		H->v2 = SIP_ROTL(H->v2, 32);
	}
} /* sip_round() */


static inline struct siphash *sip24_init(struct siphash *H, const struct sipkey *key) {
	H->v0 = 0x736f6d6570736575ULL ^ key->k[0];
	H->v1 = 0x646f72616e646f6dULL ^ key->k[1];
	H->v2 = 0x6c7967656e657261ULL ^ key->k[0];
	H->v3 = 0x7465646279746573ULL ^ key->k[1];

	H->p = H->buf;
	H->c = 0;

	return H;
} /* sip24_init() */


#define sip_endof(a) (&(a)[sizeof (a) / sizeof *(a)])

static inline struct siphash *sip24_update(struct siphash *H, const void *src, size_t len) {
	const unsigned char *p = (const unsigned char *)src, *pe = p + len;
	uint64_t m;

	do {
		while (p < pe && H->p < sip_endof(H->buf))
			*H->p++ = *p++;

		if (H->p < sip_endof(H->buf))
			break;

		m = SIP_U8TO64_LE(H->buf);
		H->v3 ^= m;
		sip_round(H, 2);
		H->v0 ^= m;

		H->p = H->buf;
		H->c += 8;
	} while (p < pe);

	return H;
} /* sip24_update() */


static inline uint64_t sip24_final(struct siphash *H) {
	char left = H->p - H->buf;
	uint64_t b = (H->c + left) << 56;

	switch (left) {
	case 7: b |= (uint64_t)H->buf[6] << 48;
	case 6: b |= (uint64_t)H->buf[5] << 40;
	case 5: b |= (uint64_t)H->buf[4] << 32;
	case 4: b |= (uint64_t)H->buf[3] << 24;
	case 3: b |= (uint64_t)H->buf[2] << 16;
	case 2: b |= (uint64_t)H->buf[1] << 8;
	case 1: b |= (uint64_t)H->buf[0] << 0;
	case 0: break;
	}

	H->v3 ^= b;
	sip_round(H, 2);
	H->v0 ^= b;
	H->v2 ^= 0xff;
	sip_round(H, 4);

	return H->v0 ^ H->v1 ^ H->v2  ^ H->v3;
} /* sip24_final() */


#define siphash24(src, len, key) \
	sip24_final(sip24_update(sip24_init(&(struct siphash)SIPHASH_INITIALIZER, (key)), (src), (len)))


#endif /* SIPHASH_H */
