#ifndef SIPHASH_COOKIE_H__
#define SIPHASH_COOKIE_H__

#include "siphash.h"
#include <stdlib.h>

uint64_t mg_siphash_cookie_hash(struct sipkey *key, uint32_t ip_src, uint32_t ip_dst, uint16_t tcp_src, uint16_t tcp_dst, uint32_t ts);

#endif /* SIPHASH_COOKIE_H__ */

