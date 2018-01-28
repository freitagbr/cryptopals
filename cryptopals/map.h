/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#ifndef CRYPTOPALS_MAP_H_
#define CRYPTOPALS_MAP_H_

#include <stddef.h>

#include "cryptopals/string.h"
#include "cryptopals/error.h"

#define MAP_DEFAULT_LENGTH 53
#define MAP_UPPER_LOAD_LIMIT 70
#define MAP_LOWER_LOAD_LIMIT 10
#define MAP_FNV1_PRIME_32 0x01000193
#define MAP_FNV1_BASE_32 2166136261U

typedef struct map_bucket {
  string key;
  string val;
} map_bucket;

typedef struct map {
  size_t base;
  size_t len;
  size_t count;
  map_bucket **buckets;
} map;

#define map_init()                                                             \
  { 0, 0, 0, NULL }

#define map_load(m) ((m->count * 100) / m->len)

size_t map_hash(const string str, unsigned long buckets);

error_t map_new_length(map *m, const size_t len);

error_t map_new(map *m);

void map_clear(map *m);

void map_delete(map m);

error_t map_set(map *m, const string key, const string val);

string *map_get(map *m, const string key);

error_t map_remove(map *m, const string key);

#endif /* CRYPTOPALS_MAP_H_ */
