/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/map.h"

#include <math.h>
#include <stdlib.h>

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"

static map_bucket MAP_BUCKET_DELETED = {{NULL, 0}, {NULL, 0}};

/**
 *  1 - is prime
 *  0 - not prime
 * -1 - n < 2
 */
static int is_prime(unsigned long n) {
  unsigned long i;
  if ((n & 1) == 0) {
    return 0;
  }
  if (n < 2) {
    return -1;
  }
  if (n == 3) {
    return 1;
  }
  for (i = 3; i <= floor(sqrt((double)n)); i += 2) {
    if ((n % i) == 0) {
      return 0;
    }
  }
  return 1;
}

static unsigned long next_prime(unsigned long n) {
  if ((n & 1) == 0) {
    n++;
  }
  while (is_prime(n) != 1) {
    n += 2;
  }
  return n;
}

static error_t map_bucket_new(map_bucket **mb, const buffer key,
                              const buffer val) {
  map_bucket *b;
  error_t err;
  if (mb == NULL) {
    return ENULLPTR;
  }
  b = *mb = (map_bucket *)calloc(1, sizeof(map_bucket));
  if (b == NULL) {
    return EMALLOC;
  }
  err = buffer_dup(&(b->key), key) || buffer_dup(&(b->val), val);
  if (err) {
    buffer_delete(&(b->key));
    buffer_delete(&(b->val));
    free((void *)b);
    return err;
  }
  return 0;
}

static void map_bucket_delete(map_bucket *b) {
  if (b != NULL && b != &MAP_BUCKET_DELETED) {
    buffer_delete(b->key);
    buffer_delete(b->val);
    free((void *)b);
  }
}

/* FNV-1a hash */
static unsigned long map_hash(const buffer buf, unsigned long buckets) {
  long hash = MAP_OFFSET_BASIS_32;
  unsigned char *ptr = buf.ptr;
  unsigned char *end = &(buf.ptr[buf.len]);
  while (ptr < end) {
    hash ^= *(ptr++);
    hash += (hash << 1) +
            (hash << 4) +
            (hash << 7) +
            (hash << 8) +
            (hash << 24);
  }
  return (unsigned long)hash % buckets;
}

error_t map_new_length(map *m, const size_t len) {
  m->base = len;
  m->len = next_prime(len);
  m->count = 0;
  m->buckets = (map_bucket **)calloc(m->len, sizeof(map_bucket *));
  if (m->buckets == NULL) {
    return EMALLOC;
  }
  return 0;
}

error_t map_new(map *m) { return map_new_length(m, MAP_DEFAULT_LENGTH); }

static error_t map_resize(map *m, const size_t new_base) {
  map_bucket **new_buckets;
  map_bucket **ptr;
  map_bucket **end;
  size_t new_len;
  size_t new_count = 0;

  if (new_base < MAP_DEFAULT_LENGTH) {
    return 0;
  }

  new_len = next_prime(new_base);
  new_buckets = (map_bucket **)calloc(new_len, sizeof(map_bucket *));
  if (new_buckets == NULL) {
    return EMALLOC;
  }

  ptr = m->buckets;
  end = &(m->buckets[m->len]);

  while (ptr < end) {
    if (*ptr != NULL && *ptr != &MAP_BUCKET_DELETED) {
      unsigned long hash = map_hash((*ptr)->key, new_len);
      unsigned long step = 0;
      map_bucket *curr = new_buckets[hash];
      while (curr != NULL && curr != &MAP_BUCKET_DELETED) {
        hash = (hash + (++step)) % new_len;
        curr = new_buckets[hash];
      }
      new_buckets[hash] = *ptr;
      new_count++;
    }
    ptr++;
  }

  if (new_count != m->count) {
    free((void *)new_buckets);
    return EMAPRESIZE;
  }

  free((void *)m->buckets);
  m->base = new_base;
  m->len = new_len;
  m->buckets = new_buckets;

  return 0;
}

static error_t map_resize_up(map *m) { return map_resize(m, m->len * 2); }

static error_t map_resize_down(map *m) { return map_resize(m, m->len / 2); }

void map_clear(map *m) {
  if (m != NULL) {
    if (m->buckets != NULL) {
      map_bucket **ptr = m->buckets;
      map_bucket **end = &(m->buckets[m->len]);
      while (ptr < end) {
        map_bucket_delete(*ptr);
        *(ptr++) = NULL;
      }
    }
    m->count = 0;
  }
}


void map_delete(map m) {
  if (m.buckets != NULL) {
    map_bucket **ptr = m.buckets;
    map_bucket **end = &(m.buckets[m.len]);
    while (ptr < end) {
      map_bucket_delete(*(ptr++));
    }
    free((void *)m.buckets);
  }
}

error_t map_set(map *m, const buffer key, const buffer val) {
  map_bucket *curr;
  map_bucket *b;
  unsigned long hash;
  unsigned long step = 0;
  error_t err;

  if (map_load(m) > MAP_UPPER_LOAD_LIMIT) {
    err = map_resize_up(m);
    if (err) {
      return err;
    }
  }

  err = map_bucket_new(&b, key, val);
  if (err) {
    return err;
  }

  hash = map_hash(key, m->len);
  curr = m->buckets[hash];

  while (curr != NULL) {
    if (curr != &MAP_BUCKET_DELETED) {
      if (buffer_cmp(curr->key, key) == 0) {
        map_bucket_delete(curr);
        m->buckets[hash] = b;
        return 0;
      }
    }
    hash = (hash + (++step)) % m->len;
    curr = m->buckets[hash];
  }

  m->buckets[hash] = b;
  m->count++;

  return 0;
}

buffer *map_get(map *m, const buffer key) {
  unsigned long hash = map_hash(key, m->len);
  unsigned long step = 0;
  map_bucket *b = m->buckets[hash];

  while (b != NULL) {
    if (b != &MAP_BUCKET_DELETED) {
      if (buffer_cmp(b->key, key) == 0) {
        return &b->val;
      }
    }
    hash = (hash + (++step)) % m->len;
    b = m->buckets[hash];
  }

  return NULL;
}

error_t map_remove(map *m, const buffer key) {
  unsigned long hash = map_hash(key, m->len);
  unsigned long step = 0;
  map_bucket *b = m->buckets[hash];

  if (map_load(m) < MAP_LOWER_LOAD_LIMIT) {
    error_t err = map_resize_down(m);
    if (err) {
      return err;
    }
  }

  while (b != NULL) {
    if (b != &MAP_BUCKET_DELETED && buffer_cmp(b->key, key) == 0) {
      map_bucket_delete(b);
      m->buckets[hash] = &MAP_BUCKET_DELETED;
      m->count--;
      return 0;
    }
    hash = (hash + (++step)) % m->len;
    b = m->buckets[hash];
  }

  return EMAPREMOVE;
}
