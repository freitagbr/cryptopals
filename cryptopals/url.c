/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/url.h"

#include <stddef.h>

#include "cryptopals/string.h"
#include "cryptopals/error.h"
#include "cryptopals/hex.h"
#include "cryptopals/map.h"

static const string QS_SEP = string_new("&", 1);
static const string QS_EQ = string_new("=", 1);

static int should_escape(unsigned char c) {
  if (('A' <= c && c <= 'Z') ||
      ('a' <= c && c <= 'z') ||
      ('0' <= c && c <= '9') ||
      c == '-' || c == '_' ||
      c == '.' || c == '~') {
    return 0;
  }
  return 1;
}

error_t url_qs_unescape(string *dst, const string src) {
  unsigned char *sptr = src.ptr;
  unsigned char *dptr;
  unsigned char *end = &(src.ptr[src.len]);
  size_t percents = 0;
  int plus = 0;
  error_t err;

  while (sptr < end) {
    switch (*sptr) {
    case '%':
      percents++;
      if (sptr + 2 >= end || htob(sptr[1]) == -1 || htob(sptr[2]) == -1) {
        return EURLUNESCAPE;
      }
      break;
    case '+':
      plus = 1;
      break;
    default:
      break;
    }
    sptr++;
  }

  if (percents == 0 && !plus) {
    return string_copy(dst, src);
  }

  err = string_alloc(dst, src.len);
  if (err) {
    return err;
  }

  sptr = src.ptr;
  dptr = dst->ptr;

  while (sptr < end) {
    switch (*sptr) {
    case '%':
      *(dptr++) = (unsigned char)((htob(sptr[1]) << 4) | htob(sptr[2]));
      sptr += 3;
      break;
    case '+':
      *(dptr++) = ' ';
      sptr++;
      break;
    default:
      *(dptr++) = *(sptr++);
      break;
    }
  }

  dst->len = dptr - dst->ptr;

  return 0;
}

error_t url_qs_escape(string *dst, const string src) {
  unsigned char *sptr = src.ptr;
  unsigned char *dptr;
  unsigned char *end = &(src.ptr[src.len]);
  size_t spaces = 0;
  size_t hexes = 0;
  error_t err;

  while (sptr < end) {
    if (should_escape(*sptr)) {
      if (*sptr == ' ') {
        spaces++;
      } else {
        hexes++;
      }
    }
    sptr++;
  }

  if (spaces == 0 && hexes == 0) {
    return string_copy(dst, src);
  }

  err = string_alloc(dst, src.len + (hexes * 2));
  if (err) {
    return err;
  }

  sptr = src.ptr;
  dptr = dst->ptr;

  while (sptr < end) {
    if (*sptr == ' ') {
      *(dptr++) = '+';
      sptr++;
    } else if (should_escape(*sptr)) {
      *(dptr++) = '%';
      btoh(dptr, *(sptr++));
      dptr += 2;
    } else {
      *(dptr++) = *(sptr++);
    }
  }

  dst->len = dptr - dst->ptr;

  return 0;
}

error_t url_qs_encode(string *dst, map *m) {
  map_bucket **mptr = m->buckets;
  map_bucket **end = &(m->buckets[m->len]);
  string keyesc = string_init();
  string valesc = string_init();
  size_t encoded = 0;
  error_t err = 0;

  while (mptr < end) {
    map_bucket *entry = *(mptr++);
    if (entry != NULL && entry->key.ptr != NULL && entry->val.ptr != NULL) {
      encoded++;

      err = url_qs_escape(&keyesc, entry->key) ||
            url_qs_escape(&valesc, entry->val) ||
            string_append(dst, keyesc);
      if (err) {
        goto end;
      }

      if (valesc.len > 0) {
        err = string_append(dst, QS_EQ) ||
              string_append(dst, valesc);
        if (err) {
          goto end;
        }
      }

      if (encoded < m->count) {
        err = string_append(dst, QS_SEP);
        if (err) {
          goto end;
        }
      }
    }
  }

end:
  string_delete(keyesc);
  string_delete(valesc);

  return err;
}

error_t url_qs_decode(map *m, const string qs) {
  unsigned char *keyptr = qs.ptr;
  unsigned char *keyend = qs.ptr;
  unsigned char *valptr = qs.ptr;
  unsigned char *valend = qs.ptr;
  unsigned char *end = &(qs.ptr[qs.len]);
  string key = string_init();
  string val = string_init();
  string keyraw = string_init();
  string valraw = string_init();
  error_t err = 0;

  if (qs.len == 0) {
    goto end;
  }

  err = map_new(m);
  if (err) {
    goto end;
  }

  while (keyptr < end) {
    while (valend < end && *valend != '&') {
      valend++;
    }
    if (keyptr == valend) {
      break;
    }
    while (keyend < valend && *keyend != '=') {
      keyend++;
    }
    valptr = keyend;
    if (valptr + 1 < valend) {
      valptr++;
    }

    key.ptr = keyptr;
    key.len = keyend - keyptr;
    val.ptr = valptr;
    val.len = valend - valptr;

    err = url_qs_unescape(&keyraw, key) ||
          url_qs_unescape(&valraw, val) ||
          map_set(m, keyraw, valraw);
    if (err) {
      goto end;
    }

    valend++;
    keyptr = keyend = valptr = valend;
  }

end:
  string_delete(keyraw);
  string_delete(valraw);

  return err;
}
