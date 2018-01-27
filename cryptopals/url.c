/* Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com> */

#include "cryptopals/url.h"

#include "cryptopals/buffer.h"
#include "cryptopals/error.h"
#include "cryptopals/hex.h"
#include "cryptopals/map.h"

static const buffer QS_SEP = buffer_new("&", 1);
static const buffer QS_EQ = buffer_new("=", 1);

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

error_t url_qs_unescape(buffer *dst, const buffer src) {
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
    return buffer_copy(dst, src);
  }

  err = buffer_alloc(dst, src.len);
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

error_t url_qs_escape(buffer *dst, const buffer src) {
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
    return buffer_copy(dst, src);
  }

  err = buffer_alloc(dst, src.len + (hexes * 2));
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

error_t url_qs_encode(buffer *dst, map *m) {
  map_bucket **mptr = m->buckets;
  map_bucket **end = &(m->buckets[m->len]);
  buffer keyesc = buffer_init();
  buffer valesc = buffer_init();
  size_t encoded = 0;
  error_t err = 0;

  while (mptr < end) {
    map_bucket *entry = *(mptr++);
    if (entry != NULL && entry->key.ptr != NULL && entry->val.ptr != NULL) {
      encoded++;

      err = url_qs_escape(&keyesc, entry->key) ||
            url_qs_escape(&valesc, entry->val);
      if (err) {
        goto end;
      }

      err = buffer_append(dst, keyesc);
      if (err) {
        goto end;
      }

      if (valesc.len > 0) {
        err = buffer_append(dst, QS_EQ) ||
              buffer_append(dst, valesc);
        if (err) {
          goto end;
        }
      }

      if (encoded < m->count) {
        err = buffer_append(dst, QS_SEP);
        if (err) {
          goto end;
        }
      }
    }
  }

end:
  buffer_delete(keyesc);
  buffer_delete(valesc);

  return err;
}

error_t url_qs_decode(map *m, const buffer qs) {
  unsigned char *keyptr = qs.ptr;
  unsigned char *keyend = qs.ptr;
  unsigned char *valptr = qs.ptr;
  unsigned char *valend = qs.ptr;
  unsigned char *end = &(qs.ptr[qs.len]);
  buffer key = buffer_init();
  buffer val = buffer_init();
  buffer keyraw = buffer_init();
  buffer valraw = buffer_init();
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
          url_qs_unescape(&valraw, val);
    if (err) {
      goto end;
    }

    err = map_set(m, keyraw, valraw);
    if (err) {
      goto end;
    }

    valend++;
    keyptr = keyend = valptr = valend;
  }

end:
  buffer_delete(keyraw);
  buffer_delete(valraw);

  return err;
}
