#pragma once

#include "submodules/cstd/lib.c"

typedef enum {
  BENCODE_KIND_NONE,
  BENCODE_KIND_NUMBER,
  BENCODE_KIND_STRING,
  BENCODE_KIND_ARRAY,
  BENCODE_KIND_DICTIONARY,
} BencodeValueKind;

typedef struct BencodeValue BencodeValue;
typedef struct {
  u64 len;
  BencodeValue *values;
} BencodeSlice;

typedef struct {
  StringSlice keys;
  BencodeSlice values;
} BencodeDictionary;

struct BencodeValue {
  BencodeValueKind kind;
  union {
    u64 num;
    String s;
    BencodeSlice array;
    BencodeDictionary dict;
  };
};

typedef enum {
  STATUS_ERR,
  STATUS_OK,
} Status;

typedef struct {
  Status status;
  BencodeValue res;
  StringSlice remaining;
} BencodeParseResult;

typedef struct {
  Status status;
  u64 num;
  String remaining;
} BencodeNumberParseResult;

[[nodiscard]] static BencodeNumberParseResult bencode_parse_number(String s) {
  BencodeNumberParseResult res = {0};

  StringConsumeResult prefix = string_consume(s, 'i');
  if (!prefix.consumed) {
    return res;
  }

  ParseNumberResult num_res = string_parse_u64(prefix.remaining);
  if (!num_res.present) {
    return res;
  }

  res.num = num_res.n;

  StringConsumeResult suffix = string_consume(num_res.remaining, 'e');
  if (!suffix.consumed) {
    return res;
  }
  res.remaining = suffix.remaining;
  res.status = STATUS_OK;

  return res;
}

typedef struct {
  Status status;
  String s;
  String remaining;
} BencodeStringParseResult;

[[nodiscard]] static BencodeStringParseResult bencode_parse_string(String s) {
  BencodeStringParseResult res = {0};

  ParseNumberResult num_res = string_parse_u64(s);
  if (!num_res.present) {
    return res;
  }

  if (0 == num_res.n) {
    return res;
  }

  StringConsumeResult prefix = string_consume(num_res.remaining, ':');
  if (!prefix.consumed) {
    return res;
  }

  if (prefix.remaining.len < num_res.n) {
    return res;
  }

  res.remaining = prefix.remaining;
  res.s = slice_range(prefix.remaining, 0, num_res.n);
  res.remaining = slice_range(prefix.remaining, num_res.n, 0);
  res.status = STATUS_OK;

  return res;
}

typedef struct {
  String announce;
  String name;
  u64 piece_length;
  String pieces;
  u64 length;
  BencodeDictionary files; // TODO.
} Metainfo;

typedef struct {
  Status status;
  Metainfo metainfo;
} ParseMetaInfoResult;
