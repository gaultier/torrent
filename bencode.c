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
  BENCODE_OK,
  BENCODE_ERR,
} BencodeParseResultKind;

typedef struct {
  BencodeParseResultKind kind;
  BencodeValue res;
  StringSlice remaining;
} BencodeParseResult;

BencodeParseResult bencode_parse(String s) {
  BencodeParseResult res = {0};
  // TODO.
  return res;
}
