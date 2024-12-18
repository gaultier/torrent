#include "bencode.c"

static void test_bencode_parse_u64() {
  {
    BencodeNumberParseResult res = bencode_parse_number(S(""));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeNumberParseResult res = bencode_parse_number(S("a"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeNumberParseResult res = bencode_parse_number(S("i"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeNumberParseResult res = bencode_parse_number(S("ie"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeNumberParseResult res = bencode_parse_number(S("i123"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeNumberParseResult res = bencode_parse_number(S("123"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeNumberParseResult res = bencode_parse_number(S("i-123e"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeNumberParseResult res = bencode_parse_number(S("i123ehello"));
    ASSERT(STATUS_OK == res.status);
    ASSERT(123 == res.num);
    ASSERT(string_eq(res.remaining, S("hello")));
  }
}

static void test_bencode_parse_string() {
  {
    BencodeStringParseResult res = bencode_parse_string(S(""));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeStringParseResult res = bencode_parse_string(S("a"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeStringParseResult res = bencode_parse_string(S("1"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeStringParseResult res = bencode_parse_string(S("0"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeStringParseResult res = bencode_parse_string(S("0:"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeStringParseResult res = bencode_parse_string(S("1:"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeStringParseResult res = bencode_parse_string(S("2:a"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeStringParseResult res = bencode_parse_string(S("2:abc"));
    ASSERT(STATUS_OK == res.status);
    ASSERT(string_eq(res.s, S("ab")));
    ASSERT(string_eq(res.remaining, S("c")));
  }
}

static void test_bencode_parse() {
  Arena arena = arena_make_from_virtual_mem(4 * KiB);
  {
    BencodeParseResult res = bencode_parse(S("i123ei456e"), &arena);
    ASSERT(STATUS_OK == res.status);
    ASSERT(BENCODE_KIND_NUMBER == res.value.kind);
    ASSERT(123 == res.value.num);
    ASSERT(string_eq(S("i456e"), res.remaining));
  }
  {
    BencodeParseResult res =
        bencode_parse(S("d2:abi123e3:xyz5:helloefoo"), &arena);
    ASSERT(STATUS_OK == res.status);
    ASSERT(BENCODE_KIND_DICTIONARY == res.value.kind);
    ASSERT(string_eq(S("foo"), res.remaining));

    BencodeDictionary dict = res.value.dict;
    ASSERT(2 == dict.keys.len);
    ASSERT(2 == dict.values.len);

    {
      String k1 = dyn_at(dict.keys, 0);
      ASSERT(string_eq(S("ab"), k1));
    }

    {
      String k2 = dyn_at(dict.keys, 1);
      ASSERT(string_eq(S("xyz"), k2));
    }

    {
      BencodeValue v1 = dyn_at(dict.values, 0);
      ASSERT(BENCODE_KIND_NUMBER == v1.kind);
      ASSERT(123 == v1.num);
    }

    {
      BencodeValue v2 = dyn_at(dict.values, 1);
      ASSERT(BENCODE_KIND_STRING == v2.kind);
      ASSERT(string_eq(S("hello"), v2.s));
    }
  }
  {
    BencodeParseResult res = bencode_parse(S("2:abfoo"), &arena);
    ASSERT(STATUS_OK == res.status);
    ASSERT(BENCODE_KIND_STRING == res.value.kind);
    ASSERT(string_eq(S("ab"), res.value.s));
    ASSERT(string_eq(S("foo"), res.remaining));
  }
}

int main() {
  test_bencode_parse_u64();
  test_bencode_parse_string();
  test_bencode_parse();
}
