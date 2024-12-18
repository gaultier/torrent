#include "bencode.c"

static void test_bencode_parse_u64() {
  {
    BencodeNumberParseResult res = bencode_parse_number(S(""));
    ASSERT(BENCODE_ERR == res.status);
  }
  {
    BencodeNumberParseResult res = bencode_parse_number(S("a"));
    ASSERT(BENCODE_ERR == res.status);
  }
  {
    BencodeNumberParseResult res = bencode_parse_number(S("i"));
    ASSERT(BENCODE_ERR == res.status);
  }
  {
    BencodeNumberParseResult res = bencode_parse_number(S("ie"));
    ASSERT(BENCODE_ERR == res.status);
  }
  {
    BencodeNumberParseResult res = bencode_parse_number(S("i123"));
    ASSERT(BENCODE_ERR == res.status);
  }
  {
    BencodeNumberParseResult res = bencode_parse_number(S("123"));
    ASSERT(BENCODE_ERR == res.status);
  }
  {
    BencodeNumberParseResult res = bencode_parse_number(S("i123ehello"));
    ASSERT(BENCODE_OK == res.status);
    ASSERT(123 == res.num);
    ASSERT(string_eq(res.remaining, S("hello")));
  }
}

int main() { test_bencode_parse_u64(); }
