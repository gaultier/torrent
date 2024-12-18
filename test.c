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

int main() {
  test_bencode_parse_u64();
  test_bencode_parse_string();
}
