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

static void test_bencode_parse_string() {
  {
    BencodeStringParseResult res = bencode_parse_string(S(""));
    ASSERT(BENCODE_ERR == res.status);
  }
  {
    BencodeStringParseResult res = bencode_parse_string(S("a"));
    ASSERT(BENCODE_ERR == res.status);
  }
  {
    BencodeStringParseResult res = bencode_parse_string(S("1"));
    ASSERT(BENCODE_ERR == res.status);
  }
  {
    BencodeStringParseResult res = bencode_parse_string(S("0"));
    ASSERT(BENCODE_ERR == res.status);
  }
  {
    BencodeStringParseResult res = bencode_parse_string(S("0:"));
    ASSERT(BENCODE_ERR == res.status);
  }
  {
    BencodeStringParseResult res = bencode_parse_string(S("1:"));
    ASSERT(BENCODE_ERR == res.status);
  }
  {
    BencodeStringParseResult res = bencode_parse_string(S("2:a"));
    ASSERT(BENCODE_ERR == res.status);
  }
  {
    BencodeStringParseResult res = bencode_parse_string(S("2:abc"));
    ASSERT(BENCODE_OK == res.status);
    ASSERT(string_eq(res.s, S("ab")));
    ASSERT(string_eq(res.remaining, S("c")));
  }
}

int main() {
  test_bencode_parse_u64();
  test_bencode_parse_string();
}
