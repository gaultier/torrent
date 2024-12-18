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

static void test_bencode_parse_list() {
  Arena arena = arena_make_from_virtual_mem(4 * KiB);
  {
    BencodeListParseResult res = bencode_parse_list(S(""), &arena);
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeListParseResult res = bencode_parse_list(S("a"), &arena);
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeListParseResult res = bencode_parse_list(S("l"), &arena);
    ASSERT(STATUS_ERR == res.status);
  }

  {
    BencodeListParseResult res = bencode_parse_list(S("lefoo"), &arena);
    ASSERT(STATUS_OK == res.status);
    ASSERT(0 == res.values.len);
    ASSERT(string_eq(res.remaining, S("foo")));
  }

  {
    BencodeListParseResult res =
        bencode_parse_list(S("l2:abi123eefoo"), &arena);
    ASSERT(STATUS_OK == res.status);
    ASSERT(2 == res.values.len);
    ASSERT(string_eq(res.remaining, S("foo")));

    {
      BencodeValue v1 = dyn_at(res.values, 0);
      ASSERT(BENCODE_KIND_STRING == v1.kind);
      ASSERT(string_eq(S("ab"), v1.s));
    }

    {
      BencodeValue v2 = dyn_at(res.values, 1);
      ASSERT(BENCODE_KIND_NUMBER == v2.kind);
      ASSERT(123 == v2.num);
    }
  }
  {
    BencodeValueParseResult res =
        bencode_parse_value(S("l2:abi123eefoo"), &arena);
    ASSERT(STATUS_OK == res.status);
    ASSERT(BENCODE_KIND_LIST == res.value.kind);
    ASSERT(string_eq(res.remaining, S("foo")));

    DynBencodeValues values = res.value.list;
    ASSERT(2 == values.len);

    {
      BencodeValue v1 = dyn_at(values, 0);
      ASSERT(BENCODE_KIND_STRING == v1.kind);
      ASSERT(string_eq(S("ab"), v1.s));
    }

    {
      BencodeValue v2 = dyn_at(values, 1);
      ASSERT(BENCODE_KIND_NUMBER == v2.kind);
      ASSERT(123 == v2.num);
    }
  }
}

static void test_bencode_parse() {
  Arena arena = arena_make_from_virtual_mem(4 * KiB);
  {
    BencodeValueParseResult res = bencode_parse_value(S("i123ei456e"), &arena);
    ASSERT(STATUS_OK == res.status);
    ASSERT(BENCODE_KIND_NUMBER == res.value.kind);
    ASSERT(123 == res.value.num);
    ASSERT(string_eq(S("i456e"), res.remaining));
  }
  {
    BencodeValueParseResult res =
        bencode_parse_value(S("d2:abi123e3:xyz5:helloefoo"), &arena);
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
    BencodeValueParseResult res = bencode_parse_value(S("2:abfoo"), &arena);
    ASSERT(STATUS_OK == res.status);
    ASSERT(BENCODE_KIND_STRING == res.value.kind);
    ASSERT(string_eq(S("ab"), res.value.s));
    ASSERT(string_eq(S("foo"), res.remaining));
  }
}

static void test_parse_metainfo() {
  Arena arena = arena_make_from_virtual_mem(32 * KiB);
  String torrent_file_content = S(
      "d8:announce43:http://OpenBSD.somedomain.net:6969/"
      "announce7:comment107:OpenBSD/7.4/alpha/install74.iso\nCreated by andrew "
      "fresh (andrew@afresh1.com)\n"
      "http://OpenBSD.somedomain.net/10:created by13:mktorrent 1.113:creation "
      "datei1697360758e4:infod6:lengthi234883072e4:name31:OpenBSD_7.4_alpha_"
      "install74.iso12:piece "
      "lengthi262144e6:pieces8:abcdefghe8:url-list65:http://"
      "openbsd.somedomain.net/pub/OpenBSD_7.4_alpha_install74.isoe");
  ParseMetaInfoResult res = parse_metainfo(torrent_file_content, &arena);
  ASSERT(STATUS_OK == res.status);
  ASSERT(string_eq(res.metainfo.announce,
                   S("http://OpenBSD.somedomain.net:6969/announce")));
  ASSERT(234883072 == res.metainfo.length);
  ASSERT(string_eq(res.metainfo.name, S("OpenBSD_7.4_alpha_install74.iso")));
  ASSERT(262144 == res.metainfo.piece_length);
  ASSERT(string_eq(res.metainfo.pieces, S("abcdefgh")));
}

int main() {
  test_bencode_parse_u64();
  test_bencode_parse_string();
  test_bencode_parse();
  test_bencode_parse_list();
  test_parse_metainfo();
}
