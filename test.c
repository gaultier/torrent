#include "bencode.c"
#include "tracker.c"

static void test_bencode_decode_u64() {
  {
    BencodeNumberDecodeResult res = bencode_decode_number(S(""));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(S("a"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(S("i"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(S("ie"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(S("i123"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(S("123"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(S("i-123e"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(S("i123ehello"));
    ASSERT(STATUS_OK == res.status);
    ASSERT(123 == res.num);
    ASSERT(string_eq(res.remaining, S("hello")));
  }
}

static void test_bencode_decode_string() {
  {
    BencodeStringDecodeResult res = bencode_decode_string(S(""));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(S("a"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(S("1"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(S("0"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(S("0:"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(S("1:"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(S("2:a"));
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(S("2:abc"));
    ASSERT(STATUS_OK == res.status);
    ASSERT(string_eq(res.s, S("ab")));
    ASSERT(string_eq(res.remaining, S("c")));
  }
}

static void test_bencode_decode_list() {
  Arena arena = arena_make_from_virtual_mem(4 * KiB);
  {
    BencodeListDecodeResult res = bencode_decode_list(S(""), &arena);
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeListDecodeResult res = bencode_decode_list(S("a"), &arena);
    ASSERT(STATUS_ERR == res.status);
  }
  {
    BencodeListDecodeResult res = bencode_decode_list(S("l"), &arena);
    ASSERT(STATUS_ERR == res.status);
  }

  {
    BencodeListDecodeResult res = bencode_decode_list(S("lefoo"), &arena);
    ASSERT(STATUS_OK == res.status);
    ASSERT(0 == res.values.len);
    ASSERT(string_eq(res.remaining, S("foo")));
  }

  {
    BencodeListDecodeResult res =
        bencode_decode_list(S("l2:abi123eefoo"), &arena);
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
    BencodeValueDecodeResult res =
        bencode_decode_value(S("l2:abi123eefoo"), &arena);
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

static void test_bencode_decode() {
  Arena arena = arena_make_from_virtual_mem(4 * KiB);
  {
    BencodeValueDecodeResult res =
        bencode_decode_value(S("i123ei456e"), &arena);
    ASSERT(STATUS_OK == res.status);
    ASSERT(BENCODE_KIND_NUMBER == res.value.kind);
    ASSERT(123 == res.value.num);
    ASSERT(string_eq(S("i456e"), res.remaining));
  }

  // Unordered keys.
  {
    BencodeValueDecodeResult res =
        bencode_decode_value(S("d2:abi123e2:ab5:helloefoo"), &arena);
    ASSERT(STATUS_OK != res.status);
  }

  {
    BencodeValueDecodeResult res =
        bencode_decode_value(S("d2:abi123e3:xyz5:helloefoo"), &arena);
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
    BencodeValueDecodeResult res = bencode_decode_value(S("2:abfoo"), &arena);
    ASSERT(STATUS_OK == res.status);
    ASSERT(BENCODE_KIND_STRING == res.value.kind);
    ASSERT(string_eq(S("ab"), res.value.s));
    ASSERT(string_eq(S("foo"), res.remaining));
  }
}

static void test_decode_metainfo() {
  Arena arena = arena_make_from_virtual_mem(4 * KiB);
  String torrent_file_content = S(
      "d8:announce43:http://OpenBSD.somedomain.net:6969/"
      "announce7:comment107:OpenBSD/7.4/alpha/install74.iso\nCreated by andrew "
      "fresh (andrew@afresh1.com)\n"
      "http://OpenBSD.somedomain.net/10:created by13:mktorrent 1.113:creation "
      "datei1697360758e4:infod6:lengthi234883072e4:name31:OpenBSD_7.4_alpha_"
      "install74.iso12:piece "
      "lengthi262144e6:pieces8:abcdefghe8:url-list65:http://"
      "openbsd.somedomain.net/pub/OpenBSD_7.4_alpha_install74.isoe");
  DecodeMetaInfoResult res = decode_metainfo(torrent_file_content, &arena);
  ASSERT(STATUS_OK == res.status);
  ASSERT(string_eq(res.metainfo.announce,
                   S("http://OpenBSD.somedomain.net:6969/announce")));
  ASSERT(234883072 == res.metainfo.length);
  ASSERT(string_eq(res.metainfo.name, S("OpenBSD_7.4_alpha_install74.iso")));
  ASSERT(262144 == res.metainfo.piece_length);
  ASSERT(string_eq(res.metainfo.pieces, S("abcdefgh")));
}

static void test_bencode_decode_encode() {
  Arena arena = arena_make_from_virtual_mem(4 * KiB);
  String torrent_file_content = S(
      "d8:announce43:http://OpenBSD.somedomain.net:6969/"
      "announce7:comment107:OpenBSD/7.4/alpha/install74.iso\nCreated by andrew "
      "fresh (andrew@afresh1.com)\n"
      "http://OpenBSD.somedomain.net/10:created by13:mktorrent 1.113:creation "
      "datei1697360758e4:infod6:lengthi234883072e4:name31:OpenBSD_7.4_alpha_"
      "install74.iso12:piece "
      "lengthi262144e6:pieces8:abcdefghe8:url-list65:http://"
      "openbsd.somedomain.net/pub/OpenBSD_7.4_alpha_install74.isoe");
  BencodeValueDecodeResult res =
      bencode_decode_value(torrent_file_content, &arena);
  ASSERT(STATUS_OK == res.status);

  DynU8 sb = {0};
  bencode_encode(res.value, &sb, &arena);
  String encoded = dyn_slice(String, sb);
  ASSERT(string_eq(encoded, torrent_file_content));
}

static void test_tracker_compute_info_hash() {
  Arena arena = arena_make_from_virtual_mem(4 * KiB);
  String torrent_file_content = S(
      "d8:announce43:http://OpenBSD.somedomain.net:6969/"
      "announce7:comment107:OpenBSD/7.4/alpha/install74.iso\nCreated by andrew "
      "fresh (andrew@afresh1.com)\n"
      "http://OpenBSD.somedomain.net/10:created by13:mktorrent 1.113:creation "
      "datei1697360758e4:infod6:lengthi234883072e4:name31:OpenBSD_7.4_alpha_"
      "install74.iso12:piece "
      "lengthi262144e6:pieces8:abcdefghe8:url-list65:http://"
      "openbsd.somedomain.net/pub/OpenBSD_7.4_alpha_install74.isoe");
  DecodeMetaInfoResult res = decode_metainfo(torrent_file_content, &arena);
  ASSERT(STATUS_OK == res.status);

  u8 hash[20] = {0};
  tracker_compute_info_hash(res.metainfo, hash, &arena);

  u8 zero_hash[20] = {0};
  static_assert(sizeof(hash) == sizeof(zero_hash));

  ASSERT(0 != memcmp(hash, zero_hash, sizeof(hash)));
}

int main() {
  test_bencode_decode_u64();
  test_bencode_decode_string();
  test_bencode_decode();
  test_bencode_decode_list();
  test_decode_metainfo();
  test_bencode_decode_encode();
  test_tracker_compute_info_hash();
}
