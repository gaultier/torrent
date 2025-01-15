#if 0
#include "peer.c"
#endif

#include "tracker.c"

static void test_bencode_decode_u64() {
  {
    BencodeNumberDecodeResult res = bencode_decode_number(S(""));
    ASSERT(0 != res.err);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(S("a"));
    ASSERT(0 != res.err);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(S("i"));
    ASSERT(0 != res.err);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(S("ie"));
    ASSERT(0 != res.err);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(S("i123"));
    ASSERT(0 != res.err);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(S("123"));
    ASSERT(0 != res.err);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(S("i-123e"));
    ASSERT(0 != res.err);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(S("i123ehello"));
    ASSERT(0 == res.err);
    ASSERT(123 == res.num);
    ASSERT(string_eq(res.remaining, S("hello")));
  }
}

static void test_bencode_decode_string() {
  {
    BencodeStringDecodeResult res = bencode_decode_string(S(""));
    ASSERT(0 != res.err);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(S("a"));
    ASSERT(0 != res.err);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(S("1"));
    ASSERT(0 != res.err);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(S("0"));
    ASSERT(0 != res.err);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(S("0:"));
    ASSERT(0 != res.err);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(S("1:"));
    ASSERT(0 != res.err);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(S("2:a"));
    ASSERT(0 != res.err);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(S("2:abc"));
    ASSERT(0 == res.err);
    ASSERT(string_eq(res.s, S("ab")));
    ASSERT(string_eq(res.remaining, S("c")));
  }
}

static void test_bencode_decode_list() {
  Arena arena = arena_make_from_virtual_mem(4 * PG_KiB);
  {
    BencodeListDecodeResult res = bencode_decode_list(S(""), &arena);
    ASSERT(0 != res.err);
  }
  {
    BencodeListDecodeResult res = bencode_decode_list(S("a"), &arena);
    ASSERT(0 != res.err);
  }
  {
    BencodeListDecodeResult res = bencode_decode_list(S("l"), &arena);
    ASSERT(0 != res.err);
  }

  {
    BencodeListDecodeResult res = bencode_decode_list(S("lefoo"), &arena);
    ASSERT(0 == res.err);
    ASSERT(0 == res.values.len);
    ASSERT(string_eq(res.remaining, S("foo")));
  }

  {
    BencodeListDecodeResult res =
        bencode_decode_list(S("l2:abi123eefoo"), &arena);
    ASSERT(0 == res.err);
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
    ASSERT(0 == res.err);
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
  Arena arena = arena_make_from_virtual_mem(4 * PG_KiB);
  {
    BencodeValueDecodeResult res =
        bencode_decode_value(S("i123ei456e"), &arena);
    ASSERT(0 == res.err);
    ASSERT(BENCODE_KIND_NUMBER == res.value.kind);
    ASSERT(123 == res.value.num);
    ASSERT(string_eq(S("i456e"), res.remaining));
  }

  // Unordered keys.
  {
    BencodeValueDecodeResult res =
        bencode_decode_value(S("d2:abi123e2:ab5:helloefoo"), &arena);
    ASSERT(0 != res.err);
  }

  {
    BencodeValueDecodeResult res =
        bencode_decode_value(S("d2:abi123e3:xyz5:helloefoo"), &arena);
    ASSERT(0 == res.err);
    ASSERT(BENCODE_KIND_DICTIONARY == res.value.kind);
    ASSERT(string_eq(S("foo"), res.remaining));

    BencodeDictionary dict = res.value.dict;
    ASSERT(2 == dict.keys.len);
    ASSERT(2 == dict.values.len);

    {
      PgString k1 = dyn_at(dict.keys, 0);
      ASSERT(string_eq(S("ab"), k1));
    }

    {
      PgString k2 = dyn_at(dict.keys, 1);
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
    ASSERT(0 == res.err);
    ASSERT(BENCODE_KIND_STRING == res.value.kind);
    ASSERT(string_eq(S("ab"), res.value.s));
    ASSERT(string_eq(S("foo"), res.remaining));
  }
}

static void test_decode_metainfo() {
  Arena arena = arena_make_from_virtual_mem(4 * PG_KiB);
  PgString torrent_file_content = S(
      "d8:announce43:http://OpenBSD.somedomain.net:6969/"
      "announce7:comment107:OpenBSD/7.4/alpha/install74.iso\nCreated by andrew "
      "fresh (andrew@afresh1.com)\n"
      "http://OpenBSD.somedomain.net/10:created by13:mktorrent 1.113:creation "
      "datei1697360758e4:infod6:lengthi234883072e4:name31:OpenBSD_7.4_alpha_"
      "install74.iso12:piece "
      "lengthi262144e6:pieces8:abcdefghe8:url-list65:http://"
      "openbsd.somedomain.net/pub/OpenBSD_7.4_alpha_install74.isoe");
  DecodeMetaInfoResult res =
      bencode_decode_metainfo(torrent_file_content, &arena);
  ASSERT(0 == res.err);

  ASSERT(string_eq(S("http"), res.res.announce.scheme));
  ASSERT(string_eq(S("OpenBSD.somedomain.net"), res.res.announce.host));
  ASSERT(6969 == res.res.announce.port);
  ASSERT(1 == res.res.announce.path_components.len);
  PgString path_component0 = slice_at(res.res.announce.path_components, 0);
  ASSERT(string_eq(S("announce"), path_component0));

  ASSERT(234883072 == res.res.length);
  ASSERT(string_eq(res.res.name, S("OpenBSD_7.4_alpha_install74.iso")));
  ASSERT(262144 == res.res.piece_length);
  ASSERT(string_eq(res.res.pieces, S("abcdefgh")));
}

static void test_bencode_decode_encode() {
  Arena arena = arena_make_from_virtual_mem(4 * PG_KiB);
  PgString torrent_file_content = S(
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
  ASSERT(0 == res.err);

  Pgu8Dyn sb = {0};
  bencode_encode(res.value, &sb, &arena);
  PgString encoded = dyn_slice(PgString, sb);
  ASSERT(string_eq(encoded, torrent_file_content));
}

static void test_tracker_compute_info_hash() {
  Arena arena = arena_make_from_virtual_mem(4 * PG_KiB);
  PgString torrent_file_content = S(
      "d8:announce43:http://OpenBSD.somedomain.net:6969/"
      "announce7:comment107:OpenBSD/7.4/alpha/install74.iso\nCreated by andrew "
      "fresh (andrew@afresh1.com)\n"
      "http://OpenBSD.somedomain.net/10:created by13:mktorrent 1.113:creation "
      "datei1697360758e4:infod6:lengthi234883072e4:name31:OpenBSD_7.4_alpha_"
      "install74.iso12:piece "
      "lengthi262144e6:pieces8:abcdefghe8:url-list65:http://"
      "openbsd.somedomain.net/pub/OpenBSD_7.4_alpha_install74.isoe");
  DecodeMetaInfoResult res =
      bencode_decode_metainfo(torrent_file_content, &arena);
  ASSERT(0 == res.err);

  PgString hash = {
      .data = arena_new(&arena, u8, 20),
      .len = 20,
  };
  tracker_compute_info_hash(res.res, hash, arena);

  u8 expected_hash[20] = {
      0xe8, 0xa4, 0x67, 0x8c, 0x48, 0x5d, 0x86, 0xd3, 0x06, 0xc3,
      0x90, 0xe8, 0x7d, 0x3a, 0x01, 0x4f, 0x8a, 0x07, 0x2d, 0x7a,
  };
  ASSERT(hash.len == sizeof(expected_hash));
  ASSERT(0 == memcmp(hash.data, expected_hash, hash.len));
}

#if 0
static void test_peer_send_handshake() {
  Arena arena = arena_make_from_virtual_mem(4 * KiB);
  Arena writer_arena = arena_make_from_virtual_mem(4 * KiB);

  Peer peer = {0};
  peer.address.port = 6881;
  peer.writer = writer_make_for_buf(&writer_arena);
  peer.arena = arena;
  peer.info_hash = S("abcdefghijklmnopqrst");
  ASSERT(20 == peer.info_hash.len);

  PgError err = peer_send_handshake(&peer);
  ASSERT(0 == err);

  WriterBufCtx *ctx = peer.writer.ctx;
  ASSERT(HANDSHAKE_LENGTH == ctx->sb.len);
}

static void test_peer_receive_handshake() {
  Arena arena = arena_make_from_virtual_mem(4 * KiB);
  Arena tmp_arena = arena_make_from_virtual_mem(4 * KiB);

  PgString req_slice = S("\x13"
                       "BitTorrent protocol"
                       "\x01"
                       "\x02"
                       "\x03"
                       "\x04"
                       "\x05"
                       "\x06"
                       "\x07"
                       "\x08"

                       "abcdefghijklmnopqrst"

                       "\x09"
                       "\x09"
                       "\x09"
                       "\x09"
                       "\x09"
                       "\x09"
                       "\x09"
                       "\x09"
                       "\x09"
                       "\x09"
                       "\x09"
                       "\x09"
                       "\x09"
                       "\x09"
                       "\x09"
                       "\x09"
                       "\x09"
                       "\x09"
                       "\x09"
                       "\x09");

  Peer peer = {0};
  peer.address.port = 6881;
  MemReadContext src_ctx = {.s = req_slice};
  peer.reader = reader_make_from_slice(&src_ctx);
  peer.arena = arena;
  peer.tmp_arena = tmp_arena;
  peer.info_hash = S("abcdefghijklmnopqrst");
  ASSERT(20 == peer.info_hash.len);

  PgError err = peer_receive_handshake(&peer);
  ASSERT(0 == err);

  MemReadContext *ctx = peer.reader.ctx;
  ASSERT(HANDSHAKE_LENGTH == ctx->idx);
}

static void test_peer_receive_any_message_bitfield() {
  Arena arena = arena_make_from_virtual_mem(4 * KiB);
  Arena tmp_arena = arena_make_from_virtual_mem(4 * KiB);

  PgString read_slice = S("\x0"
                        "\x0"
                        "\x0"
                        "\x1b"
                        "\x5"
                        "abcdefghijklmnopqrstuvwxyz");

  Peer peer = {0};
  peer.address.port = 6881;
  MemReadContext src_ctx = {.s = read_slice};
  peer.reader = reader_make_from_slice(&src_ctx);
  peer.arena = arena;
  peer.tmp_arena = tmp_arena;

  PeerMessageResult res = peer_receive_any_message(&peer);
  ASSERT(STATUS_OK == res.status);

  MemReadContext *ctx = peer.reader.ctx;
  ASSERT(4 + 1 + 26 == ctx->idx);

  ASSERT(PEER_MSG_KIND_BITFIELD == res.msg.kind);
}

static void test_peer_send_message() {
  Arena arena = arena_make_from_virtual_mem(4 * KiB);
  Arena tmp_arena = arena_make_from_virtual_mem(4 * KiB);
  Arena writer_arena = arena_make_from_virtual_mem(4 * KiB);

  Peer peer = {0};
  peer.address.port = 6881;
  peer.writer = writer_make_for_buf(&writer_arena);
  peer.arena = arena;
  peer.tmp_arena = tmp_arena;
  peer.info_hash = S("abcdefghijklmnopqrst");
  ASSERT(20 == peer.info_hash.len);

  PeerMessage msg = {
      .kind = PEER_MSG_KIND_REQUEST,
      .request =
          {
              .index = 2,
              .begin = 17 * BLOCK_LENGTH,
              .length = BLOCK_LENGTH,
          },
  };
  PgError err = peer_send_message(&peer, msg);
  ASSERT(0 == err);

  WriterBufCtx *ctx = peer.writer.ctx;
  ASSERT(sizeof(u32) + 1 + 3 * sizeof(u32) == ctx->sb.len);

  PgString expected = S(
      // Length.
      "\x0"
      "\x0"
      "\x0"
      "\x0d"
      // Tag.
      "\x06"
      // Request Index.
      "\x0"
      "\x0"
      "\x0"
      "\x02"

      // Request Begin.
      "\x0"
      "\x04"
      "\x40"
      "\x00"

      // Request Length.
      "\x0"
      "\x00"
      "\x40"
      "\x00");
  PgString got = dyn_slice(PgString, ctx->sb);
  ASSERT(string_eq(expected, got));
}
#endif

int main() {
  test_bencode_decode_u64();
  test_bencode_decode_string();
  test_bencode_decode();
  test_bencode_decode_list();
  test_decode_metainfo();
  test_bencode_decode_encode();
  test_tracker_compute_info_hash();
#if 0
  test_peer_send_handshake();
  test_peer_receive_handshake();
  test_peer_receive_any_message_bitfield();
  test_peer_send_message();
#endif
}
