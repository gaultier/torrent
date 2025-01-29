
#include "peer.c"
#include "tracker.c"

static void test_bencode_decode_u64() {
  {
    BencodeNumberDecodeResult res = bencode_decode_number(PG_S(""));
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(PG_S("a"));
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(PG_S("i"));
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(PG_S("ie"));
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(PG_S("i123"));
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(PG_S("123"));
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(PG_S("i-123e"));
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeNumberDecodeResult res = bencode_decode_number(PG_S("i123ehello"));
    PG_ASSERT(0 == res.err);
    PG_ASSERT(123 == res.num);
    PG_ASSERT(pg_string_eq(res.remaining, PG_S("hello")));
  }
}

static void test_bencode_decode_string() {
  {
    BencodeStringDecodeResult res = bencode_decode_string(PG_S(""));
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(PG_S("a"));
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(PG_S("1"));
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(PG_S("0"));
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(PG_S("0:"));
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(PG_S("1:"));
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(PG_S("2:a"));
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeStringDecodeResult res = bencode_decode_string(PG_S("2:abc"));
    PG_ASSERT(0 == res.err);
    PG_ASSERT(pg_string_eq(res.s, PG_S("ab")));
    PG_ASSERT(pg_string_eq(res.remaining, PG_S("c")));
  }
}

static void test_bencode_decode_list() {
  PgArena arena = pg_arena_make_from_virtual_mem(4 * PG_KiB);
  {
    BencodeListDecodeResult res = bencode_decode_list(PG_S(""), &arena);
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeListDecodeResult res = bencode_decode_list(PG_S("a"), &arena);
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeListDecodeResult res = bencode_decode_list(PG_S("l"), &arena);
    PG_ASSERT(0 != res.err);
  }

  {
    BencodeListDecodeResult res = bencode_decode_list(PG_S("lefoo"), &arena);
    PG_ASSERT(0 == res.err);
    PG_ASSERT(0 == res.values.len);
    PG_ASSERT(pg_string_eq(res.remaining, PG_S("foo")));
  }

  {
    BencodeListDecodeResult res =
        bencode_decode_list(PG_S("l2:abi123eefoo"), &arena);
    PG_ASSERT(0 == res.err);
    PG_ASSERT(2 == res.values.len);
    PG_ASSERT(pg_string_eq(res.remaining, PG_S("foo")));

    {
      BencodeValue v1 = PG_SLICE_AT(res.values, 0);
      PG_ASSERT(BENCODE_KIND_STRING == v1.kind);
      PG_ASSERT(pg_string_eq(PG_S("ab"), v1.s));
    }

    {
      BencodeValue v2 = PG_SLICE_AT(res.values, 1);
      PG_ASSERT(BENCODE_KIND_NUMBER == v2.kind);
      PG_ASSERT(123 == v2.num);
    }
  }
  {
    BencodeValueDecodeResult res =
        bencode_decode_value(PG_S("l2:abi123eefoo"), &arena);
    PG_ASSERT(0 == res.err);
    PG_ASSERT(BENCODE_KIND_LIST == res.value.kind);
    PG_ASSERT(pg_string_eq(res.remaining, PG_S("foo")));

    DynBencodeValues values = res.value.list;
    PG_ASSERT(2 == values.len);

    {
      BencodeValue v1 = PG_SLICE_AT(values, 0);
      PG_ASSERT(BENCODE_KIND_STRING == v1.kind);
      PG_ASSERT(pg_string_eq(PG_S("ab"), v1.s));
    }

    {
      BencodeValue v2 = PG_SLICE_AT(values, 1);
      PG_ASSERT(BENCODE_KIND_NUMBER == v2.kind);
      PG_ASSERT(123 == v2.num);
    }
  }
}

static void test_bencode_decode() {
  PgArena arena = pg_arena_make_from_virtual_mem(4 * PG_KiB);
  {
    BencodeValueDecodeResult res =
        bencode_decode_value(PG_S("i123ei456e"), &arena);
    PG_ASSERT(0 == res.err);
    PG_ASSERT(BENCODE_KIND_NUMBER == res.value.kind);
    PG_ASSERT(123 == res.value.num);
    PG_ASSERT(pg_string_eq(PG_S("i456e"), res.remaining));
  }

  // Unordered keys.
  {
    BencodeValueDecodeResult res =
        bencode_decode_value(PG_S("d2:abi123e2:ab5:helloefoo"), &arena);
    PG_ASSERT(0 != res.err);
  }

  {
    BencodeValueDecodeResult res =
        bencode_decode_value(PG_S("d2:abi123e3:xyz5:helloefoo"), &arena);
    PG_ASSERT(0 == res.err);
    PG_ASSERT(BENCODE_KIND_DICTIONARY == res.value.kind);
    PG_ASSERT(pg_string_eq(PG_S("foo"), res.remaining));

    BencodeDictionary dict = res.value.dict;
    PG_ASSERT(2 == dict.keys.len);
    PG_ASSERT(2 == dict.values.len);

    {
      PgString k1 = PG_SLICE_AT(dict.keys, 0);
      PG_ASSERT(pg_string_eq(PG_S("ab"), k1));
    }

    {
      PgString k2 = PG_SLICE_AT(dict.keys, 1);
      PG_ASSERT(pg_string_eq(PG_S("xyz"), k2));
    }

    {
      BencodeValue v1 = PG_SLICE_AT(dict.values, 0);
      PG_ASSERT(BENCODE_KIND_NUMBER == v1.kind);
      PG_ASSERT(123 == v1.num);
    }

    {
      BencodeValue v2 = PG_SLICE_AT(dict.values, 1);
      PG_ASSERT(BENCODE_KIND_STRING == v2.kind);
      PG_ASSERT(pg_string_eq(PG_S("hello"), v2.s));
    }
  }
  {
    BencodeValueDecodeResult res =
        bencode_decode_value(PG_S("2:abfoo"), &arena);
    PG_ASSERT(0 == res.err);
    PG_ASSERT(BENCODE_KIND_STRING == res.value.kind);
    PG_ASSERT(pg_string_eq(PG_S("ab"), res.value.s));
    PG_ASSERT(pg_string_eq(PG_S("foo"), res.remaining));
  }
}

static void test_decode_metainfo() {
  PgArena arena = pg_arena_make_from_virtual_mem(4 * PG_KiB);
  PgString torrent_file_content = PG_S(
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
  PG_ASSERT(0 == res.err);

  PG_ASSERT(pg_string_eq(PG_S("http"), res.res.announce.scheme));
  PG_ASSERT(
      pg_string_eq(PG_S("OpenBSD.somedomain.net"), res.res.announce.host));
  PG_ASSERT(6969 == res.res.announce.port);
  PG_ASSERT(1 == res.res.announce.path_components.len);
  PgString path_component0 = PG_SLICE_AT(res.res.announce.path_components, 0);
  PG_ASSERT(pg_string_eq(PG_S("announce"), path_component0));

  PG_ASSERT(234883072 == res.res.length);
  PG_ASSERT(
      pg_string_eq(res.res.name, PG_S("OpenBSD_7.4_alpha_install74.iso")));
  PG_ASSERT(262144 == res.res.piece_length);
  PG_ASSERT(pg_string_eq(res.res.pieces, PG_S("abcdefgh")));
}

static void test_bencode_decode_encode() {
  PgArena arena = pg_arena_make_from_virtual_mem(4 * PG_KiB);
  PgString torrent_file_content = PG_S(
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
  PG_ASSERT(0 == res.err);

  Pgu8Dyn sb = {0};
  PgWriter w = pg_writer_make_from_string_builder(&sb, &arena);

  PG_ASSERT(0 == bencode_encode(res.value, &w, &arena));
  PgString encoded = PG_DYN_SLICE(PgString, sb);
  PG_ASSERT(pg_string_eq(encoded, torrent_file_content));
}

static void test_tracker_compute_info_hash() {
  PgArena arena = pg_arena_make_from_virtual_mem(4 * PG_KiB);
  PgString torrent_file_content = PG_S(
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
  PG_ASSERT(0 == res.err);

  PgString hash = {
      .data = pg_arena_new(&arena, u8, PG_SHA1_DIGEST_LENGTH),
      .len = PG_SHA1_DIGEST_LENGTH,
  };
  tracker_compute_info_hash(res.res, hash, arena);

  u8 expected_hash[PG_SHA1_DIGEST_LENGTH] = {
      0xe8, 0xa4, 0x67, 0x8c, 0x48, 0x5d, 0x86, 0xd3, 0x06, 0xc3,
      0x90, 0xe8, 0x7d, 0x3a, 0x01, 0x4f, 0x8a, 0x07, 0x2d, 0x7a,
  };
  PG_ASSERT(hash.len == sizeof(expected_hash));
  PG_ASSERT(0 == memcmp(hash.data, expected_hash, hash.len));
}

static void test_peer_make_handshake() {
  PgArena arena = pg_arena_make_from_virtual_mem(4 * PG_KiB);
  PgString info_hash = PG_S("abcdefghijklmnopqrst");
  PgString handshake = peer_make_handshake(info_hash, &arena);

  PG_ASSERT(HANDSHAKE_LENGTH == handshake.len);
  PG_ASSERT(pg_string_starts_with(handshake, PG_S("\x13"
                                                  "BitTorrent protocol")));
}

#if 0
static void test_peer_receive_handshake() {
  PgArena arena = pg_arena_make_from_virtual_mem(4 * KiB);
  PgArena tmp_arena = pg_arena_make_from_virtual_mem(4 * KiB);

  PgString req_slice = PG_S("\x13"
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
  peer.reader = pg_reader_make_from_slice(&src_ctx);
  peer.arena = arena;
  peer.tmp_arena = tmp_arena;
  peer.info_hash = PG_S("abcdefghijklmnopqrst");
  PG_ASSERT(PG_SHA1_DIGEST_LENGTH == peer.info_hash.len);

  PgError err = peer_receive_handshake(&peer);
  PG_ASSERT(0 == err);

  MemReadContext *ctx = peer.reader.ctx;
  PG_ASSERT(HANDSHAKE_LENGTH == ctx->idx);
}

static void test_peer_receive_any_message_bitfield() {
  PgArena arena = pg_arena_make_from_virtual_mem(4 * KiB);
  PgArena tmp_arena = pg_arena_make_from_virtual_mem(4 * KiB);

  PgString read_slice = PG_S("\x0"
                             "\x0"
                             "\x0"
                             "\x1b"
                             "\x5"
                             "abcdefghijklmnopqrstuvwxyz");

  Peer peer = {0};
  peer.address.port = 6881;
  MemReadContext src_ctx = {.s = read_slice};
  peer.reader = pg_reader_make_from_slice(&src_ctx);
  peer.arena = arena;
  peer.tmp_arena = tmp_arena;

  PeerMessageResult res = peer_receive_any_message(&peer);
  PG_ASSERT(STATUS_OK == res.status);

  MemReadContext *ctx = peer.reader.ctx;
  PG_ASSERT(4 + 1 + 26 == ctx->idx);

  PG_ASSERT(PEER_MSG_KIND_BITFIELD == res.msg.kind);
}

static void test_peer_send_message() {
  PgArena arena = pg_arena_make_from_virtual_mem(4 * KiB);
  PgArena tmp_arena = pg_arena_make_from_virtual_mem(4 * KiB);
  PgArena pg_writer_arena = pg_arena_make_from_virtual_mem(4 * KiB);

  Peer peer = {0};
  peer.address.port = 6881;
  peer.writer = pg_writer_make_for_buf(&pg_writer_arena);
  peer.arena = arena;
  peer.tmp_arena = tmp_arena;
  peer.info_hash = PG_S("abcdefghijklmnopqrst");
  PG_ASSERT(PG_SHA1_DIGEST_LENGTH == peer.info_hash.len);

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
  PG_ASSERT(0 == err);

  WriterBufCtx *ctx = peer.writer.ctx;
  PG_ASSERT(sizeof(u32) + 1 + 3 * sizeof(u32) == ctx->sb.len);

  PgString expected = PG_S(
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
  PgString got = PG_DYN_SLICE(PgString, ctx->sb);
  PG_ASSERT(pg_string_eq(expected, got));
}
#endif

static void test_download_compute_max_blocks_per_piece_count() {
  PG_ASSERT(1 == download_compute_max_blocks_per_piece_count(1));
  PG_ASSERT(1 == download_compute_max_blocks_per_piece_count(BLOCK_SIZE));
  PG_ASSERT(2 == download_compute_max_blocks_per_piece_count(BLOCK_SIZE + 1));
  PG_ASSERT(32 == download_compute_max_blocks_per_piece_count(BLOCK_SIZE * 32));
}

static void test_download_compute_blocks_count_for_piece() {
  PG_ASSERT(32 == download_compute_blocks_count_for_piece(1243, 32 * BLOCK_SIZE,
                                                          652652544));
  PG_ASSERT(27 == download_compute_blocks_count_for_piece(
                      1244 /* Last piece */, 32 * BLOCK_SIZE, 652652544));
}

static void test_download_compute_block_length() {
  PG_ASSERT(BLOCK_SIZE == download_compute_block_length(0, BLOCK_SIZE * 32));
  PG_ASSERT(BLOCK_SIZE == download_compute_block_length(1, BLOCK_SIZE * 32));
  PG_ASSERT(1 == download_compute_block_length(32, BLOCK_SIZE * 32 + 1));
}

static void test_download_pick_next_piece() {
  // We have everything, remote has nothing.
  {
    PgString local_bitfield_have = PG_S("\xff");
    PgString remote_bitfield_have = PG_S("\x00");
    Pgu32Ok res =
        download_pick_next_piece(local_bitfield_have, remote_bitfield_have, 8);
    PG_ASSERT(!res.ok);
  }
  // Remote has everything, local has nothing.
  {
    PgString local_bitfield_have = PG_S("\x00");
    PgString remote_bitfield_have = PG_S("\xff");
    Pgu32Ok res =
        download_pick_next_piece(local_bitfield_have, remote_bitfield_have, 8);
    PG_ASSERT(res.ok);
    PG_ASSERT(res.res < 8);
  }

  // Only one choice.
  {
    PgString local_bitfield_have = PG_S("\x03");
    PgString remote_bitfield_have = PG_S("\x04");
    Pgu32Ok res =
        download_pick_next_piece(local_bitfield_have, remote_bitfield_have, 8);
    PG_ASSERT(res.ok);
    PG_ASSERT(2 == res.res);
  }
  // Number of pieces smaller than 8.
  {
    PgString local_bitfield_have = PG_S("\x07");
    PgString remote_bitfield_have = PG_S("\x07");
    Pgu32Ok res =
        download_pick_next_piece(local_bitfield_have, remote_bitfield_have, 3);
    PG_ASSERT(!res.ok);
  }
}

static void test_piece_download_pick_next_block() {

  // Trivial case: pick first block.
  {
    PgArena arena =
        pg_arena_make_from_virtual_mem(4 * PG_KiB + 32 * BLOCK_SIZE);
    PieceDownload pd = piece_download_make(0, BLOCK_SIZE * 32, 32, &arena);
    Download download = {
        .max_blocks_per_piece_count = 32,
        .piece_length = 32 * BLOCK_SIZE,
        .pieces_count = 3,
        .total_file_size = 2 * 32 * BLOCK_SIZE + 1,
        .pieces_have = pg_string_make(1, &arena),
    };
    Pgu32Ok res = piece_download_pick_next_block(&pd, &download, 1);
    PG_ASSERT(res.ok);
    PG_ASSERT(res.res < 32);

    PG_ASSERT(1 == pg_bitfield_count(pd.blocks_bitfield_downloading));
  }

  // Max concurrent downloads reached.
  {
    PgArena arena =
        pg_arena_make_from_virtual_mem(4 * PG_KiB + 32 * BLOCK_SIZE);

    PieceDownload pd = piece_download_make(0, BLOCK_SIZE * 32, 32, &arena);
    Download download = {
        .max_blocks_per_piece_count = 32,
        .piece_length = 32 * BLOCK_SIZE,
        .pieces_count = 3,
        .total_file_size = 2 * 32 * BLOCK_SIZE + 1,
        .pieces_have = pg_string_make(1, &arena),
    };
    {
      Pgu32Ok res = piece_download_pick_next_block(&pd, &download, 1);
      PG_ASSERT(res.ok);
      PG_ASSERT(res.res < 32);

      PG_ASSERT(1 == pg_bitfield_count(pd.blocks_bitfield_downloading));
    }

    {
      Pgu32Ok res = piece_download_pick_next_block(&pd, &download, 1);
      PG_ASSERT(!res.ok);

      PG_ASSERT(1 == pg_bitfield_count(pd.blocks_bitfield_downloading));
    }
  }

  // All blocks downloaded.
  {
    PgArena arena =
        pg_arena_make_from_virtual_mem(4 * PG_KiB + 32 * BLOCK_SIZE);

    PieceDownload pd = piece_download_make(0, BLOCK_SIZE * 32, 32, &arena);
    Download download = {
        .max_blocks_per_piece_count = 32,
        .piece_length = 32 * BLOCK_SIZE,
        .pieces_count = 3,
        .total_file_size = 2 * 32 * BLOCK_SIZE + 1,
        .pieces_have = pg_string_make(1, &arena),
    };

    for (u32 i = 0; i < 32; i++) {
      pg_bitfield_set(pd.blocks_bitfield_have, i, true);
    }
    {
      Pgu32Ok res = piece_download_pick_next_block(&pd, &download, 1);
      PG_ASSERT(!res.ok);
    }
  }

  // One block left to download.
  {
    PgArena arena =
        pg_arena_make_from_virtual_mem(4 * PG_KiB + 32 * BLOCK_SIZE);

    PieceDownload pd = piece_download_make(0, BLOCK_SIZE * 32, 32, &arena);
    Download download = {
        .max_blocks_per_piece_count = 32,
        .piece_length = 32 * BLOCK_SIZE,
        .pieces_count = 3,
        .total_file_size = 2 * 32 * BLOCK_SIZE + 1,
        .pieces_have = pg_string_make(1, &arena),
    };

    for (u32 i = 0; i < 32; i++) {
      pg_bitfield_set(pd.blocks_bitfield_have, i, true);
    }
    pg_bitfield_set(pd.blocks_bitfield_have, 10, false);

    {
      Pgu32Ok res = piece_download_pick_next_block(&pd, &download, 1);
      PG_ASSERT(res.ok);
      PG_ASSERT(10 == res.res);
    }
  }

  // Last piece which is smaller.
  {
    PgArena arena =
        pg_arena_make_from_virtual_mem(4 * PG_KiB + 32 * BLOCK_SIZE);

    PieceDownload pd = piece_download_make(2, BLOCK_SIZE * 32, 32, &arena);
    Download download = {
        .max_blocks_per_piece_count = 32,
        .piece_length = 32 * BLOCK_SIZE,
        .pieces_count = 3,
        .total_file_size = 2 * 32 * BLOCK_SIZE + 1,
        .pieces_have = pg_string_make(1, &arena),
    };

    {
      Pgu32Ok res = piece_download_pick_next_block(&pd, &download, 1);
      PG_ASSERT(res.ok);
      PG_ASSERT(0 == res.res);
    }
    {
      Pgu32Ok res = piece_download_pick_next_block(&pd, &download, 1);
      PG_ASSERT(!res.ok);
    }
  }
}

int main() {
  test_bencode_decode_u64();
  test_bencode_decode_string();
  test_bencode_decode();
  test_bencode_decode_list();
  test_decode_metainfo();
  test_bencode_decode_encode();
  test_tracker_compute_info_hash();
  test_peer_make_handshake();
  test_download_compute_max_blocks_per_piece_count();
#if 0
  test_peer_receive_handshake();
  test_peer_receive_any_message_bitfield();
  test_peer_send_message();
#endif
  test_download_compute_blocks_count_for_piece();
  test_download_compute_block_length();
  test_download_pick_next_piece();
  test_piece_download_pick_next_block();
}
