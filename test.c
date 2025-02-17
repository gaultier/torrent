#include "peer.c"
#include "tracker.c"

static void test_bencode_decode_u64() {
  {
    BencodeValueDecodeResult res = bencode_decode_number(PG_S(""), 0);
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeValueDecodeResult res = bencode_decode_number(PG_S("a"), 0);
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeValueDecodeResult res = bencode_decode_number(PG_S("i"), 0);
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeValueDecodeResult res = bencode_decode_number(PG_S("ie"), 0);
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeValueDecodeResult res = bencode_decode_number(PG_S("i123"), 0);
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeValueDecodeResult res = bencode_decode_number(PG_S("123"), 0);
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeValueDecodeResult res = bencode_decode_number(PG_S("i-123e"), 0);
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeValueDecodeResult res =
        bencode_decode_number(PG_S("i123ehello"), 99);
    PG_ASSERT(0 == res.err);
    PG_ASSERT(123 == res.value.num);
    PG_ASSERT(99 == res.value.start);
    PG_ASSERT(99 + 5 == res.value.end);
    PG_ASSERT(pg_string_eq(res.remaining, PG_S("hello")));
  }
}

static void test_bencode_decode_string() {
  {
    BencodeValueDecodeResult res = bencode_decode_string(PG_S(""), 0);
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeValueDecodeResult res = bencode_decode_string(PG_S("a"), 0);
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeValueDecodeResult res = bencode_decode_string(PG_S("1"), 0);
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeValueDecodeResult res = bencode_decode_string(PG_S("0"), 0);
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeValueDecodeResult res = bencode_decode_string(PG_S("0:"), 0);
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeValueDecodeResult res = bencode_decode_string(PG_S("1:"), 0);
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeValueDecodeResult res = bencode_decode_string(PG_S("2:a"), 0);
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeValueDecodeResult res = bencode_decode_string(PG_S("2:abc"), 99);
    PG_ASSERT(0 == res.err);
    PG_ASSERT(99 == res.value.start);
    PG_ASSERT(99 + 4 == res.value.end);
    PG_ASSERT(pg_string_eq(res.value.s, PG_S("ab")));
    PG_ASSERT(pg_string_eq(res.remaining, PG_S("c")));
  }
}

static void test_bencode_decode_list() {
  PgArena arena = pg_arena_make_from_virtual_mem(4 * PG_KiB);
  PgArenaAllocator arena_allocator = pg_make_arena_allocator(&arena);
  PgAllocator *allocator = pg_arena_allocator_as_allocator(&arena_allocator);
  {
    BencodeValueDecodeResult res = bencode_decode_list(PG_S(""), 0, allocator);
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeValueDecodeResult res = bencode_decode_list(PG_S("a"), 0, allocator);
    PG_ASSERT(0 != res.err);
  }
  {
    BencodeValueDecodeResult res = bencode_decode_list(PG_S("l"), 0, allocator);
    PG_ASSERT(0 != res.err);
  }

  {
    BencodeValueDecodeResult res =
        bencode_decode_list(PG_S("lefoo"), 99, allocator);
    PG_ASSERT(0 == res.err);
    PG_ASSERT(99 == res.value.start);
    PG_ASSERT(99 + 2 == res.value.end);
    PG_ASSERT(0 == res.value.list.len);
    PG_ASSERT(pg_string_eq(res.remaining, PG_S("foo")));
  }

  {
    BencodeValueDecodeResult res =
        bencode_decode_list(PG_S("l2:abi123eefoo"), 99, allocator);
    PG_ASSERT(0 == res.err);
    PG_ASSERT(99 == res.value.start);
    PG_ASSERT(99 + 11 == res.value.end);
    PG_ASSERT(2 == res.value.list.len);
    PG_ASSERT(pg_string_eq(res.remaining, PG_S("foo")));

    {
      BencodeValue v1 = PG_SLICE_AT(res.value.list, 0);
      PG_ASSERT(99 + 1 == v1.start);
      PG_ASSERT(99 + 5 == v1.end);
      PG_ASSERT(BENCODE_KIND_STRING == v1.kind);
      PG_ASSERT(pg_string_eq(PG_S("ab"), v1.s));
    }

    {
      BencodeValue v2 = PG_SLICE_AT(res.value.list, 1);
      PG_ASSERT(99 + 5 == v2.start);
      PG_ASSERT(99 + 10 == v2.end);
      PG_ASSERT(BENCODE_KIND_NUMBER == v2.kind);
      PG_ASSERT(123 == v2.num);
    }
  }
  {
    BencodeValueDecodeResult res =
        bencode_decode_value(PG_S("l2:abi123eefoo"), 99, allocator);
    PG_ASSERT(0 == res.err);
    PG_ASSERT(99 == res.value.start);
    PG_ASSERT(99 + 11 == res.value.end);
    PG_ASSERT(BENCODE_KIND_LIST == res.value.kind);
    PG_ASSERT(pg_string_eq(res.remaining, PG_S("foo")));

    BencodeValueDyn values = res.value.list;
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
  PgArenaAllocator arena_allocator = pg_make_arena_allocator(&arena);
  PgAllocator *allocator = pg_arena_allocator_as_allocator(&arena_allocator);
  {
    BencodeValueDecodeResult res =
        bencode_decode_value(PG_S("i123ei456e"), 99, allocator);
    PG_ASSERT(0 == res.err);
    PG_ASSERT(99 == res.value.start);
    PG_ASSERT(99 + 5 == res.value.end);
    PG_ASSERT(BENCODE_KIND_NUMBER == res.value.kind);
    PG_ASSERT(123 == res.value.num);
    PG_ASSERT(pg_string_eq(PG_S("i456e"), res.remaining));
  }

  // Unordered keys.
  {
    BencodeValueDecodeResult res =
        bencode_decode_value(PG_S("d2:abi123e2:ab5:helloefoo"), 99, allocator);
    PG_ASSERT(0 != res.err);
  }

  {
    BencodeValueDecodeResult res =
        bencode_decode_value(PG_S("d2:abi123e3:xyz5:helloefoo"), 99, allocator);
    PG_ASSERT(0 == res.err);
    PG_ASSERT(99 == res.value.start);
    PG_ASSERT(99 + 23 == res.value.end);
    PG_ASSERT(BENCODE_KIND_DICTIONARY == res.value.kind);
    PG_ASSERT(pg_string_eq(PG_S("foo"), res.remaining));

    BencodeKeyValueDyn dict = res.value.dict;
    PG_ASSERT(2 == dict.len);

    {
      PgString k1 = PG_SLICE_AT(dict, 0).key;
      PG_ASSERT(pg_string_eq(PG_S("ab"), k1));
    }

    {
      PgString k2 = PG_SLICE_AT(dict, 1).key;
      PG_ASSERT(pg_string_eq(PG_S("xyz"), k2));
    }

    {
      BencodeValue v1 = PG_SLICE_AT(dict, 0).value;
      PG_ASSERT(BENCODE_KIND_NUMBER == v1.kind);
      PG_ASSERT(123 == v1.num);
    }

    {
      BencodeValue v2 = PG_SLICE_AT(dict, 1).value;
      PG_ASSERT(BENCODE_KIND_STRING == v2.kind);
      PG_ASSERT(pg_string_eq(PG_S("hello"), v2.s));
    }
  }
  {
    BencodeValueDecodeResult res =
        bencode_decode_value(PG_S("2:abfoo"), 99, allocator);
    PG_ASSERT(0 == res.err);
    PG_ASSERT(99 == res.value.start);
    PG_ASSERT(99 + 4 == res.value.end);
    PG_ASSERT(BENCODE_KIND_STRING == res.value.kind);
    PG_ASSERT(pg_string_eq(PG_S("ab"), res.value.s));
    PG_ASSERT(pg_string_eq(PG_S("foo"), res.remaining));
  }
}

static void test_decode_metainfo() {
  PgArena arena = pg_arena_make_from_virtual_mem(4 * PG_KiB);
  PgArenaAllocator arena_allocator = pg_make_arena_allocator(&arena);
  PgAllocator *allocator = pg_arena_allocator_as_allocator(&arena_allocator);

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
      bencode_decode_metainfo(torrent_file_content, allocator);
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
  PgArenaAllocator arena_allocator = pg_make_arena_allocator(&arena);
  PgAllocator *allocator = pg_arena_allocator_as_allocator(&arena_allocator);

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
      bencode_decode_value(torrent_file_content, 0, allocator);
  PG_ASSERT(0 == res.err);
  PG_ASSERT(0 == res.value.start);
  PG_ASSERT(torrent_file_content.len == res.value.end);

  Pgu8Dyn sb = {0};
  PgWriter w = pg_writer_make_from_string_builder(&sb, allocator);

  PG_ASSERT(0 == bencode_encode(res.value, &w, allocator));
  PgString encoded = PG_DYN_SLICE(PgString, sb);
  PG_ASSERT(pg_string_eq(encoded, torrent_file_content));
}

static void test_tracker_compute_info_hash() {
  PgArena arena = pg_arena_make_from_virtual_mem(4 * PG_KiB);
  PgArenaAllocator arena_allocator = pg_make_arena_allocator(&arena);
  PgAllocator *allocator = pg_arena_allocator_as_allocator(&arena_allocator);

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
      bencode_decode_metainfo(torrent_file_content, allocator);
  PG_ASSERT(0 == res.err);

  PgString info_encoded = PG_SLICE_RANGE(torrent_file_content,
                                         res.res.info_start, res.res.info_end);
  PgSha1 hash = pg_sha1(info_encoded);

  PgSha1 expected_hash = {.data = {
                              0xe8, 0xa4, 0x67, 0x8c, 0x48, 0x5d, 0x86,
                              0xd3, 0x06, 0xc3, 0x90, 0xe8, 0x7d, 0x3a,
                              0x01, 0x4f, 0x8a, 0x07, 0x2d, 0x7a,
                          }};
  PG_ASSERT(0 == memcmp(hash.data, expected_hash.data, PG_SHA1_DIGEST_LENGTH));
}

static void test_peer_make_handshake() {
  PgArena arena = pg_arena_make_from_virtual_mem(4 * PG_KiB);
  PgArenaAllocator arena_allocator = pg_make_arena_allocator(&arena);
  PgAllocator *allocator = pg_arena_allocator_as_allocator(&arena_allocator);

  PgSha1 info_hash = {.data = "abcdefghijklmnopqrst"};
  PgString handshake = peer_make_handshake(info_hash, allocator);

  PG_ASSERT(HANDSHAKE_LENGTH == handshake.len);
  PG_ASSERT(pg_string_starts_with(handshake, PG_S("\x13"
                                                  "BitTorrent protocol")));
}

static void test_download_compute_max_blocks_per_piece_count() {
  PG_ASSERT(1 == download_compute_max_blocks_per_piece_count(1));
  PG_ASSERT(1 == download_compute_max_blocks_per_piece_count(BLOCK_SIZE));
  PG_ASSERT(2 == download_compute_max_blocks_per_piece_count(BLOCK_SIZE + 1));
  PG_ASSERT(32 == download_compute_max_blocks_per_piece_count(BLOCK_SIZE * 32));
}

static void test_download_compute_blocks_count_for_piece() {
  Download download = {0};
  download.pieces_count = 1981;
  download.blocks_per_piece_max = 16;
  download.piece_length = download.blocks_per_piece_max * BLOCK_SIZE;
  download.total_size = 519174144;
  download.blocks_count = 31688;

  PG_ASSERT(download.blocks_per_piece_max ==
            download_compute_blocks_count_for_piece(
                &download, (PieceIndex){download.pieces_count - 2}));
  PG_ASSERT(8 == download_compute_blocks_count_for_piece(
                     &download,
                     (PieceIndex){download.pieces_count - 1} /* Last piece */));
}

static void test_download_compute_block_length() {
  Download download = {0};
  download.pieces_count = 1981;
  download.blocks_per_piece_max = 16;
  download.piece_length = download.blocks_per_piece_max * BLOCK_SIZE;
  download.total_size = 519174144;
  download.blocks_count = 31688;

  PG_ASSERT(BLOCK_SIZE == download_compute_block_length(&download,
                                                        (BlockForPieceIndex){0},
                                                        (PieceIndex){1}));
  PG_ASSERT(BLOCK_SIZE == download_compute_block_length(&download,
                                                        (BlockForPieceIndex){1},
                                                        (PieceIndex){1}));
  // Last block - last piece has 8 blocks.
  PG_ASSERT(14336 ==
            download_compute_block_length(
                &download,
                (BlockForPieceIndex){7} /* Last block for the last piece */,
                (PieceIndex){download.pieces_count - 1}));
}

#if 0
static void test_download_pick_next() {
  PgRng rng = pg_rand_make();

  // We have everything, remote has nothing.
  {
    PgString local_bitfield_have = PG_S("\xff");
    PgString remote_bitfield_have = PG_S("\x00");
    Pgu32Ok res = download_pick_next_block(&rng, local_bitfield_have,
                                           remote_bitfield_have, 8);
    PG_ASSERT(!res.ok);
  }
  // Remote has everything, local has nothing.
  {
    PgString local_bitfield_have = PG_S("\x00");
    PgString remote_bitfield_have = PG_S("\xff");
    Pgu32Ok res = download_pick_next_block(&rng, local_bitfield_have,
                                           remote_bitfield_have, 8);
    PG_ASSERT(res.ok);
    PG_ASSERT(res.res < 8);
  }

  // Only one choice.
  {
    PgString local_bitfield_have = PG_S("\x03");
    PgString remote_bitfield_have = PG_S("\x04");
    Pgu32Ok res = download_pick_next_block(&rng, local_bitfield_have,
                                           remote_bitfield_have, 8);
    PG_ASSERT(res.ok);
    PG_ASSERT(2 == res.res);
  }
  // Number of pieces smaller than 8.
  {
    PgString local_bitfield_have = PG_S("\x07");
    PgString remote_bitfield_have = PG_S("\x07");
    Pgu32Ok res = download_pick_next_block(&rng, local_bitfield_have,
                                           remote_bitfield_have, 3);
    PG_ASSERT(!res.ok);
  }
}
#endif

#if 0
static void test_piece_download_pick_next_block() {
  PgRng rng = pg_rand_make();

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
        .rng = &rng,
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
        .rng = &rng,
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
        .rng = &rng,
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
        .rng = &rng,
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
        .rng = &rng,
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
#endif

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
  test_download_compute_blocks_count_for_piece();
  test_download_compute_block_length();
  // test_download_pick_next();
  //  test_piece_download_pick_next_block();
}
