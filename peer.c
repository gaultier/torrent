#pragma once
#include "download.c"

#include "submodules/libuv/include/uv.h"

// TODO: Timeouts.
// TODO: Timer-triggered keep-alives.
// TODO: Requesting pieces.
// TODO: Serve piece data.
// TODO: Retry on failure (with exp backoff?).

#include "submodules/cstd/lib.c"

[[maybe_unused]]
static PgString uv_buf_to_string(uv_buf_t buf) {
  return (PgString){.data = (u8 *)buf.base, .len = buf.len};
}

static uv_buf_t string_to_uv_buf(PgString s) {
  return (uv_buf_t){.base = (char *)s.data, .len = s.len};
}

#define HANDSHAKE_LENGTH 68

typedef enum {
  PEER_STATE_NONE,
  PEER_STATE_HANDSHAKED,
  // More.
} PeerState;

typedef struct {
  u32 index, begin, length;
} PeerMessageRequest;

typedef struct {
  u32 index, begin;
  PgString data;
} PeerMessagePiece;

typedef struct {
  u32 index, begin, length;
} PeerMessageCancel;

typedef enum : u8 {
  PEER_MSG_KIND_CHOKE = 0,
  PEER_MSG_KIND_UNCHOKE = 1,
  PEER_MSG_KIND_INTERESTED = 2,
  PEER_MSG_KIND_UNINTERESTED = 3,
  PEER_MSG_KIND_HAVE = 4,
  PEER_MSG_KIND_BITFIELD = 5,
  PEER_MSG_KIND_REQUEST = 6,
  PEER_MSG_KIND_PIECE = 7,
  PEER_MSG_KIND_CANCEL = 8,
  PEER_MSG_KIND_KEEP_ALIVE = 9,
} PeerMessageKind;

typedef struct {
  PeerMessageKind kind;
  union {
    PeerMessagePiece piece;
    PeerMessageCancel cancel;
    PeerMessageRequest request;
    PgString bitfield;
    u32 have;
  };
} PeerMessage;

typedef struct {
  bool present;
  PgError err;
} PeerMessageReadResult;

typedef struct {
  u32 piece;
  PgString data; // Piece data.
  PgString blocks_bitfield_have;
  PgString blocks_bitfield_downloading;
} PieceDownload;
PG_DYN(PieceDownload) PieceDownloadDyn;

typedef struct {
  PgIpv4Address address;
  PgString info_hash;
  PgLogger *logger;
  PgAllocator allocator;
  /* PgArena arena; */
  /* PgArena arena_tmp; */
  bool remote_choked, remote_interested;
  bool local_choked, local_interested;
  PgString remote_bitfield;
  bool remote_bitfield_received;
  Download *download;
  PeerState state;

  PieceDownloadDyn downloading_pieces;
  u64 concurrent_pieces_download_max;
  u64 concurrent_blocks_download_max;
  PgString piece_hashes;

  uv_tcp_t uv_tcp;
  uv_connect_t uv_req_connect;

  PgRing recv;
  PgFile file; // TODO: Support multiple files.
} Peer;

PG_DYN(Peer) PeerDyn;
PG_SLICE(Peer) PeerSlice;

#if 0
[[nodiscard]] static PgError peer_request_block_maybe(Peer *peer,
                                                      PieceDownload *pd);
#endif

#if 0
[[nodiscard]] [[maybe_unused]] static PieceDownload
piece_download_make(u32 piece, u64 piece_length, u32 max_blocks_per_piece_count,
                    PgArena *arena) {
  PieceDownload res = {0};
  res.piece = piece;
  res.data = pg_string_make(piece_length, arena);
  res.blocks_bitfield_have =
      pg_string_make(pg_div_ceil(max_blocks_per_piece_count, 8), arena);
  res.blocks_bitfield_downloading =
      pg_string_make(pg_div_ceil(max_blocks_per_piece_count, 8), arena);

  return res;
}
#endif

[[maybe_unused]] [[nodiscard]] static PieceDownload *
peer_find_piece_download(Peer *peer, u32 piece) {
  for (u64 i = 0; i < peer->downloading_pieces.len; i++) {
    PieceDownload *pd = PG_SLICE_AT_PTR(&peer->downloading_pieces, i);
    if (piece == pd->piece) {
      return pd;
    }
  }
  return nullptr;
}

[[maybe_unused]] [[nodiscard]] static PgString
peer_message_kind_to_string(PeerMessageKind kind) {
  switch (kind) {
  case PEER_MSG_KIND_CHOKE:
    return PG_S("PEER_MSG_KIND_CHOKE");
  case PEER_MSG_KIND_UNCHOKE:
    return PG_S("PEER_MSG_KIND_UNCHOKE");
  case PEER_MSG_KIND_INTERESTED:
    return PG_S("PEER_MSG_KIND_INTERESTED");
  case PEER_MSG_KIND_UNINTERESTED:
    return PG_S("PEER_MSG_KIND_UNINTERESTED");
  case PEER_MSG_KIND_HAVE:
    return PG_S("PEER_MSG_KIND_HAVE");
  case PEER_MSG_KIND_BITFIELD:
    return PG_S("PEER_MSG_KIND_BITFIELD");
  case PEER_MSG_KIND_REQUEST:
    return PG_S("PEER_MSG_KIND_REQUEST");
  case PEER_MSG_KIND_PIECE:
    return PG_S("PEER_MSG_KIND_PIECE");
  case PEER_MSG_KIND_CANCEL:
    return PG_S("PEER_MSG_KIND_CANCEL");
  case PEER_MSG_KIND_KEEP_ALIVE:
    return PG_S("PEER_MSG_KIND_KEEP_ALIVE");
  default:
    PG_ASSERT(0);
  }
}

[[maybe_unused]] [[nodiscard]] static Peer
peer_make(PgIpv4Address address, PgString info_hash, PgLogger *logger,
          Download *download, u64 concurrent_pieces_download_max,
          u64 concurrent_blocks_download_max, PgString piece_hashes,
          PgFile file) {
  PG_ASSERT(PG_SHA1_DIGEST_LENGTH == info_hash.len);
  PG_ASSERT(piece_hashes.len == PG_SHA1_DIGEST_LENGTH * download->pieces_count);

  Peer peer = {0};
  peer.address = address;
  peer.info_hash = info_hash;
  peer.logger = logger;
  peer.download = download;
  peer.concurrent_pieces_download_max = concurrent_pieces_download_max;
  peer.concurrent_blocks_download_max = concurrent_blocks_download_max;
  peer.piece_hashes = piece_hashes;
  peer.file = file;

  peer.allocator = pg_make_tracing_heap_allocator();
  /* peer.arena = */
  /*     pg_arena_make_from_virtual_mem(4 * PG_KiB + 2 * BLOCK_SIZE + */
  /*                                    (peer.concurrent_pieces_download_max) *
   */
  /*                                        (download->piece_length + 4 *
   * PG_KiB)); */
  /* peer.arena_tmp = pg_arena_make_from_virtual_mem(4 * PG_KiB + BLOCK_SIZE);
   */
  peer.remote_choked = true;
  peer.remote_interested = false;
  /* peer.remote_bitfield = */
  /*     pg_string_make(pg_div_ceil(download->pieces_count, 8), &peer.arena); */

  peer.local_choked = true;
  peer.local_interested = false;

  /* PG_DYN_ENSURE_CAP(&peer.downloading_pieces, concurrent_pieces_download_max,
   */
  /*                   &peer.arena); */

  return peer;
}

static void peer_on_close(uv_handle_t *handle) {
  (void)handle;
  PG_ASSERT(handle->data);
  Peer *peer = handle->data;

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: closed io handles",
         PG_L("address", peer->address));

  // TODO: Kick-start a retry here?

  PgAllocator allocator_tracing = pg_make_tracing_heap_allocator();
  pg_free(&allocator_tracing, peer, sizeof(*peer));
}

static void peer_release(Peer *peer) {
  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: start closing io handles",
         PG_L("address", peer->address));

  uv_close((uv_handle_t *)&peer->uv_tcp, peer_on_close);
}

#if 0
[[nodiscard]] static PgError peer_read_handshake(Peer *peer) {
  PgArena arena_tmp = peer->arena_tmp;
  PgString handshake = {
      .data = pg_arena_new(&arena_tmp, u8, HANDSHAKE_LENGTH),
      .len = HANDSHAKE_LENGTH,
  };

  if (!pg_ring_read_slice(&peer->recv, handshake)) {
    return 0;
  }

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: received handshake",
         PG_L("address", peer->address), PG_L("handshake", handshake));

  PgString prefix = PG_SLICE_RANGE(handshake, 0, PG_SHA1_DIGEST_LENGTH);
  PgString prefix_expected = PG_S("\x13"
                                  "BitTorrent protocol");
  if (!pg_string_eq(prefix, prefix_expected)) {
    return PG_ERR_INVALID_VALUE;
  }

  PgString reserved_bytes =
      PG_SLICE_RANGE(handshake, PG_SHA1_DIGEST_LENGTH, 28);
  (void)reserved_bytes; // Ignore.

  PgString info_hash_received =
      PG_SLICE_RANGE(handshake, 28, 28 + PG_SHA1_DIGEST_LENGTH);
  if (!pg_string_eq(info_hash_received, peer->info_hash)) {
    return PG_ERR_INVALID_VALUE;
  }

  PgString remote_peer_id =
      PG_SLICE_RANGE_START(handshake, 28 + PG_SHA1_DIGEST_LENGTH);
  PG_ASSERT(20 == remote_peer_id.len);
  // Ignore remote_peer_id for now.

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: received valid handshake",
         PG_L("address", peer->address));

  peer->state = PEER_STATE_HANDSHAKED;

  return 0;
}

[[nodiscard]] static bool piece_download_verify_piece(PieceDownload *pd,
                                                      PgString pieces_hash) {
  PG_ASSERT(pieces_hash.len >= PG_SHA1_DIGEST_LENGTH * (pd->piece + 1));

  PgString hash_expected =
      PG_SLICE_RANGE(pieces_hash, PG_SHA1_DIGEST_LENGTH * pd->piece,
                     PG_SHA1_DIGEST_LENGTH * (pd->piece + 1));
  return download_verify_piece_hash(pd->data, hash_expected);
}

[[nodiscard]] static PgError peer_save_piece_to_disk(PgFile file, u32 piece,
                                                     u64 piece_length,
                                                     PgString data) {
  u64 file_offset = piece * piece_length;
  return pg_file_write_data_at_offset_from_start(file, file_offset, data);
}

static void piece_download_reuse_for_piece(PieceDownload *pd, u32 piece) {
  pd->piece = piece;
  memset(pd->blocks_bitfield_downloading.data, 0,
         pd->blocks_bitfield_downloading.len);
  memset(pd->blocks_bitfield_have.data, 0, pd->blocks_bitfield_have.len);
}

[[nodiscard]] static PgError
peer_request_blocks_for_piece_download(Peer *peer, PieceDownload *pd) {
  u64 blocks_downloading_count =
      pg_bitfield_count(pd->blocks_bitfield_downloading);
  PG_ASSERT(blocks_downloading_count <= peer->concurrent_blocks_download_max);

  if (pg_bitfield_count(pd->blocks_bitfield_downloading) ==
      peer->concurrent_blocks_download_max) {
    return 0;
  }

  u64 blocks_to_queue_count =
      peer->concurrent_blocks_download_max - blocks_downloading_count;
  PG_ASSERT(blocks_to_queue_count <= peer->concurrent_blocks_download_max);

  for (u64 j = 0; j < blocks_to_queue_count; j++) {
    pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: queuing block download",
           PG_L("address", peer->address), PG_L("piece", pd->piece),
           PG_L("piece_download_concurrent_blocks_download_count",
                blocks_downloading_count));
    PgError err = peer_request_block_maybe(peer, pd);
    if (err) {
      return err;
    }
  }
  PG_ASSERT(pg_bitfield_count(pd->blocks_bitfield_downloading) <=
            peer->concurrent_blocks_download_max);

  return 0;
}

[[nodiscard]] static PgError peer_complete_piece_download(Peer *peer,
                                                          PieceDownload *pd) {
  bool verified = piece_download_verify_piece(pd, peer->piece_hashes);
  if (!verified) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR,
           "peer: completed piece download but hash verification failed",
           PG_L("address", peer->address), PG_L("piece", pd->piece));
    return PG_ERR_INVALID_VALUE;
  }

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG,
         "peer: completed piece download and hash verification succeeded",
         PG_L("address", peer->address), PG_L("piece", pd->piece));

  // TODO: Async disk I/O.
  PgError err_file = peer_save_piece_to_disk(
      peer->file, pd->piece, peer->download->piece_length, pd->data);
  if (err_file) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR,
           "peer: failed to save piece data to disk",
           PG_L("address", peer->address), PG_L("piece", pd->piece),
           PG_L("err", err_file),
           PG_L("err_s", pg_cstr_to_string(strerror((i32)err_file))));
    return err_file;
  }

  pg_bitfield_set(peer->download->pieces_have, pd->piece, true);

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: saved piece data to disk",
         PG_L("address", peer->address), PG_L("piece", pd->piece));

  Pgu32Ok piece_new = download_pick_next_piece(
      peer->download->rng, peer->download->pieces_have, peer->remote_bitfield,
      peer->download->pieces_count);
  if (!piece_new.ok) {
    pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: no new piece to pick",
           PG_L("address", peer->address),
           PG_L("pieces_have", peer->download->pieces_have));
  } else {
    piece_download_reuse_for_piece(pd, piece_new.res);
    return peer_request_blocks_for_piece_download(peer, pd);
  }

  return 0;
}

[[nodiscard]] static PgError peer_receive_block(Peer *peer, u32 piece,
                                                u32 begin, u32 data_len) {
  PieceDownload *pd = peer_find_piece_download(peer, piece);
  if (nullptr == pd) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR,
           "peer: piece message for piece not being downloaded",
           PG_L("address", peer->address), PG_L("piece", piece));
    return PG_ERR_INVALID_VALUE;
  }

  // Sanity checks.
  u64 blocks_downloading_before =
      pg_bitfield_count(pd->blocks_bitfield_downloading);
  PG_ASSERT(blocks_downloading_before <= peer->concurrent_blocks_download_max);
  u32 blocks_count = download_compute_blocks_count_for_piece(
      pd->piece, peer->download->piece_length, peer->download->total_file_size);
  u64 blocks_have_before = pg_bitfield_count(pd->blocks_bitfield_have);
  PG_ASSERT(blocks_downloading_before + blocks_have_before <= blocks_count);

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: received piece message",
         PG_L("address", peer->address), PG_L("piece", piece),
         PG_L("begin", begin), PG_L("data_len", data_len),
         PG_L("blocks_bitfield_have", pd->blocks_bitfield_have),
         PG_L("blocks_bitfield_downloading", pd->blocks_bitfield_downloading));

  // Bounds check.
  u64 end = 0;
  if (ckd_add(&end, begin, data_len) || end > peer->download->piece_length) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR,
           "peer: begin/data.len invalid in piece message",
           PG_L("address", peer->address), PG_L("piece", piece),
           PG_L("begin", begin), PG_L("data.len", data_len),
           PG_L("piece_length", peer->download->piece_length));
    return PG_ERR_INVALID_VALUE;
  }
  PG_ASSERT(pd->data.len == peer->download->piece_length);

  u32 block = begin / BLOCK_SIZE;
  u64 blocks_count_for_piece = download_compute_blocks_count_for_piece(
      piece, peer->download->piece_length, peer->download->total_file_size);

  // TODO: This be a validation error instead of an assert.
  PG_ASSERT(block < blocks_count_for_piece);

  // From the spec:
  //
  // > It's possible for an unexpected piece to arrive if choke and unchoke
  // messages are sent in quick succession and/or transfer is going very slowly.
  //
  // In this case, ignore.
  // TODO: Keep it if we do not have it.
  bool expected_block = true;
  if (!pg_bitfield_get(pd->blocks_bitfield_downloading, block)) {
    pg_log(
        peer->logger, PG_LOG_LEVEL_DEBUG, "peer: received unexpected block",
        PG_L("address", peer->address), PG_L("piece", piece),
        PG_L("begin", begin), PG_L("data.len", data_len), PG_L("block", block),
        PG_L("blocks_count_for_piece", blocks_count_for_piece),
        PG_L("blocks_have_before", blocks_have_before),
        PG_L("blocks_downloading_before", blocks_downloading_before),
        PG_L("blocks_bitfield_have", pd->blocks_bitfield_have),
        PG_L("blocks_bitfield_downloading", pd->blocks_bitfield_downloading));
    if (pg_bitfield_get(pd->blocks_bitfield_have, block)) {
      PgArena arena_tmp = peer->arena_tmp;
      PgString block_dst = pg_string_make(data_len, &arena_tmp);
      PG_ASSERT(pg_ring_read_slice(&peer->recv, block_dst));
      return 0;
    }
    expected_block = false;
  }

  pg_bitfield_set(pd->blocks_bitfield_have, block, true);
  pg_bitfield_set(pd->blocks_bitfield_downloading, block, false);

  // Sanity checks.
  u64 blocks_downloading_after =
      pg_bitfield_count(pd->blocks_bitfield_downloading);
  PG_ASSERT(blocks_downloading_after <= peer->concurrent_blocks_download_max);
  u64 blocks_have_after = pg_bitfield_count(pd->blocks_bitfield_have);
  PG_ASSERT(blocks_downloading_after + blocks_have_after <= blocks_count);

  PG_ASSERT(blocks_downloading_after ==
            blocks_downloading_before - expected_block);
  PG_ASSERT(blocks_have_after == blocks_have_before + 1);
  PG_ASSERT(blocks_have_after <= blocks_count_for_piece);

  // Actual data copy here, the rest is just metadata bookkeeping.
  PgString block_dst = PG_SLICE_RANGE(pd->data, begin, begin + data_len);
  PG_ASSERT(pg_ring_read_slice(&peer->recv, block_dst));

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: received block",
         PG_L("address", peer->address), PG_L("piece", piece),
         PG_L("begin", begin), PG_L("data.len", data_len), PG_L("block", block),
         PG_L("blocks_count_for_piece", blocks_count_for_piece),
         PG_L("blocks_have_before", blocks_have_before),
         PG_L("blocks_downloading_before", blocks_downloading_before),
         PG_L("blocks_have_after", blocks_have_after),
         PG_L("blocks_downloading_after", blocks_downloading_after),
         PG_L("blocks_bitfield_have", pd->blocks_bitfield_have),
         PG_L("blocks_bitfield_downloading", pd->blocks_bitfield_downloading));

  if (blocks_have_after < blocks_count_for_piece) {
    return peer_request_block_maybe(peer, pd);
  } else {
    PG_ASSERT(blocks_have_after == blocks_count_for_piece);
    return peer_complete_piece_download(peer, pd);
  }
}
#endif

[[maybe_unused]] [[nodiscard]] static Pgu32Ok
piece_download_pick_next_block(PieceDownload *pd, Download *download,
                               u64 concurrent_blocks_download_max) {
  Pgu32Ok res = {0};

  PG_ASSERT(pd->piece <= download->pieces_count);
  u64 blocks_downloading = pg_bitfield_count(pd->blocks_bitfield_downloading);
  PG_ASSERT(blocks_downloading <= concurrent_blocks_download_max);

  if (blocks_downloading >= concurrent_blocks_download_max) {
    return res;
  }

  u32 blocks_count = download_compute_blocks_count_for_piece(
      pd->piece, download->piece_length, download->total_file_size);
  u64 blocks_have = pg_bitfield_count(pd->blocks_bitfield_have);
  PG_ASSERT(blocks_downloading + blocks_have <= blocks_count);

  u32 start = pg_rand_u32_min_incl_max_excl(download->rng, 0, blocks_count);

  for (u64 i = 0; i < blocks_count; i++) {
    u32 idx = (start + i) % blocks_count;
    if (!pg_bitfield_get(pd->blocks_bitfield_have, idx) &&
        !pg_bitfield_get(pd->blocks_bitfield_downloading, idx)) {
      PG_ASSERT(idx < blocks_count);
      PG_ASSERT(pg_bitfield_count(pd->blocks_bitfield_downloading) <
                concurrent_blocks_download_max);

      pg_bitfield_set(pd->blocks_bitfield_downloading, idx, true);

      PG_ASSERT(pg_bitfield_count(pd->blocks_bitfield_downloading) <=
                concurrent_blocks_download_max);

      res.res = idx;
      res.ok = true;
      return res;
    }
  }
  return res;
}

#if 0
[[maybe_unused]] [[nodiscard]] static PgString
peer_encode_message(PeerMessage msg, PgArena *arena) {

  Pgu8Dyn sb = {0};
  u64 cap = 16;
  if (msg.kind == PEER_MSG_KIND_BITFIELD) {
    cap += msg.bitfield.len;
  } else if (msg.kind == PEER_MSG_KIND_PIECE) {
    cap += BLOCK_SIZE;
  }
  PG_DYN_ENSURE_CAP(&sb, cap, arena);

  switch (msg.kind) {
  case PEER_MSG_KIND_KEEP_ALIVE:
    pg_string_builder_append_u32(&sb, 0, arena);
    break;

  case PEER_MSG_KIND_CHOKE:
  case PEER_MSG_KIND_UNCHOKE:
  case PEER_MSG_KIND_INTERESTED:
  case PEER_MSG_KIND_UNINTERESTED:
    pg_string_builder_append_u32(&sb, 1, arena);
    *PG_DYN_PUSH(&sb, arena) = msg.kind;
    break;

  case PEER_MSG_KIND_HAVE:
    pg_string_builder_append_u32(&sb, 1 + sizeof(u32), arena);
    *PG_DYN_PUSH(&sb, arena) = msg.kind;
    pg_string_builder_append_u32(&sb, msg.have, arena);
    break;

  case PEER_MSG_KIND_BITFIELD:
    pg_string_builder_append_u32(&sb, 1 + (u32)msg.bitfield.len, arena);
    *PG_DYN_PUSH(&sb, arena) = msg.kind;
    PG_DYN_APPEND_SLICE(&sb, msg.bitfield, arena);
    break;

  case PEER_MSG_KIND_REQUEST:
    pg_string_builder_append_u32(&sb, 1 + 3 * sizeof(u32), arena);
    *PG_DYN_PUSH(&sb, arena) = msg.kind;
    pg_string_builder_append_u32(&sb, msg.request.index, arena);
    pg_string_builder_append_u32(&sb, msg.request.begin, arena);
    pg_string_builder_append_u32(&sb, msg.request.length, arena);
    break;

  case PEER_MSG_KIND_PIECE:
    pg_string_builder_append_u32(
        &sb, 1 + 2 * sizeof(u32) + (u32)msg.piece.data.len, arena);
    *PG_DYN_PUSH(&sb, arena) = msg.kind;
    pg_string_builder_append_u32(&sb, msg.piece.index, arena);
    pg_string_builder_append_u32(&sb, msg.piece.begin, arena);
    PG_DYN_APPEND_SLICE(&sb, msg.piece.data, arena);
    break;

  case PEER_MSG_KIND_CANCEL:
    pg_string_builder_append_u32(&sb, 1 + 3 * sizeof(u32), arena);
    *PG_DYN_PUSH(&sb, arena) = msg.kind;
    pg_string_builder_append_u32(&sb, msg.cancel.index, arena);
    pg_string_builder_append_u32(&sb, msg.cancel.begin, arena);
    pg_string_builder_append_u32(&sb, msg.cancel.length, arena);
    break;
  default:
    PG_ASSERT(0);
  }

  PG_ASSERT(sb.len >= sizeof(u32));

  PgString s = PG_DYN_SLICE(PgString, sb);
  return s;
}
#endif

static void peer_on_tcp_write(uv_write_t *req, int status) {
  PG_ASSERT(req->handle);
  PG_ASSERT(req->handle->data);
  Peer *peer = req->handle->data;

  if (status < 0) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to tcp write",
           PG_L("address", peer->address),
           PG_L("err", pg_cstr_to_string((char *)uv_strerror(status))));
    peer_release(peer);
    return;
  }

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: tcp write ok",
         PG_L("address", peer->address));

  pg_free(&peer->allocator, req, sizeof(*req));
#if 0
  int err_read = uv_read_start((uv_stream_t *)&peer->uv_tcp, peer_uv_alloc,
                               peer_on_tcp_read);
  if (err_read < 0) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to start tcp read",
           PG_L("port", peer->port),
           PG_L("err", pg_cstr_to_string((char *)uv_strerror(status))));
    peer_release(peer);
    return;
  }
#endif
}

#if 0
[[nodiscard]] static PgError peer_request_block_maybe(Peer *peer,
                                                      PieceDownload *pd) {
  PG_ASSERT(pg_bitfield_count(pd->blocks_bitfield_downloading) <=
            peer->concurrent_blocks_download_max);

  PgArena arena_tmp = peer->arena_tmp;
  u64 blocks_downloading_before =
      pg_bitfield_count(pd->blocks_bitfield_downloading);
  Pgu32Ok block = piece_download_pick_next_block(
      pd, peer->download, peer->concurrent_blocks_download_max);
  PG_ASSERT(blocks_downloading_before <= peer->concurrent_blocks_download_max);

  if (!block.ok) {
    pg_log(
        peer->logger, PG_LOG_LEVEL_DEBUG, "peer: no block left to pick",
        PG_L("address", peer->address), PG_L("piece", pd->piece),
        PG_L("blocks_bitfield_have", pd->blocks_bitfield_have),
        PG_L("blocks_bitfield_downloading", pd->blocks_bitfield_downloading));
    return 0;
  }
  PG_ASSERT(true ==
            pg_bitfield_get(pd->blocks_bitfield_downloading, block.res));
  PG_ASSERT(blocks_downloading_before + 1 ==
            pg_bitfield_count(pd->blocks_bitfield_downloading));

  u32 block_length =
      download_compute_block_length(block.res, peer->download->piece_length);
  PeerMessage msg = {
      .kind = PEER_MSG_KIND_REQUEST,
      .request =
          {
              .index = pd->piece,
              .begin = block.res * BLOCK_SIZE,
              .length = block_length,
          },
  };
  PG_ASSERT(msg.request.index + msg.request.length <=
            peer->download->piece_length);

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "requesting block",
         PG_L("address", peer->address), PG_L("block", block.res),
         PG_L("piece", pd->piece), PG_L("begin", msg.request.begin),
         PG_L("block_length", block_length),
         PG_L("blocks_bitfield_have", pd->blocks_bitfield_have),
         PG_L("blocks_bitfield_downloading", pd->blocks_bitfield_downloading));

  PgString msg_encoded = peer_encode_message(msg, &arena_tmp);
  PgError err = pg_event_loop_write(peer->loop, peer->os_handle_socket,
                                    msg_encoded, peer_on_write);
  if (err) {
    return err;
  }

  return 0;
}

[[nodiscard]] static PgError peer_request_remote_data_maybe(Peer *peer) {
  PG_ASSERT(0 != peer->concurrent_pieces_download_max);
  PG_ASSERT(0 != peer->concurrent_blocks_download_max);

  PG_ASSERT(peer->downloading_pieces.len <=
            peer->concurrent_pieces_download_max);

  // TODO: Should we send 'interested' first?

  if (peer->remote_choked) {
    pg_log(peer->logger, PG_LOG_LEVEL_DEBUG,
           "peer: not requesting remote data since remote is choked",
           PG_L("address", peer->address));

    return 0;
  }

  if (peer->downloading_pieces.len < peer->concurrent_pieces_download_max) {
    u64 pieces_to_queue_count =
        peer->concurrent_pieces_download_max - peer->downloading_pieces.len;
    PG_ASSERT(pieces_to_queue_count > 0);
    PG_ASSERT(pieces_to_queue_count <= peer->concurrent_pieces_download_max);

    for (u64 i = 0; i < pieces_to_queue_count; i++) {
      Pgu32Ok piece = download_pick_next_piece(
          peer->download->rng, peer->download->pieces_have,
          peer->remote_bitfield, peer->download->pieces_count);
      if (!piece.ok) {
        pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: no piece left to pick",
               PG_L("address", peer->address));

        break;
      }

      PG_ASSERT(peer->downloading_pieces.len <
                peer->concurrent_pieces_download_max);
      *PG_DYN_PUSH(&peer->downloading_pieces, &peer->arena) =
          piece_download_make(piece.res, peer->download->piece_length,
                              peer->download->max_blocks_per_piece_count,
                              &peer->arena);
      pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: queuing piece download",
             PG_L("address", peer->address), PG_L("piece", piece.res),
             PG_L("downloading_pieces_count", peer->downloading_pieces.len));

      PG_ASSERT(peer->downloading_pieces.len <=
                peer->concurrent_pieces_download_max);
    }
  }

  for (u64 i = 0; i < peer->downloading_pieces.len; i++) {
    PieceDownload *pd = PG_SLICE_AT_PTR(&peer->downloading_pieces, i);
    PgError err = peer_request_blocks_for_piece_download(peer, pd);
    if (err) {
      return err;
    }
  }
  PG_ASSERT(peer->downloading_pieces.len <=
            peer->concurrent_pieces_download_max);

  return 0;
}

[[nodiscard]] static PeerMessageReadResult peer_read_any_message(Peer *peer) {
  PeerMessageReadResult res = {0};

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: reading any message",
         PG_L("address", peer->address),
         PG_L("recv_read_space", pg_ring_read_space(peer->recv)),
         PG_L("recv_write_space", pg_ring_write_space(peer->recv)));

  u32 length_announced = 0;
  {
    PgRing recv_tmp = peer->recv;
    if (!pg_ring_read_u32(&recv_tmp, &length_announced)) {
      return res;
    }
    length_announced = ntohl(length_announced);

    u32 length_announced_max = 16 + BLOCK_SIZE;
    if (length_announced > length_announced_max) {
      pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: length announced too big",
             PG_L("address", peer->address),
             PG_L("length_announced", length_announced),
             PG_L("length_announced_max", length_announced_max));
      res.err = PG_ERR_INVALID_VALUE;
      return res;
    }

    if (pg_ring_read_space(recv_tmp) < length_announced) {
      pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: need to read more data",
             PG_L("address", peer->address),
             PG_L("length_announced", length_announced),
             PG_L("ring_read_space", pg_ring_read_space(recv_tmp)));
      return res;
    }
    peer->recv = recv_tmp;
  }

  u8 kind = PEER_MSG_KIND_KEEP_ALIVE;

  if (0 == length_announced) {
    goto end;
  }

  PG_ASSERT(pg_ring_read_u8(&peer->recv, &kind));

  switch (kind) {
  case PEER_MSG_KIND_CHOKE: {
    peer->remote_choked = true;
    // TODO: Cancel on-going downloads?
    break;
  }
  case PEER_MSG_KIND_UNCHOKE: {
    peer->remote_choked = false;
    res.err = peer_request_remote_data_maybe(peer);
    break;
  }
  case PEER_MSG_KIND_INTERESTED: {
    peer->remote_interested = true;
    break;
  }
  case PEER_MSG_KIND_UNINTERESTED: {
    peer->remote_interested = false;
    break;
  }
  case PEER_MSG_KIND_HAVE: {
    if ((1 + sizeof(u32)) != length_announced) {
      res.err = PG_ERR_INVALID_VALUE;
      return res;
    }
    u32 have = 0;
    PG_ASSERT(pg_ring_read_u32(&peer->recv, &have));

    if (have > peer->download->pieces_count) {
      res.err = PG_ERR_INVALID_VALUE;
      return res;
    }
    break;
  }
  case PEER_MSG_KIND_BITFIELD: {
    if (peer->remote_bitfield_received) {
      pg_log(peer->logger, PG_LOG_LEVEL_ERROR,
             "received bitfield message more than once",
             PG_L("address", peer->address));
      res.err = PG_ERR_INVALID_VALUE;
      return res;
    }

    u64 bitfield_len = length_announced - 1;
    if (0 == bitfield_len || peer->download->pieces_have.len != bitfield_len) {
      pg_log(peer->logger, PG_LOG_LEVEL_ERROR,
             "invalid bitfield length received", PG_L("address", peer->address),
             PG_L("len_actual", bitfield_len),
             PG_L("len_expected", peer->download->pieces_have.len));
      res.err = PG_ERR_INVALID_VALUE;
      return res;
    }

    PG_ASSERT(nullptr != peer->remote_bitfield.data);
    PG_ASSERT(pg_ring_read_slice(&peer->recv, peer->remote_bitfield));
    for (u64 i = 0; i < peer->remote_bitfield.len; i++) {
      u8 *ptr = PG_SLICE_AT_PTR(&peer->remote_bitfield, i);
      *ptr = __builtin_bitreverse8(*ptr);
    }
    peer->remote_bitfield_received = true;

    // Check that padding bits in the remote bitfield are 0.
    for (u64 i = 0;
         i < peer->remote_bitfield.len * 8 - peer->download->pieces_count;
         i++) {
      PG_ASSERT(0 == pg_bitfield_get(peer->remote_bitfield,
                                     peer->download->pieces_count + i));
    }

    break;
  }
  case PEER_MSG_KIND_REQUEST: {
    if (1 + 3 * sizeof(u32) != length_announced) {
      res.err = PG_ERR_INVALID_VALUE;
      return res;
    }
    u32 index = 0, begin = 0, data_length = 0;
    PG_ASSERT(pg_ring_read_u32(&peer->recv, &index));
    PG_ASSERT(pg_ring_read_u32(&peer->recv, &begin));
    PG_ASSERT(pg_ring_read_u32(&peer->recv, &data_length));
    index = ntohl(index);
    begin = ntohl(begin);
    data_length = ntohl(data_length);

    break;
  }
  case PEER_MSG_KIND_PIECE: {
    if (length_announced < sizeof(kind) + 2 * sizeof(u32) ||
        length_announced > sizeof(kind) + 2 * sizeof(u32) + BLOCK_SIZE) {
      res.err = PG_ERR_INVALID_VALUE;
      return res;
    }
    u32 piece = 0, begin = 0;
    PG_ASSERT(pg_ring_read_u32(&peer->recv, &piece));
    PG_ASSERT(pg_ring_read_u32(&peer->recv, &begin));
    piece = ntohl(piece);
    begin = ntohl(begin);

    u32 data_len =
        length_announced - (sizeof(kind) + sizeof(piece) + sizeof(begin));
    PG_ASSERT(data_len <= BLOCK_SIZE);
    res.err = peer_receive_block(peer, piece, begin, data_len);

    break;
  }
  case PEER_MSG_KIND_CANCEL: {
    if (1 + 3 * sizeof(u32) != length_announced) {
      res.err = PG_ERR_INVALID_VALUE;
      return res;
    }

    u32 index = 0, begin = 0, data_length = 0;
    PG_ASSERT(pg_ring_read_u32(&peer->recv, &index));
    PG_ASSERT(pg_ring_read_u32(&peer->recv, &begin));
    PG_ASSERT(pg_ring_read_u32(&peer->recv, &data_length));
    index = ntohl(index);
    begin = ntohl(begin);
    data_length = ntohl(data_length);

    break;
  }
  default:
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: message unknown kind",
           PG_L("address", peer->address),
           PG_L("kind", peer_message_kind_to_string(kind)));
    res.err = PG_ERR_INVALID_VALUE;
    return res;
  }

end:
  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: received message",
         PG_L("address", peer->address),
         PG_L("length_announced", length_announced), PG_L("err", res.err),
         PG_L("err_s", pg_cstr_to_string(strerror((i32)res.err))),
         PG_L("kind", peer_message_kind_to_string(kind)),
         PG_L("recv_read_space", pg_ring_read_space(peer->recv)),
         PG_L("recv_write_space", pg_ring_write_space(peer->recv)));

  res.present = true;
  return res;
}

[[nodiscard]] static PgError peer_handle_recv_data(Peer *peer) {
  for (u64 _i = 0; _i < 128; _i++) {
    switch (peer->state) {
    case PEER_STATE_NONE: {
      PgError err = peer_read_handshake(peer);
      if (err) {
        return err;
      }
    } break;
    case PEER_STATE_HANDSHAKED: {
      PeerMessageReadResult res = peer_read_any_message(peer);
      if (res.err) {
        return res.err;
      }
      if (!res.present) {
        return 0;
      }
      break;
    }
    default:
      PG_ASSERT(0);
    }
  }
  return 0;
}

static void peer_on_tcp_read(PgEventLoop *loop, PgOsHandle os_handle, void *ctx,
                             PgError err, PgString data) {
  PG_ASSERT(nullptr != ctx);
  (void)loop;
  (void)os_handle;

  Peer *peer = ctx;

  if (err) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to tcp read",
           PG_L("address", peer->address), PG_L("err", err),
           PG_L("err_s", pg_cstr_to_string(strerror((i32)err))));
    peer_release(peer);
    return;
  }

  // TODO: What to do here, maybe `read_stop` and set a timer to `read_start` at
  // a later time?
  if (0 == data.len) {
    pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: nothing to read",
           PG_L("address", peer->address));
    return;
  }

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: read tcp",
         PG_L("address", peer->address), PG_L("data", data),
         PG_L("data.len", data.len),
         PG_L("recv_read_space", pg_ring_read_space(peer->recv)),
         PG_L("recv_write_space", pg_ring_write_space(peer->recv)));

  PgError err_handle = peer_handle_recv_data(peer);
  if (err_handle) {
    peer_release(peer);
    return;
  }

  if (!pg_ring_write_slice(&peer->recv, data)) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: read too much data",
           PG_L("address", peer->address),
           PG_L("recv_write_space", pg_ring_write_space(peer->recv)),
           PG_L("data.len", data.len));
    peer_release(peer);
    return;
  }

  err_handle = peer_handle_recv_data(peer);
  if (err_handle) {
    peer_release(peer);
    return;
  }
}

static void peer_on_tcp_write(PgEventLoop *loop, PgOsHandle os_handle,
                              void *ctx, PgError err) {
  PG_ASSERT(nullptr != ctx);

  Peer *peer = ctx;

  if (err) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to tcp write",
           PG_L("address", peer->address), PG_L("err", err),
           PG_L("err_s", pg_cstr_to_string(strerror((i32)err))));
    peer_release(peer);
    return;
  }

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: wrote",
         PG_L("address", peer->address));

  PgError err_read =
      pg_event_loop_read_start(loop, os_handle, peer_on_tcp_read);
  if (err_read) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to tcp start read",
           PG_L("address", peer->address), PG_L("err", err_read),
           PG_L("err_s", pg_cstr_to_string(strerror((i32)err_read))));
    peer_release(peer);
    return;
  }
}
#endif

[[maybe_unused]] [[nodiscard]] static PgString
peer_make_handshake(PgString info_hash, PgAllocator *allocator) {
  Pgu8Dyn sb = {0};
  PG_DYN_ENSURE_CAP(&sb, HANDSHAKE_LENGTH, allocator);
  PG_DYN_APPEND_SLICE_WITHIN_CAPACITY(&sb, PG_S("\x13"
                                                "BitTorrent protocol"
                                                "\x00"
                                                "\x00"
                                                "\x00"
                                                "\x00"
                                                "\x00"
                                                "\x00"
                                                "\x00"
                                                "\x00"));
  PG_ASSERT(1 + 19 + 8 == sb.len);

  PG_ASSERT(PG_SHA1_DIGEST_LENGTH == info_hash.len);
  PG_DYN_APPEND_SLICE_WITHIN_CAPACITY(&sb, info_hash);

  PgString peer_id = PG_S("00000000000000000000");
  PG_ASSERT(20 == peer_id.len);
  PG_DYN_APPEND_SLICE_WITHIN_CAPACITY(&sb, peer_id);

  PG_ASSERT(HANDSHAKE_LENGTH == sb.len);
  return PG_DYN_SLICE(PgString, sb);
}

static void peer_on_tcp_connect(uv_connect_t *req, int status) {
  PG_ASSERT(req->data);
  Peer *peer = req->data;

  if (status < 0) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to connect",
           PG_L("err", status),
           PG_L("err_s", pg_cstr_to_string((char *)uv_strerror(status))),
           PG_L("address", peer->address));
    peer_release(peer);
    return;
  }

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: connected",
         PG_L("address", peer->address));

  PgString handshake = peer_make_handshake(peer->info_hash, &peer->allocator);
  uv_buf_t buf = string_to_uv_buf(handshake);

  uv_write_t *req_write =
      pg_alloc(&peer->allocator, sizeof(uv_write_t), _Alignof(uv_write_t), 1);
  // TODO: Should we remember what data/length was written?
  req->data = peer;

  int err_write = uv_write(req_write, (uv_stream_t *)&peer->uv_tcp, &buf, 1,
                           peer_on_tcp_write);
  if (err_write < 0) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to tcp write",
           PG_L("address", peer->address),
           PG_L("err", pg_cstr_to_string((char *)uv_strerror(err_write))));
    peer_release(peer);
    return;
  }
}

[[maybe_unused]] [[nodiscard]] static PgError peer_start(Peer *peer) {
  peer->uv_tcp.data = peer;

  int err_tcp_init = uv_tcp_init(uv_default_loop(), &peer->uv_tcp);
  if (err_tcp_init < 0) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to tcp init",
           PG_L("address", peer->address),
           PG_L("err_s", pg_cstr_to_string((char *)uv_strerror(err_tcp_init))));
    peer_release(peer);
    return (PgError)err_tcp_init;
  }

  // TODO: IPV6.
  struct sockaddr_in sockaddr = {
      .sin_family = AF_INET,
      .sin_port = htons(peer->address.port),
      .sin_addr.s_addr = htonl(peer->address.ip),
  };
  peer->uv_req_connect.data = peer;
  int err_tcp_connect =
      uv_tcp_connect(&peer->uv_req_connect, &peer->uv_tcp,
                     (struct sockaddr *)&sockaddr, peer_on_tcp_connect);
  if (err_tcp_connect < 0) {
    pg_log(
        peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to start tcp connect",
        PG_L("address", peer->address), PG_L("err", err_tcp_connect),
        PG_L("err_s", pg_cstr_to_string((char *)uv_strerror(err_tcp_connect))));
    peer_release(peer);
    return (PgError)err_tcp_init;
  }

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: started tcp connect",
         PG_L("address", peer->address));

  return 0;
}

#if 0
[[maybe_unused]]
static void peer_pick_random(PgIpv4AddressDyn *addresses_all,
                             PeerDyn *peers_active, u64 count,
                             PgString info_hash, PgArena *arena) {
  u64 real_count = PG_MIN(addresses_all->len, count);

  for (u64 i = 0; i < real_count; i++) {
    u32 idx = pg_rand_u32(0, (u32)addresses_all->len - 1); // FIXME
    PgIpv4Address address = PG_SLICE_AT(*addresses_all, idx);
    Peer peer = peer_make(address, info_hash);
    *PG_DYN_PUSH(peers_active, arena) = peer;
    PG_SLICE_SWAP_REMOVE(addresses_all, idx);

    pg_log(PG_LOG_LEVEL_DEBUG, "peer_pick_random", &peer.arena,
           PG_L("ipv4", peer.address.ip), PG_L("port", peer.address.port));
  }
}
#endif
