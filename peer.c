#pragma once
#include "download.c"

// TODO: Timeouts.
// TODO: Timer-triggered keep-alives.
// TODO: Requesting & storing pieces.
// TODO: Verify piece data hash.
// TODO: Serve piece data.
// TODO: Retry on failure (with exp backoff?).

#include "submodules/cstd/lib.c"

#define HANDSHAKE_LENGTH 68
#define LENGTH_LENGTH 4

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
  PgArena arena;
  PgArena arena_tmp;
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

  PgEventLoop *loop;
  u64 os_handle_socket;
  PgRing recv;
  PgFile file; // TODO: Support multiple files.
} Peer;

PG_DYN(Peer) PeerDyn;
PG_SLICE(Peer) PeerSlice;

[[nodiscard]] [[maybe_unused]] static PgError
peer_request_block_maybe(Peer *peer, PieceDownload *pd);

[[nodiscard]] [[maybe_unused]] static PieceDownload
piece_download_make(u32 piece, u64 piece_length, u32 blocks_per_piece_count,
                    PgArena *arena) {
  PieceDownload res = {0};
  res.piece = piece;
  res.data = pg_string_make(piece_length, arena);
  res.blocks_bitfield_have =
      pg_string_make(pg_div_ceil(blocks_per_piece_count, 8), arena);
  res.blocks_bitfield_downloading =
      pg_string_make(pg_div_ceil(blocks_per_piece_count, 8), arena);

  return res;
}

[[nodiscard]] static PieceDownload *peer_find_piece_download(Peer *peer,
                                                             u32 piece) {
  for (u64 i = 0; i < peer->downloading_pieces.len; i++) {
    PieceDownload *pd = PG_SLICE_AT_PTR(&peer->downloading_pieces, i);
    if (piece == pd->piece) {
      return pd;
    }
  }
  return nullptr;
}

[[nodiscard]] [[maybe_unused]] static PgString
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

[[maybe_unused]] [[nodiscard]] static Peer peer_make(
    PgIpv4Address address, PgString info_hash, PgLogger *logger,
    Download *download, PgEventLoop *loop, u64 concurrent_pieces_download_max,
    u64 concurrent_blocks_download_max, PgString piece_hashes, PgFile file) {
  PG_ASSERT(20 == info_hash.len);
  PG_ASSERT(piece_hashes.len == 20 * download->pieces_count);

  Peer peer = {0};
  peer.address = address;
  peer.info_hash = info_hash;
  peer.logger = logger;
  peer.download = download;
  peer.loop = loop;
  peer.concurrent_pieces_download_max = concurrent_pieces_download_max;
  peer.concurrent_blocks_download_max = concurrent_blocks_download_max;
  peer.piece_hashes = piece_hashes;
  peer.file = file;

  // At most one block is held in memory at any time, plus a bit of temporary
  // data for encoding/decoding messages.
  // TODO: Check if this still holds if we use async I/O for file rw.
  peer.arena = pg_arena_make_from_virtual_mem(
      32 * PG_KiB +
      BLOCK_SIZE * concurrent_pieces_download_max *
          concurrent_blocks_download_max +
      peer.concurrent_pieces_download_max * download->piece_length);
  peer.arena_tmp = pg_arena_make_from_virtual_mem(4 * PG_KiB + BLOCK_SIZE);
  peer.remote_choked = true;
  peer.remote_interested = false;
  peer.remote_bitfield =
      pg_string_make(pg_div_ceil(download->pieces_count, 8), &peer.arena);

  peer.local_choked = true;
  peer.local_interested = false;

  PG_DYN_ENSURE_CAP(&peer.downloading_pieces, concurrent_pieces_download_max,
                    &peer.arena);

  return peer;
}

// TODO: Principled peer lifetime. Perhaps with a pool?
// Need to be careful when the peer is released, and handling double release.
[[maybe_unused]]
static void peer_release(Peer *peer) {
  (void)pg_arena_release(&peer->arena);
  (void)pg_arena_release(&peer->arena_tmp);
  (void)pg_event_loop_handle_close(peer->loop, peer->os_handle_socket);
  free(peer);
}

[[nodiscard]] static PgError peer_read_handshake(Peer *peer) {
  PgArena arena_tmp = peer->arena_tmp;
  PgString handshake = {
      .data = pg_arena_new(&arena_tmp, u8, HANDSHAKE_LENGTH),
      .len = HANDSHAKE_LENGTH,
  };

  if (!pg_ring_read_slice(&peer->recv, handshake)) {
    return 0;
  }

  pg_log(peer->logger, PG_LOG_LEVEL_INFO, "peer: received handshake",
         PG_L("address", peer->address), PG_L("handshake", handshake));

  PgString prefix = PG_SLICE_RANGE(handshake, 0, 20);
  PgString prefix_expected = PG_S("\x13"
                                  "BitTorrent protocol");
  if (!pg_string_eq(prefix, prefix_expected)) {
    return PG_ERR_INVALID_VALUE;
  }

  PgString reserved_bytes = PG_SLICE_RANGE(handshake, 20, 28);
  (void)reserved_bytes; // Ignore.

  PgString info_hash_received = PG_SLICE_RANGE(handshake, 28, 28 + 20);
  if (!pg_string_eq(info_hash_received, peer->info_hash)) {
    return PG_ERR_INVALID_VALUE;
  }

  PgString remote_peer_id = PG_SLICE_RANGE_START(handshake, 28 + 20);
  PG_ASSERT(20 == remote_peer_id.len);
  // Ignore remote_peer_id for now.

  pg_log(peer->logger, PG_LOG_LEVEL_INFO, "peer: received valid handshake",
         PG_L("address", peer->address));

  peer->state = PEER_STATE_HANDSHAKED;

  return 0;
}

[[nodiscard]] static bool piece_download_verify_piece(PieceDownload *pd,
                                                      PgString pieces_hash) {
  PG_ASSERT(pieces_hash.len >= 20 * (pd->piece + 1));

  PgString hash_expected =
      PG_SLICE_RANGE(pieces_hash, 20 * pd->piece, 20 * (pd->piece + 1));
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
           PG_L("err", err_file));
    return err_file;
  }

  pg_bitfield_set(peer->download->pieces_have, pd->piece, true);

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: saved piece data to disk",
         PG_L("address", peer->address), PG_L("piece", pd->piece));

  i64 piece_new =
      download_pick_next_piece(peer->download, peer->remote_bitfield);
  if (-1 == piece_new) {
    pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: no new piece to pick",
           PG_L("address", peer->address),
           PG_L("pieces_have", peer->download->pieces_have));
  } else {
    PG_ASSERT(piece_new <= UINT32_MAX);
    piece_download_reuse_for_piece(pd, (u32)piece_new);
    return peer_request_blocks_for_piece_download(peer, pd);
  }

  return 0;
}

[[nodiscard]] static PgError peer_receive_block(Peer *peer, u32 piece,
                                                u32 begin, PgString data) {
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
  // TODO: Should be a validation error, not an assert.
  PG_ASSERT(pg_bitfield_count(pd->blocks_bitfield_downloading) > 0);

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: received piece message",
         PG_L("address", peer->address), PG_L("piece", piece),
         PG_L("begin", begin), PG_L("data.len", data.len),
         PG_L("blocks_bitfield_have", pd->blocks_bitfield_have),
         PG_L("blocks_bitfield_downloading", pd->blocks_bitfield_downloading));

  // Bounds check.
  u64 end = 0;
  if (ckd_add(&end, begin, data.len) || end > peer->download->piece_length) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR,
           "peer: begin/data.len invalid in piece message",
           PG_L("address", peer->address), PG_L("piece", piece),
           PG_L("begin", begin), PG_L("data.len", data.len),
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
  // In this case, ignore, if we have the block already.
  // Otherwise, just keep it.
  if (!pg_bitfield_get(pd->blocks_bitfield_downloading, block) &&
      pg_bitfield_get(pd->blocks_bitfield_have, block)) {
    return 0;
  }

  pg_bitfield_set(pd->blocks_bitfield_have, block, true);
  pg_bitfield_set(pd->blocks_bitfield_downloading, block, false);

  // Sanity checks.
  u64 blocks_downloading_after =
      pg_bitfield_count(pd->blocks_bitfield_downloading);
  PG_ASSERT(blocks_downloading_after <= peer->concurrent_blocks_download_max);
  u64 blocks_have_after = pg_bitfield_count(pd->blocks_bitfield_have);
  PG_ASSERT(blocks_downloading_after + blocks_have_after <= blocks_count);

  PG_ASSERT(blocks_downloading_after == blocks_downloading_before - 1);
  PG_ASSERT(blocks_have_after == blocks_have_before + 1);
  PG_ASSERT(blocks_have_after <= blocks_count_for_piece);

  // Actual data copy here, the rest is just metadata bookkeeping.
  memcpy(pd->data.data + begin, data.data, data.len);

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: received block",
         PG_L("address", peer->address), PG_L("piece", piece),
         PG_L("begin", begin), PG_L("data.len", data.len), PG_L("block", block),
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

[[nodiscard]] [[maybe_unused]] static i64
piece_download_pick_next_block(PieceDownload *pd, Download *download,
                               u64 concurrent_blocks_download_max) {
  PG_ASSERT(pd->piece <= download->pieces_count);
  u64 blocks_downloading = pg_bitfield_count(pd->blocks_bitfield_downloading);
  PG_ASSERT(blocks_downloading <= concurrent_blocks_download_max);

  if (blocks_downloading >= concurrent_blocks_download_max) {
    return -1;
  }

  u32 blocks_count = download_compute_blocks_count_for_piece(
      pd->piece, download->piece_length, download->total_file_size);
  u64 blocks_have = pg_bitfield_count(pd->blocks_bitfield_have);
  PG_ASSERT(blocks_downloading + blocks_have <= blocks_count);

  u64 start = pg_rand_u32(0, blocks_count);

  for (u64 i = 0; i < blocks_count; i++) {
    u64 idx = (start + i) % blocks_count;
    if (!pg_bitfield_get(pd->blocks_bitfield_have, idx) &&
        !pg_bitfield_get(pd->blocks_bitfield_downloading, idx)) {
      PG_ASSERT(idx <= UINT32_MAX);
      PG_ASSERT(idx < blocks_count);
      PG_ASSERT(pg_bitfield_count(pd->blocks_bitfield_downloading) <
                concurrent_blocks_download_max);

      pg_bitfield_set(pd->blocks_bitfield_downloading, idx, true);

      PG_ASSERT(pg_bitfield_count(pd->blocks_bitfield_downloading) <=
                concurrent_blocks_download_max);

      return (i32)idx;
    }
  }
  return -1;
}

[[maybe_unused]] [[nodiscard]] static PgString
peer_encode_message(PeerMessage msg, PgArena *arena) {

  Pgu8Dyn sb = {0};
  u64 cap = 16 + (PEER_MSG_KIND_BITFIELD == msg.kind ? (msg.bitfield.len) : 0);
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

[[maybe_unused]] static void peer_on_write(PgEventLoop *loop, u64 os_handle,
                                           void *ctx, PgError err) {
  (void)loop;
  (void)os_handle;

  PG_ASSERT(nullptr != ctx);
  Peer *peer = ctx;

  if (err) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to write",
           PG_L("err", err), PG_L("address", peer->address));
    peer_release(peer);
    return;
  }

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: write successful",
         PG_L("address", peer->address));
}

[[nodiscard]] [[maybe_unused]] static PgError
peer_request_block_maybe(Peer *peer, PieceDownload *pd) {
  PG_ASSERT(pg_bitfield_count(pd->blocks_bitfield_downloading) <=
            peer->concurrent_blocks_download_max);

  PgArena arena_tmp = peer->arena_tmp;
  u64 blocks_downloading_before =
      pg_bitfield_count(pd->blocks_bitfield_downloading);
  i64 block = piece_download_pick_next_block(
      pd, peer->download, peer->concurrent_blocks_download_max);
  PG_ASSERT(blocks_downloading_before <= peer->concurrent_blocks_download_max);

  if (-1 == block) {
    pg_log(
        peer->logger, PG_LOG_LEVEL_DEBUG, "peer: no block left to pick",
        PG_L("address", peer->address), PG_L("piece", pd->piece),
        PG_L("blocks_bitfield_have", pd->blocks_bitfield_have),
        PG_L("blocks_bitfield_downloading", pd->blocks_bitfield_downloading));
    return 0;
  }
  PG_ASSERT(true ==
            pg_bitfield_get(pd->blocks_bitfield_downloading, (u64)block));
  PG_ASSERT(blocks_downloading_before + 1 ==
            pg_bitfield_count(pd->blocks_bitfield_downloading));

  u32 block_length =
      download_compute_block_length((u32)block, peer->download->piece_length);
  PeerMessage msg = {
      .kind = PEER_MSG_KIND_REQUEST,
      .request =
          {
              .index = (u32)pd->piece,
              .begin = (u32)block * BLOCK_SIZE,
              .length = block_length,
          },
  };
  PG_ASSERT(msg.request.index + msg.request.length <=
            peer->download->piece_length);

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "requesting block",
         PG_L("address", peer->address), PG_L("block", (u32)block),
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

[[nodiscard]] [[maybe_unused]] static PgError
peer_request_remote_data_maybe(Peer *peer) {
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
      i64 piece =
          download_pick_next_piece(peer->download, peer->remote_bitfield);
      if (-1 == piece) {
        pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: no piece left to pick",
               PG_L("address", peer->address));

        break;
      }

      *PG_DYN_PUSH(&peer->downloading_pieces, &peer->arena) =
          piece_download_make((u32)piece, peer->download->piece_length,
                              peer->download->blocks_per_piece_count,
                              &peer->arena);
      pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: queuing piece download",
             PG_L("address", peer->address), PG_L("piece", (u32)piece),
             PG_L("downloading_pieces_count", peer->downloading_pieces.len));
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

  PgArena arena_tmp = peer->arena_tmp;
  PgRing recv_tmp = peer->recv;

  PgString length = {
      .data = pg_arena_new(&arena_tmp, u8, LENGTH_LENGTH),
      .len = LENGTH_LENGTH,
  };
  if (!pg_ring_read_slice(&recv_tmp, length)) {
    return res;
  }
  u32 length_announced = pg_u8x4_be_to_u32(length);
  u32 length_announced_max = 16 + BLOCK_SIZE;
  if (length_announced > length_announced_max) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: length announced too big",
           PG_L("address", peer->address),
           PG_L("length_announced", length_announced),
           PG_L("length_announced_max", length_announced_max));
    res.err = PG_ERR_INVALID_VALUE;
    return res;
  }

  u8 kind = PEER_MSG_KIND_KEEP_ALIVE;

  if (0 == length_announced) {
    goto end;
  }

  PgString data = {0};
  if (pg_ring_read_space(recv_tmp) < length_announced) {
    pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: need to read more data",
           PG_L("address", peer->address),
           PG_L("length_announced", length_announced),
           PG_L("ring_read_space", pg_ring_read_space(recv_tmp)));
    return res;
  }
  data = (PgString){
      .data = pg_arena_new(&arena_tmp, u8, length_announced),
      .len = length_announced,
  };
  // TODO: Optimize by reading directly from ring lazily.
  PG_ASSERT(true == pg_ring_read_slice(&recv_tmp, data));

  kind = PG_SLICE_AT(data, 0);

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
    PgString data_msg = PG_SLICE_RANGE_START(data, 1);
    u32 have = pg_u8x4_be_to_u32(data_msg);

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

    PgString bitfield = PG_SLICE_RANGE_START(data, 1);
    PG_ASSERT(nullptr != peer->remote_bitfield.data);
    memcpy(peer->remote_bitfield.data, bitfield.data, bitfield.len);
    peer->remote_bitfield_received = true;

    break;
  }
  case PEER_MSG_KIND_REQUEST: {
    if (1 + 3 * sizeof(u32) != length_announced) {
      res.err = PG_ERR_INVALID_VALUE;
      return res;
    }
    u32 index = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 1, 5));
    u32 begin = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 5, 9));
    u32 data_length = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 9, 13));

    // TODO
    (void)index;
    (void)begin;
    (void)data_length;

    break;
  }
  case PEER_MSG_KIND_PIECE: {
    if (1 + 2 * sizeof(u32) + BLOCK_SIZE != length_announced) {
      res.err = PG_ERR_INVALID_VALUE;
      return res;
    }
    u32 piece = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 1, 5));
    u32 begin = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 5, 9));
    PgString piece_data = PG_SLICE_RANGE_START(data, 9);

    res.err = peer_receive_block(peer, piece, begin, piece_data);

    break;
  }
  case PEER_MSG_KIND_CANCEL: {
    if (1 + 3 * sizeof(u32) != length_announced) {
      res.err = PG_ERR_INVALID_VALUE;
      return res;
    }
    u32 index = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 1, 5));
    u32 begin = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 5, 9));
    u32 data_length = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 9, 13));

    // TODO
    (void)index;
    (void)begin;
    (void)data_length;

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
         PG_L("kind", peer_message_kind_to_string(kind)));

  res.present = true;
  peer->recv = recv_tmp;
  return res;
}

[[nodiscard]] [[maybe_unused]] static PgError
peer_handle_recv_data(Peer *peer) {
  for (u64 _i = 0; _i < 8; _i++) {
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

[[maybe_unused]]
static void peer_on_read(PgEventLoop *loop, u64 os_handle, void *ctx,
                         PgError err, PgString data) {
  PG_ASSERT(nullptr != ctx);
  (void)loop;
  (void)os_handle;

  Peer *peer = ctx;

  if (err) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to tcp read",
           PG_L("address", peer->address), PG_L("err", err));
    peer_release(peer);
    return;
  }

  // TODO: What to do here, maybe `read_stop` and set a timer to `read_start` at
  // a later time?
  if (0 == data.len) {
    pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: nothing to read, closing",
           PG_L("address", peer->address));
    peer_release(peer);
    return;
  }

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: read tcp",
         PG_L("address", peer->address), PG_L("data", data));

  // FIXME: The write callback could starve the read callback here without
  // 'fair' scheduling, and fill the ring buffer.
  if (!pg_ring_write_slice(&peer->recv, data)) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: read too much data",
           PG_L("address", peer->address),
           PG_L("recv_write_space", pg_ring_write_space(peer->recv)),
           PG_L("data.len", data.len));
    peer_release(peer);
    return;
  }

  PgError err_handle = peer_handle_recv_data(peer);
  if (err_handle) {
    peer_release(peer);
    return;
  }
}

[[maybe_unused]]
static void peer_on_tcp_write(PgEventLoop *loop, u64 os_handle, void *ctx,
                              PgError err) {
  PG_ASSERT(nullptr != ctx);

  Peer *peer = ctx;

  if (err) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to tcp write",
           PG_L("address", peer->address), PG_L("err", err));
    peer_release(peer);
    return;
  }

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: wrote",
         PG_L("address", peer->address));

  PgError err_read = pg_event_loop_read_start(loop, os_handle, peer_on_read);
  if (err_read) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to tcp start read",
           PG_L("address", peer->address), PG_L("err", err_read));
    peer_release(peer);
    return;
  }
}

[[maybe_unused]] [[nodiscard]] static PgString
peer_make_handshake(PgString info_hash, PgArena *arena) {
  Pgu8Dyn sb = {0};
  PG_DYN_APPEND_SLICE(&sb,
                      PG_S("\x13"
                           "BitTorrent protocol"
                           "\x00"
                           "\x00"
                           "\x00"
                           "\x00"
                           "\x00"
                           "\x00"
                           "\x00"
                           "\x00"),
                      arena);
  PG_ASSERT(1 + 19 + 8 == sb.len);

  PG_ASSERT(20 == info_hash.len);
  PG_DYN_APPEND_SLICE(&sb, info_hash, arena);

  PgString peer_id = PG_S("00000000000000000000");
  PG_ASSERT(20 == peer_id.len);
  PG_DYN_APPEND_SLICE(&sb, peer_id, arena);

  PG_ASSERT(HANDSHAKE_LENGTH == sb.len);
  return PG_DYN_SLICE(PgString, sb);
}

[[maybe_unused]]
static void peer_on_connect(PgEventLoop *loop, u64 os_handle, void *ctx,
                            PgError err) {
  Peer *peer = ctx;

  if (err) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to connect",
           PG_L("err", err), PG_L("address", peer->address));
    peer_release(peer);
    return;
  }

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: connected",
         PG_L("address", peer->address));

  peer->recv = pg_ring_make(
      4 * PG_KiB + BLOCK_SIZE * peer->concurrent_blocks_download_max *
                       peer->concurrent_pieces_download_max,
      &peer->arena);
  {
    PgArena arena_tmp = peer->arena_tmp;
    PgString handshake = peer_make_handshake(peer->info_hash, &arena_tmp);
    PgError err_write =
        pg_event_loop_write(loop, os_handle, handshake, peer_on_tcp_write);
    if (err_write) {
      pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to tcp write",
             PG_L("err", err_write), PG_L("address", peer->address));
      peer_release(peer);
      return;
    }
  }
}

[[maybe_unused]] [[nodiscard]] static PgError peer_start(PgEventLoop *loop,
                                                         Peer *peer) {
  Pgu64Result res_tcp = pg_event_loop_tcp_init(loop, peer);
  if (res_tcp.err) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to tcp init",
           PG_L("err", res_tcp.err), PG_L("address", peer->address));
    peer_release(peer);
    return res_tcp.err;
  }
  peer->os_handle_socket = res_tcp.res;

  PgError err_connect = pg_event_loop_tcp_connect(
      loop, peer->os_handle_socket, peer->address, peer_on_connect);
  if (err_connect) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to start connect",
           PG_L("err", err_connect), PG_L("address", peer->address));
    peer_release(peer);
    return err_connect;
  }

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: started",
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

    pg_log(PG_LOG_LEVEL_INFO, "peer_pick_random", &peer.arena,
           PG_L("ipv4", peer.address.ip), PG_L("port", peer.address.port));
  }
}
#endif
