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
  PeerMessage res;
} PeerMessageReadResult;

typedef struct {
  u32 piece;
  PgString blocks_bitfield_have;
  u64 concurrent_blocks_download_count;
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

  PgEventLoop *loop;
  u64 os_handle;
  PgRing recv;
} Peer;

PG_DYN(Peer) PeerDyn;
PG_SLICE(Peer) PeerSlice;

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

[[maybe_unused]] [[nodiscard]] static Peer
peer_make(PgIpv4Address address, PgString info_hash, PgLogger *logger,
          Download *download, PgEventLoop *loop,
          u64 concurrent_pieces_download_max,
          u64 concurrent_blocks_download_max) {
  Peer peer = {0};
  peer.address = address;
  peer.info_hash = info_hash;
  peer.logger = logger;
  peer.download = download;
  peer.loop = loop;
  peer.concurrent_pieces_download_max = concurrent_pieces_download_max;
  peer.concurrent_blocks_download_max = concurrent_blocks_download_max;

  // At most one block is held in memory at any time, plus a bit of temporary
  // data for encoding/decoding messages.
  // TODO: Check if this still holds if we use async I/O for file rw.
  peer.arena = pg_arena_make_from_virtual_mem(
      4 * PG_KiB +
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
  (void)pg_event_loop_handle_close(peer->loop, peer->os_handle);
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

  if (0 == length_announced) {
    res.res.kind = PEER_MSG_KIND_KEEP_ALIVE;
    goto end;
  }

  PgString data = {
      .data = pg_arena_new(&arena_tmp, u8, length_announced),
      .len = length_announced,
  };
  if (!pg_ring_read_slice(&recv_tmp, data)) {
    return res;
  }

  u8 kind = PG_SLICE_AT(data, 0);

  switch (kind) {
  case PEER_MSG_KIND_CHOKE: {
    res.res.kind = kind;
    break;
  }
  case PEER_MSG_KIND_UNCHOKE: {
    res.res.kind = kind;
    break;
  }
  case PEER_MSG_KIND_INTERESTED: {
    res.res.kind = kind;
    break;
  }
  case PEER_MSG_KIND_UNINTERESTED: {
    res.res.kind = kind;
    break;
  }
  case PEER_MSG_KIND_HAVE: {
    if ((1 + sizeof(u32)) != length_announced) {
      res.err = PG_ERR_INVALID_VALUE;
      return res;
    }
    res.res.kind = kind;
    PgString data_msg = PG_SLICE_RANGE_START(data, 1);
    res.res.have = pg_u8x4_be_to_u32(data_msg);

    if (res.res.have > peer->download->pieces_count) {
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

    res.res.kind = kind;
    u64 bitfield_len = length_announced - 1;
    if (0 == bitfield_len ||
        peer->download->local_bitfield_have.len != bitfield_len) {
      pg_log(peer->logger, PG_LOG_LEVEL_ERROR,
             "invalid bitfield length received", PG_L("address", peer->address),
             PG_L("len_actual", res.res.bitfield.len),
             PG_L("len_expected", peer->download->local_bitfield_have.len));
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
    res.res.kind = kind;
    if (1 + 3 * sizeof(u32) != length_announced) {
      res.err = PG_ERR_INVALID_VALUE;
      return res;
    }
    res.res.request.index = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 1, 5));
    res.res.request.begin = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 5, 9));
    res.res.request.length = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 9, 13));

    break;
  }
  case PEER_MSG_KIND_PIECE: {
    res.res.kind = kind;
    if (1 + 2 * sizeof(u32) + BLOCK_SIZE != length_announced) {
      res.err = PG_ERR_INVALID_VALUE;
      return res;
    }
    res.res.piece.index = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 1, 5));
    res.res.piece.begin = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 5, 9));
    res.res.piece.data =
        pg_string_dup(PG_SLICE_RANGE_START(data, 9), &peer->arena);

    break;
  }
  case PEER_MSG_KIND_CANCEL: {
    res.res.kind = kind;
    if (1 + 3 * sizeof(u32) != length_announced) {
      res.err = PG_ERR_INVALID_VALUE;
      return res;
    }
    res.res.cancel.index = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 1, 5));
    res.res.cancel.begin = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 5, 9));
    res.res.cancel.length = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 9, 13));

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
         PG_L("length_announced", length_announced),
         PG_L("kind", peer_message_kind_to_string(res.res.kind)));

  peer->recv = recv_tmp;
  res.present = true;
  return res;
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

[[nodiscard]] [[maybe_unused]] static i64
peer_pick_block(u32 piece, Download *download, PgString blocks_bitfield_have) {
  u32 blocks_count = download_compute_blocks_count_for_piece(
      piece, download->piece_length, download->total_file_size);
  u64 start = pg_rand_u32(0, blocks_count);

  for (u64 i = 0; i < blocks_count; i++) {
    u64 idx = (start + i) % blocks_count;
    if (!pg_bitfield_get(blocks_bitfield_have, idx)) {
      PG_ASSERT(idx <= UINT32_MAX);
      PG_ASSERT(idx < blocks_count);
      return (i32)idx;
    }
  }
  return -1;
}

[[nodiscard]] [[maybe_unused]] static PgError
peer_request_block_maybe(Peer *peer, PieceDownload *pd) {
  PgArena arena_tmp = peer->arena_tmp;
  i64 block =
      peer_pick_block(pd->piece, peer->download, pd->blocks_bitfield_have);
  if (-1 == block) {
    // TODO: Verify piece hash.
    pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: no block left to pick",
           PG_L("address", peer->address), PG_L("piece", pd->piece));
    return 0;
  }

  PeerMessage msg = {
      .kind = PEER_MSG_KIND_REQUEST,
      .request =
          {
              .index = (u32)block,
              .begin = (u32)block * BLOCK_SIZE,
              .length = BLOCK_SIZE,
          },
  };
  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "requesting block",
         PG_L("address", peer->address), PG_L("block", (u32)block),
         PG_L("piece", pd->piece));

  PgString msg_encoded = peer_encode_message(msg, &arena_tmp);
  PgError err = pg_event_loop_write(peer->loop, peer->os_handle, msg_encoded,
                                    peer_on_write);
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
    for (u64 i = 0; i < peer->concurrent_pieces_download_max -
                            peer->downloading_pieces.len;
         i++) {

      i64 piece =
          download_pick_next_piece(peer->download, peer->remote_bitfield);
      if (-1 == piece) {
        pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: no piece left to pick",
               PG_L("address", peer->address));

        break;
      }

      *PG_DYN_PUSH(&peer->downloading_pieces, &peer->arena) = (PieceDownload){
          .piece = (u32)piece,
          .blocks_bitfield_have = pg_string_make(
              pg_div_ceil(peer->download->blocks_per_piece_count, 8),
              &peer->arena),
      };
    }
  }

  for (u64 i = 0; i < peer->downloading_pieces.len; i++) {
    PieceDownload *pd = PG_SLICE_AT_PTR(&peer->downloading_pieces, i);
    PG_ASSERT(pd->concurrent_blocks_download_count <=
              peer->concurrent_blocks_download_max);

    if (pd->concurrent_blocks_download_count ==
        peer->concurrent_blocks_download_max) {
      continue;
    }

    for (u64 j = 0; j < peer->concurrent_blocks_download_max -
                            pd->concurrent_blocks_download_count;
         j++) {
      PgError err = peer_request_block_maybe(peer, pd);
      if (err) {
        return err;
      }
    }
  }

  return 0;
}

[[nodiscard]] [[maybe_unused]] static PgError
peer_handle_message(Peer *peer, PeerMessage msg) {
  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: handle message",
         PG_L("address", peer->address),
         PG_L("msg.kind", peer_message_kind_to_string(msg.kind)));

  switch (msg.kind) {
  case PEER_MSG_KIND_CHOKE:
    peer->remote_choked = true;
    break;
  case PEER_MSG_KIND_UNCHOKE:
    peer->remote_choked = false;
    return peer_request_remote_data_maybe(peer);
  case PEER_MSG_KIND_INTERESTED:
    peer->remote_interested = true;
    break;
  case PEER_MSG_KIND_UNINTERESTED:
    peer->remote_interested = false;
    break;
  case PEER_MSG_KIND_HAVE:
    pg_bitfield_set(peer->remote_bitfield, msg.have, true);
    break;
  case PEER_MSG_KIND_BITFIELD: {
    return peer_request_remote_data_maybe(peer);
  }
  case PEER_MSG_KIND_REQUEST:
    // TODO
    break;
  case PEER_MSG_KIND_PIECE:
    // TODO
    break;
  case PEER_MSG_KIND_CANCEL:
    // TODO
    break;
  case PEER_MSG_KIND_KEEP_ALIVE: {
    PgArena arena_tmp = peer->arena_tmp;
    PeerMessage msg_response = {.kind = PEER_MSG_KIND_KEEP_ALIVE};
    PgString msg_encoded = peer_encode_message(msg_response, &arena_tmp);
    PgError err = pg_event_loop_write(peer->loop, peer->os_handle, msg_encoded,
                                      peer_on_write);
    if (err) {
      pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to write",
             PG_L("err", err), PG_L("address", peer->address),
             PG_L("msg_encoded", msg_encoded),
             PG_L("msg.kind", peer_message_kind_to_string(msg.kind)));
      peer_release(peer);
      return err;
    }
    pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: sending keep alive",
           PG_L("address", peer->address),
           PG_L("msg.kind", peer_message_kind_to_string(msg.kind)));
  } break;
  default:
    PG_ASSERT(0);
  }
  return 0;
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
      PeerMessageReadResult res_msg = peer_read_any_message(peer);
      if (res_msg.err) {
        return res_msg.err;
      }
      if (!res_msg.present) {
        return 0;
      }

      PgError err_handle_msg = peer_handle_message(peer, res_msg.res);
      if (err_handle_msg) {
        return err_handle_msg;
      }

    } break;
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

  peer->recv = pg_ring_make(4 * PG_KiB + BLOCK_SIZE, &peer->arena);
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
  peer->os_handle = res_tcp.res;

  PgError err_connect = pg_event_loop_tcp_connect(
      loop, peer->os_handle, peer->address, peer_on_connect);
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
