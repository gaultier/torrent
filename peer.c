#pragma once

#include "bencode.c"

#define HANDSHAKE_LENGTH 68
#define LENGTH_LENGTH 4
#define ERR_HANDSHAKE_INVALID 100
#define BLOCK_LENGTH (1UL << 14)

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

RESULT(PeerMessage) PeerMessageResult;

typedef struct {
  PgIpv4Address address;
  BufferedReader reader;
  PgWriter writer;
  PgString info_hash;
  PgArena arena;
  PgArena tmp_arena;
  int pid;
  int pipe_child_to_parent[2];
  u64 liveness_last_message_ns;
  bool tombstone;
  bool choked, interested;
  PgString remote_bitfield;
} Peer;

DYN(Peer);
SLICE(Peer);

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

[[maybe_unused]] [[nodiscard]] static Peer peer_make(PgIpv4Address address,
                                                     PgString info_hash) {
  Peer peer = {0};
  peer.info_hash = info_hash;
  peer.address = address;
  peer.arena = pg_arena_make_from_virtual_mem(4 * KiB);
  peer.tmp_arena = pg_arena_make_from_virtual_mem(4 * KiB);
  peer.choked = true;
  peer.interested = false;

  return peer;
}

[[maybe_unused]] [[nodiscard]] static PgError peer_connect(Peer *peer) {
  PG_ASSERT(0 != peer->address.ip);
  PG_ASSERT(0 != peer->address.port);

  log(LOG_LEVEL_INFO, "peer connect", &peer->arena, L("ipv4", peer->address.ip),
      L("port", peer->address.port));

  PgCreateSocketResult res_create_socket = pg_net_create_tcp_socket();
  if (res_create_socket.err) {
    log(LOG_LEVEL_ERROR, "peer create socket", &peer->arena,
        L("ipv4", peer->address.ip), L("port", peer->address.port),
        L("err", res_create_socket.err));
    return (PgError)errno;
  }

  {
    PgError err_set_nodelay = pg_net_set_nodelay(res_create_socket.res, true);
    if (err_set_nodelay) {
      log(LOG_LEVEL_ERROR, "failed to setsockopt(2)", &peer->arena,
          L("ipv4", peer->address.ip), L("port", peer->address.port),
          L("err", err_set_nodelay));
    }
  }

  peer->reader = pg_reader_make_from_socket(res_create_socket.res);
  peer->writer = pg_writer_make_from_socket(res_create_socket.res);

  {
    PgError err = pg_net_connect_ipv4(res_create_socket.res, peer->address);
    if (err) {
      log(LOG_LEVEL_ERROR, "peer connect", &peer->arena,
          L("ipv4", peer->address.ip), L("port", peer->address.port),
          L("err", err));
      return (PgError)err;
    }
  }

  log(LOG_LEVEL_INFO, "peer connected", &peer->arena,
      L("ipv4", peer->address.ip), L("port", peer->address.port));
  return 0;
}

[[nodiscard]] static PgString peer_make_handshake(PgString info_hash,
                                                PgArena *arena) {
  DynU8 sb = {0};
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

[[nodiscard]] static PgError peer_send_handshake(Peer *peer) {
  PgString handshake = peer_make_handshake(peer->info_hash, &peer->arena);
  PgError err = pg_writer_write_all(peer->writer, handshake);
  if (err) {
    log(LOG_LEVEL_ERROR, "peer send handshake", &peer->arena,
        L("ipv4", peer->address.ip), L("port", peer->address.port),
        L("err", err));
    return err;
  }

  log(LOG_LEVEL_INFO, "peer sent handshake ok", &peer->arena,
      L("ipv4", peer->address.ip), L("port", peer->address.port));

  return 0;
}

[[nodiscard]] static PgError peer_receive_handshake(Peer *peer) {
  PG_ASSERT(0 != peer->tmp_arena.start);

  PgArena tmp_arena = peer->tmp_arena;
  PgString handshake = {
      .data = pg_arena_new(&tmp_arena, u8, HANDSHAKE_LENGTH),
      .len = HANDSHAKE_LENGTH,
  };

  PgError res_io_err = pg_reader_read_exactly(&peer->reader, handshake);
  if (res_io_err) {
    log(LOG_LEVEL_ERROR, "peer_receive_handshake", &peer->arena,
        L("ipv4", peer->address.ip), L("port", peer->address.port),
        L("err", res_io_err));
    return res_io_err;
  }
  log(LOG_LEVEL_INFO, "peer_receive_handshake", &peer->arena,
      L("ipv4", peer->address.ip), L("port", peer->address.port));

  PgString prefix = PG_SLICE_RANGE(handshake, 0, 20);
  PgString prefix_expected = PG_S("\x13"
                             "BitTorrent protocol");
  if (!pg_string_eq(prefix, prefix_expected)) {
    log(LOG_LEVEL_ERROR, "peer_receive_handshake wrong handshake prefix",
        &peer->arena, L("ipv4", peer->address.ip),
        L("port", peer->address.port), L("recv", handshake));
    return ERR_HANDSHAKE_INVALID;
  }

  PgString reserved_bytes = PG_SLICE_RANGE(handshake, 20, 28);
  (void)reserved_bytes; // Ignore.

  PgString info_hash_received = PG_SLICE_RANGE(handshake, 28, 28 + 20);
  if (!pg_string_eq(info_hash_received, peer->info_hash)) {
    log(LOG_LEVEL_ERROR, "peer_receive_handshake wrong handshake hash",
        &peer->arena, L("ipv4", peer->address.ip),
        L("port", peer->address.port), L("recv", handshake));
    return ERR_HANDSHAKE_INVALID;
  }

  PgString remote_peer_id = PG_SLICE_RANGE_START(handshake, 28 + 20);
  PG_ASSERT(20 == remote_peer_id.len);
  // Ignore remote_peer_id for now.

  log(LOG_LEVEL_INFO, "peer_receive_handshake valid", &peer->arena,
      L("ipv4", peer->address.ip), L("port", peer->address.port));

  return 0;
}

[[maybe_unused]]
static void peer_pick_random(DynIpv4Address *addresses_all,
                             DynPeer *peers_active, u64 count, PgString info_hash,
                             PgArena *arena) {
  u64 real_count = MIN(addresses_all->len, count);

  for (u64 i = 0; i < real_count; i++) {
    u32 idx = arc4random_uniform((u32)addresses_all->len); // FIXME
    PgIpv4Address address = PG_SLICE_AT(*addresses_all, idx);
    Peer peer = peer_make(address, info_hash);
    *PG_DYN_PUSH(peers_active, arena) = peer;
    PG_slice_swap_remove(addresses_all, idx);

    log(LOG_LEVEL_INFO, "peer_pick_random", &peer.arena,
        L("ipv4", peer.address.ip), L("port", peer.address.port));
  }
}

[[nodiscard]] static PeerMessageResult peer_receive_any_message(Peer *peer) {
  PG_ASSERT(peer->tmp_arena.start != 0);
  PG_ASSERT(peer->arena.start != 0);
  PG_ASSERT(peer->reader.read_fn != nullptr);

  PeerMessageResult res = {0};

  PgArena tmp_arena = peer->tmp_arena;

  PgString length = {
      .data = pg_arena_new(&tmp_arena, u8, LENGTH_LENGTH),
      .len = LENGTH_LENGTH,
  };
  PgError err_io = pg_reader_read_exactly(&peer->reader, length);
  if (err_io) {
    res.err = err_io;
    return res;
  }

  u32 length_announced = pg_u8x4_be_to_u32(length);

  if (0 == length_announced) {
    res.res.kind = PEER_MSG_KIND_KEEP_ALIVE;
    return res;
  }

  PgString data = {
      .data = pg_arena_new(&tmp_arena, u8, length_announced),
      .len = length_announced,
  };
  err_io = pg_reader_read_exactly(&peer->reader, data);
  if (err_io) {
    res.err = err_io;
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
      res.err = TORR_ERR_PEER_MESSAGE_INVALID;
      return res;
    }
    res.res.kind = kind;
    PgString data_msg = PG_SLICE_RANGE_START(data, 1);
    res.res.have = pg_u8x4_be_to_u32(data_msg);
    break;
  }
  case PEER_MSG_KIND_BITFIELD: {
    res.res.kind = kind;
    // TODO: Length check?
    res.res.bitfield.len = length_announced - 1;
    if (0 == res.res.bitfield.len) {
      res.err = TORR_ERR_PEER_MESSAGE_INVALID;
      return res;
    }

    res.res.bitfield = pg_string_dup(PG_SLICE_RANGE_START(data, 1), &peer->arena);

    break;
  }
  case PEER_MSG_KIND_REQUEST: {
    res.res.kind = kind;
    if (1 + 3 * sizeof(u32) != length_announced) {
      res.err = TORR_ERR_PEER_MESSAGE_INVALID;
      return res;
    }
    res.res.request.index = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 1, 5));
    res.res.request.begin = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 5, 9));
    res.res.request.length = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 9, 13));

    break;
  }
  case PEER_MSG_KIND_PIECE: {
    res.res.kind = kind;
    if (1 + 2 * sizeof(u32) + BLOCK_LENGTH != length_announced) {
      res.err = TORR_ERR_PEER_MESSAGE_INVALID;
      return res;
    }
    res.res.piece.index = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 1, 5));
    res.res.piece.begin = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 5, 9));
    res.res.piece.data = pg_string_dup(PG_SLICE_RANGE_START(data, 9), &peer->arena);

    break;
  }
  case PEER_MSG_KIND_CANCEL: {
    res.res.kind = kind;
    if (1 + 3 * sizeof(u32) != length_announced) {
      res.err = TORR_ERR_PEER_MESSAGE_INVALID;
      return res;
    }
    res.res.cancel.index = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 1, 5));
    res.res.cancel.begin = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 5, 9));
    res.res.cancel.length = pg_u8x4_be_to_u32(PG_SLICE_RANGE(data, 9, 13));

    break;
  }
  default:
    log(LOG_LEVEL_ERROR, "peer message unknown kind", &peer->arena,
        L("ipv4", peer->address.ip), L("port", peer->address.port),
        L("kind", peer_message_kind_to_string(kind)));
    res.err = TORR_ERR_PEER_MESSAGE_INVALID;
    return res;
  }
  log(LOG_LEVEL_DEBUG, "peer received message", &peer->arena,
      L("ipv4", peer->address.ip), L("port", peer->address.port),
      L("length_announced", length_announced),
      L("kind", peer_message_kind_to_string(kind)));

  return res;
}

[[maybe_unused]] static void peer_handle_message(Peer *peer, PeerMessage msg) {
  switch (msg.kind) {
  case PEER_MSG_KIND_CHOKE:
    peer->choked = true;
    break;
  case PEER_MSG_KIND_UNCHOKE:
    peer->choked = false;
    break;
  case PEER_MSG_KIND_INTERESTED:
    peer->interested = true;
    break;
  case PEER_MSG_KIND_UNINTERESTED:
    peer->interested = false;
    break;
  case PEER_MSG_KIND_HAVE:
    break;
  case PEER_MSG_KIND_BITFIELD:
    peer->remote_bitfield = msg.bitfield;
    break;
  case PEER_MSG_KIND_REQUEST:
    // TODO
    break;
  case PEER_MSG_KIND_PIECE:
    // TODO
    break;
  case PEER_MSG_KIND_CANCEL:
    // TODO
    break;
  case PEER_MSG_KIND_KEEP_ALIVE:
    // TODO
    break;
  default:
    PG_ASSERT(0);
  }
}

[[maybe_unused]] [[nodiscard]] static PgError peer_send_message(Peer *peer,
                                                              PeerMessage msg) {
  log(LOG_LEVEL_INFO, "peer_send_message", &peer->arena,
      L("ipv4", peer->address.ip), L("port", peer->address.port),
      L("msg.kind", peer_message_kind_to_string(msg.kind)));

  PgError res = 0;

  PgArena tmp_arena = peer->tmp_arena;
  DynU8 sb = {0};
  PG_DYN_ENSURE_CAP(&sb, 256, &tmp_arena);

  switch (msg.kind) {
  case PEER_MSG_KIND_KEEP_ALIVE:
    pg_string_builder_append_u32(&sb, 0, &tmp_arena);
    break;

  case PEER_MSG_KIND_CHOKE:
  case PEER_MSG_KIND_UNCHOKE:
  case PEER_MSG_KIND_INTERESTED:
  case PEER_MSG_KIND_UNINTERESTED:
    pg_string_builder_append_u32(&sb, 1, &tmp_arena);
    *PG_DYN_PUSH(&sb, &tmp_arena) = msg.kind;
    break;

  case PEER_MSG_KIND_HAVE:
    pg_string_builder_append_u32(&sb, 1 + sizeof(u32), &tmp_arena);
    *PG_DYN_PUSH(&sb, &tmp_arena) = msg.kind;
    pg_string_builder_append_u32(&sb, msg.have, &tmp_arena);
    break;

  case PEER_MSG_KIND_BITFIELD:
    pg_string_builder_append_u32(&sb, 1 + (u32)msg.bitfield.len, &tmp_arena);
    *PG_DYN_PUSH(&sb, &tmp_arena) = msg.kind;
    PG_DYN_APPEND_SLICE(&sb, msg.bitfield, &tmp_arena);
    break;

  case PEER_MSG_KIND_REQUEST:
    pg_string_builder_append_u32(&sb, 1 + 3 * sizeof(u32), &tmp_arena);
    *PG_DYN_PUSH(&sb, &tmp_arena) = msg.kind;
    pg_string_builder_append_u32(&sb, msg.request.index, &tmp_arena);
    pg_string_builder_append_u32(&sb, msg.request.begin, &tmp_arena);
    pg_string_builder_append_u32(&sb, msg.request.length, &tmp_arena);
    break;

  case PEER_MSG_KIND_PIECE:
    pg_string_builder_append_u32(&sb, 1 + 2 * sizeof(u32) + (u32)msg.piece.data.len,
                     &tmp_arena);
    *PG_DYN_PUSH(&sb, &tmp_arena) = msg.kind;
    pg_string_builder_append_u32(&sb, msg.piece.index, &tmp_arena);
    pg_string_builder_append_u32(&sb, msg.piece.begin, &tmp_arena);
    PG_DYN_APPEND_SLICE(&sb, msg.piece.data, &tmp_arena);
    break;

  case PEER_MSG_KIND_CANCEL:
    pg_string_builder_append_u32(&sb, 1 + 3 * sizeof(u32), &tmp_arena);
    *PG_DYN_PUSH(&sb, &tmp_arena) = msg.kind;
    pg_string_builder_append_u32(&sb, msg.cancel.index, &tmp_arena);
    pg_string_builder_append_u32(&sb, msg.cancel.begin, &tmp_arena);
    pg_string_builder_append_u32(&sb, msg.cancel.length, &tmp_arena);
    break;
  default:
    PG_ASSERT(0);
  }

  PG_ASSERT(sb.len >= sizeof(u32));

  PgString s = PG_DYN_SLICE(PgString, sb);
  res = pg_writer_write_all(peer->writer, s);

  log(res ? LOG_LEVEL_ERROR : LOG_LEVEL_INFO, "peer sent message", &peer->arena,
      L("ipv4", peer->address.ip), L("port", peer->address.port),
      L("msg.kind", peer_message_kind_to_string(msg.kind)), L("s.len", s.len),
      L("err", res));

  return res;
}

[[maybe_unused]]
static void peer_spawn(Peer *peer) {
  if (peer->pid) { // Idempotency.
    return;
  }

  log(LOG_LEVEL_INFO, "peer spawn", &peer->arena, L("ipv4", peer->address.ip),
      L("port", peer->address.port));

  if (-1 == pipe(peer->pipe_child_to_parent)) {
    log(LOG_LEVEL_ERROR, "failed to pipe(2)", &peer->arena, L("err", errno));
    exit(errno);
  }

  peer->liveness_last_message_ns = monotonic_now_ns();

  int child_pid = fork();
  if (-1 == child_pid) {
    log(LOG_LEVEL_ERROR, "failed to fork(2)", &peer->arena, L("err", errno));
    exit(errno);
  }

  if (child_pid > 0) { // Parent.
    peer->pid = child_pid;
    close(peer->pipe_child_to_parent[1]); // Close write end of the
                                          // liveness pipe.
    return;
  }

  // Child.
  close(peer->pipe_child_to_parent[0]); // Close read end of the
                                        // liveness pipe.
  {
    PgError err = peer_connect(peer);
    if (err) {
      exit(1);
    }
  }

  {
    u64 now_ns = monotonic_now_ns();
    write(peer->pipe_child_to_parent[1], &now_ns, sizeof(now_ns));
  }

  {
    PgError err = peer_send_handshake(peer);
    if (err) {
      exit(1);
    }
  }
  {
    PgError err = peer_receive_handshake(peer);
    if (err) {
      exit(1);
    }
  }
  {
    PeerMessageResult res = peer_receive_any_message(peer);
    if (res.err) {
      exit(1);
    }
  }
  {
    PeerMessage msg = {
        .kind = PEER_MSG_KIND_REQUEST,
        .request =
            {
                .index = 2,
                .begin = 17 * BLOCK_LENGTH,
                .length = BLOCK_LENGTH,
            },
    };
    PgError res_send_msg = peer_send_message(peer, msg);
    if (res_send_msg) {
      exit(1);
    }
  }
  {
    PeerMessageResult res = peer_receive_any_message(peer);
    if (res.err) {
      exit(1);
    }
  }

  sleep(10000);
}
