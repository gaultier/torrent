#pragma once

#include "bencode.c"
#include <netinet/tcp.h>

#define HANDSHAKE_LENGTH 68
#define LENGTH_LENGTH 4
#define ERR_HANDSHAKE_INVALID 100

typedef struct {
  u32 index, begin, length;
} PeerMessageRequest;

typedef struct {
  u32 index, begin;
  String data;
} PeerMessagePiece;

typedef struct {
  u32 index, begin, length;
} PeerMessageCancel;

typedef enum {
  PEER_MSG_KIND_NONE = -2,
  PEER_MSG_KIND_KEEP_ALIVE = -1,
  PEER_MSG_KIND_CHOKE = 0,
  PEER_MSG_KIND_UNCHOKE = 1,
  PEER_MSG_KIND_INTERESTED = 2,
  PEER_MSG_KIND_UNINTERESTED = 3,
  PEER_MSG_KIND_HAVE = 4,
  PEER_MSG_KIND_BITFIELD = 5,
  PEER_MSG_KIND_REQUEST = 6,
  PEER_MSG_KIND_PIECE = 7,
  PEER_MSG_KIND_CANCEL = 8,
} PeerMessageKind;

typedef union {
  PeerMessageKind kind;
  union {
    PeerMessagePiece piece;
    PeerMessageCancel cancel;
    PeerMessageRequest request;
    String bitfield;
    u32 have;
  };
} PeerMessage;

typedef struct {
  Status status;
  PeerMessage msg;
} PeerMessageResult;

typedef struct {
  Ipv4Address address;
  Reader reader;
  Writer writer;
  String info_hash;
  Arena arena;
  Arena tmp_arena;
  int pid;
  int parent_child_liveness_pipe[2];
  u64 liveness_last_message_ns;
  bool tombstone;
} Peer;

DYN(Peer);
SLICE(Peer);

[[maybe_unused]] [[nodiscard]] static Peer peer_make(Ipv4Address address,
                                                     String info_hash) {
  Peer peer = {0};
  peer.info_hash = info_hash;
  peer.address = address;
  peer.arena = arena_make_from_virtual_mem(4 * KiB);
  peer.tmp_arena = arena_make_from_virtual_mem(4 * KiB);

  return peer;
}

[[maybe_unused]] [[nodiscard]] static Error peer_connect(Peer *peer) {
  ASSERT(0 != peer->address.ip);
  ASSERT(0 != peer->address.port);

  log(LOG_LEVEL_INFO, "peer connect", &peer->arena, L("ipv4", peer->address.ip),
      L("port", peer->address.port));

  int sock_fd = socket(AF_INET, SOCK_STREAM /*| SOCK_NONBLOCK*/, IPPROTO_TCP);
  if (-1 == sock_fd) {
    log(LOG_LEVEL_ERROR, "peer create socket", &peer->arena,
        L("ipv4", peer->address.ip), L("port", peer->address.port),
        L("err", errno));
    return (Error)errno;
  }
  int opt = 1;
  setsockopt(sock_fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));

  peer->reader = reader_make_from_socket(sock_fd);
  peer->writer = writer_make_from_socket(sock_fd);

  struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(peer->address.port),
      .sin_addr = {htonl(peer->address.ip)},
  };

  if (-1 == connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr))) {
    log(LOG_LEVEL_ERROR, "peer connect", &peer->arena,
        L("ipv4", peer->address.ip), L("port", peer->address.port),
        L("err", errno));
    return (Error)errno;
  }

  log(LOG_LEVEL_INFO, "peer connected", &peer->arena,
      L("ipv4", peer->address.ip), L("port", peer->address.port));
  return 0;
}

[[nodiscard]] static String peer_make_handshake(String info_hash,
                                                Arena *arena) {
  DynU8 sb = {0};
  dyn_append_slice(&sb,
                   S("\x13"
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
  ASSERT(1 + 19 + 8 == sb.len);

  ASSERT(20 == info_hash.len);
  dyn_append_slice(&sb, info_hash, arena);

  String peer_id = S("00000000000000000000");
  ASSERT(20 == peer_id.len);
  dyn_append_slice(&sb, peer_id, arena);

  ASSERT(HANDSHAKE_LENGTH == sb.len);
  return dyn_slice(String, sb);
}

[[nodiscard]] static Error peer_send_handshake(Peer *peer) {
  String handshake = peer_make_handshake(peer->info_hash, &peer->arena);
  Error err = writer_write_all(peer->writer, handshake);
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

[[nodiscard]] static Error peer_receive_handshake(Peer *peer) {
  ASSERT(0 != peer->tmp_arena.start);

  Arena tmp_arena = peer->tmp_arena;
  String handshake = {
      .data = arena_new(&tmp_arena, u8, HANDSHAKE_LENGTH),
      .len = HANDSHAKE_LENGTH,
  };

  IoOperationResult res_io = reader_read_exactly(&peer->reader, handshake);
  if (res_io.err) {
    log(LOG_LEVEL_ERROR, "peer_receive_handshake", &peer->arena,
        L("ipv4", peer->address.ip), L("port", peer->address.port),
        L("recv", res_io.s), L("err", res_io.err));
    return res_io.err;
  }
  log(LOG_LEVEL_INFO, "peer_receive_handshake", &peer->arena,
      L("ipv4", peer->address.ip), L("port", peer->address.port),
      L("recv_count", res_io.s.len));

  if (HANDSHAKE_LENGTH != res_io.s.len) {
    log(LOG_LEVEL_ERROR, "peer_receive_handshake wrong handshake length",
        &peer->arena, L("ipv4", peer->address.ip),
        L("port", peer->address.port), L("recv", res_io.s),
        L("err", res_io.err));
    return ERR_HANDSHAKE_INVALID;
  }

  String prefix = slice_range(res_io.s, 0, 20);
  String prefix_expected = S("\x13"
                             "BitTorrent protocol");
  if (!string_eq(prefix, prefix_expected)) {
    log(LOG_LEVEL_ERROR, "peer_receive_handshake wrong handshake prefix",
        &peer->arena, L("ipv4", peer->address.ip),
        L("port", peer->address.port), L("recv", res_io.s),
        L("err", res_io.err));
    return ERR_HANDSHAKE_INVALID;
  }

  String reserved_bytes = slice_range(res_io.s, 20, 28);
  (void)reserved_bytes; // Ignore.

  String info_hash_received = slice_range(res_io.s, 28, 28 + 20);
  if (!string_eq(info_hash_received, peer->info_hash)) {
    log(LOG_LEVEL_ERROR, "peer_receive_handshake wrong handshake hash",
        &peer->arena, L("ipv4", peer->address.ip),
        L("port", peer->address.port), L("recv", res_io.s),
        L("err", res_io.err));
    return ERR_HANDSHAKE_INVALID;
  }

  String remote_peer_id = slice_range(res_io.s, 28 + 20, 0);
  ASSERT(20 == remote_peer_id.len);
  // Ignore remote_peer_id for now.

  log(LOG_LEVEL_INFO, "peer_receive_handshake valid", &peer->arena,
      L("ipv4", peer->address.ip), L("port", peer->address.port));

  return 0;
}

[[maybe_unused]]
static void peer_pick_random(DynIpv4Address *addresses_all,
                             DynPeer *peers_active, u64 count, String info_hash,
                             Arena *arena) {
  u64 real_count = MIN(addresses_all->len, count);

  for (u64 i = 0; i < real_count; i++) {
    u32 idx = arc4random_uniform((u32)addresses_all->len); // FIXME
    Ipv4Address address = slice_at(*addresses_all, idx);
    Peer peer = peer_make(address, info_hash);
    *dyn_push(peers_active, arena) = peer;
    slice_swap_remove(addresses_all, idx);

    log(LOG_LEVEL_INFO, "peer_pick_random", &peer.arena,
        L("ipv4", peer.address.ip), L("port", peer.address.port));
  }
}

[[nodiscard]] static PeerMessageResult peer_receive_any_message(Peer *peer) {
  PeerMessageResult res = {0};

  Arena tmp_arena = peer->tmp_arena;

  String length = {
      .data = arena_new(&tmp_arena, u8, LENGTH_LENGTH),
      .len = LENGTH_LENGTH,
  };
  IoOperationResult io_res = reader_read_exactly(&peer->reader, length);
  if (io_res.err) {
    return res;
  }

  u32 length_announced = u8x4_be_to_u32(io_res.s);

  if (0 == length_announced) {
    res.status = STATUS_OK;
    res.msg.kind = PEER_MSG_KIND_KEEP_ALIVE;
    return res;
  }

  String data = {
      .data = arena_new(&tmp_arena, u8, length_announced),
      .len = length_announced,
  };
  io_res = reader_read_exactly(&peer->reader, data);
  if (io_res.err) {
    return res;
  }

  u8 kind = slice_at(io_res.s, 0);

  log(LOG_LEVEL_DEBUG, "peer message", &peer->arena,
      L("ipv4", peer->address.ip), L("port", peer->address.port),
      L("length_announced", length_announced), L("kind", (u64)kind));

  switch (kind) {
  case PEER_MSG_KIND_CHOKE: {
    res.msg.kind = kind;
    res.status = STATUS_OK;
    break;
  }
  case PEER_MSG_KIND_UNCHOKE: {
    res.msg.kind = kind;
    res.status = STATUS_OK;
    break;
  }
  case PEER_MSG_KIND_INTERESTED: {
    res.msg.kind = kind;
    res.status = STATUS_OK;
    break;
  }
  case PEER_MSG_KIND_UNINTERESTED: {
    res.msg.kind = kind;
    res.status = STATUS_OK;
    break;
  }
  case PEER_MSG_KIND_HAVE: {
    if ((1 + 4) != length_announced) {
      return res;
    }
    res.msg.kind = kind;
    String data_msg = slice_range(io_res.s, 1, 0);
    res.msg.have = u8x4_be_to_u32(data_msg);
    res.status = STATUS_OK;
    break;
  }
  case PEER_MSG_KIND_BITFIELD: {
    res.msg.kind = kind;
    // TODO: Length check?
    res.msg.bitfield.len = length_announced - 1;
    res.msg.bitfield.data = arena_new(&peer->arena, u8, res.msg.bitfield.len);

    String data_msg = slice_range(io_res.s, 1, 0);
    ASSERT(data_msg.len == res.msg.bitfield.len);
    memcpy(res.msg.bitfield.data, data_msg.data, data_msg.len);

    res.status = STATUS_OK;
    break;
  }
  case PEER_MSG_KIND_REQUEST: {
    break;
  }
  case PEER_MSG_KIND_PIECE: {
    break;
  }
  case PEER_MSG_KIND_CANCEL: {
    break;
  }
  default:
    log(LOG_LEVEL_ERROR, "peer message unknown kind", &peer->arena,
        L("ipv4", peer->address.ip), L("port", peer->address.port),
        L("kind", (u64)kind));
    return res;
  }

  return res;
}

[[maybe_unused]]
static void peer_spawn(Peer *peer) {
  if (peer->pid) { // Idempotency.
    return;
  }

  log(LOG_LEVEL_INFO, "peer spawn", &peer->arena, L("ipv4", peer->address.ip),
      L("port", peer->address.port));

  if (-1 == pipe(peer->parent_child_liveness_pipe)) {
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
    close(peer->parent_child_liveness_pipe[1]); // Close write end of the
                                                // liveness pipe.
    return;
  }

  // Child.
  close(peer->parent_child_liveness_pipe[0]); // Close read end of the
                                              // liveness pipe.
  {
    Error err = peer_connect(peer);
    if (err) {
      exit(1);
    }
  }

  {
    u64 now_ns = monotonic_now_ns();
    write(peer->parent_child_liveness_pipe[1], &now_ns, sizeof(now_ns));
  }

  {
    Error err = peer_send_handshake(peer);
    if (err) {
      exit(1);
    }
  }
  {
    Error err = peer_receive_handshake(peer);
    if (err) {
      exit(1);
    }
  }
  {
    PeerMessageResult res = peer_receive_any_message(peer);
    if (STATUS_OK != res.status) {
      exit(1);
    }
  }

  sleep(10000);
}
