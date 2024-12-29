#pragma once

#include "tracker.c"
#include <netinet/tcp.h>

#define HANDSHAKE_LENGTH 68
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
  PEER_MSG_KIND_NONE = -1,
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
  };
} PeerMessage;

typedef struct {
  Ipv4Address address;
  Reader reader;
  Writer writer;
  PeerState state;
  String info_hash;
  Arena arena;
  int pid;
} Peer;

DYN(Peer);
SLICE(Peer);

[[maybe_unused]] [[nodiscard]] static Peer peer_make(Ipv4Address address,
                                                     String info_hash) {
  Peer peer = {0};
  peer.info_hash = info_hash;
  peer.address = address;
  peer.arena = arena_make_from_virtual_mem(4 * KiB);

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
  IoOperationResult res_io =
      reader_read_exactly(&peer->reader, HANDSHAKE_LENGTH, &peer->arena);
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

typedef struct {
  Error err;
  /* u32 next_tick_ms; */
  IoOperationSubscription io_subscription;
} PeerTickResult;

#if 0
[[nodiscard]] [[maybe_unused]]
// TODO: Report if progress was made?
static PeerTickResult peer_tick(Peer *peer, bool can_read, bool can_write) {
  ASSERT(can_read || can_write);

  log(LOG_LEVEL_INFO, "peer_tick", &peer->arena, L("ipv4", peer->address.ip),
      L("port", peer->address.port), L("peer.state", peer->state),
      L("can_read", (u32)can_read), L("can_write", (u32)can_write));

  PeerTickResult res = {0};
  if (PEER_STATE_CONNECTING == peer->state) {
    peer->state = PEER_STATE_CONNECTED;
  }

  switch (peer->state) {
  case PEER_STATE_CONNECTED: {
    if (can_write) {
      res.err = peer_send_handshake(peer);
      res.io_subscription = IO_OP_WILL_READ;
    }
    break;
  }
  case PEER_STATE_HANDSHAKE_SENT: {
    if (can_read) {
      res.err = peer_receive_handshake(peer);

      res.io_subscription = IO_OP_WILL_WRITE;
    }
    break;
  }
  case PEER_STATE_HANDSHAKE_RECEIVED: {

    log(LOG_LEVEL_INFO, "peer_tick TODO", &peer->arena,
        L("ipv4", peer->address.ip), L("port", peer->address.port),
        L("peer.state", peer->state), L("can_read", (u32)can_read),
        L("can_write", (u32)can_write));
    break;
  }
  case PEER_STATE_NONE:
  case PEER_STATE_CONNECTING:
  default:
    ASSERT(0);
  }
  return res;
}
#endif

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

#if 0
static void peer_end(Peer *peer) {
  writer_close(&peer->writer);
  peer->tombstone = true;
}
#endif

#if 0
static void peers_run(PeerSlice peers) {
  for (;;) {
    for (
  } 
}
#endif

[[maybe_unused]]
static void peer_spawn(Peer *peer) {
  if (PEER_STATE_NONE != peer->state) { // Idempotency.
    ASSERT(0 != peer->pid);
    return;
  }

  log(LOG_LEVEL_INFO, "peer spawn", &peer->arena, L("ipv4", peer->address.ip),
      L("port", peer->address.port));

  peer->state = PEER_STATE_SPAWNED;

  int child_pid = fork();
  if (-1 == child_pid) {
    exit(errno); // TODO: better.
  }

  if (child_pid > 0) { // Parent.
    peer->pid = child_pid;
    return;
  }

  // Child.
  {
    Error err = peer_connect(peer);
    if (err) {
      exit(1);
    }
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

  sleep(10000);
}
