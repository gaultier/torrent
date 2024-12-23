#pragma once

#include "tracker.c"

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

[[maybe_unused]] [[nodiscard]] static Error peer_connect(Peer *peer) {
  ASSERT(0 != peer->ipv4);
  ASSERT(0 != peer->port);

  int sock_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (-1 == sock_fd) {
    log(LOG_LEVEL_ERROR, "peer create socket", &peer->arena,
        L("ipv4", peer->ipv4), L("port", peer->port), L("err", errno));
    return (Error)errno;
  }

  struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(peer->port),
      .sin_addr = {htonl(peer->ipv4)},
  };

  if (-1 == connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr))) {
    if (EINPROGRESS != errno) {
      log(LOG_LEVEL_ERROR, "peer connect", &peer->arena, L("ipv4", peer->ipv4),
          L("port", peer->port), L("err", errno));
      return (Error)errno;
    }
  }
  peer->reader = reader_make_from_socket(sock_fd);
  peer->writer = writer_make_from_socket(sock_fd);

  log(LOG_LEVEL_INFO, "peer connected", &peer->arena, L("ipv4", peer->ipv4),
      L("port", peer->port));
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
    log(LOG_LEVEL_ERROR, "peer handshake", &peer->arena, L("ipv4", peer->ipv4),
        L("port", peer->port), L("err", err));
    return err;
  }

  return 0;
}

[[nodiscard]] static Error peer_receive_handshake(Peer *peer) {
  IoOperationResult res_io =
      reader_read_exactly(&peer->reader, HANDSHAKE_LENGTH, &peer->arena);
  if (res_io.err) {
    return res_io.err;
  }
  log(LOG_LEVEL_INFO, "peer_receive_handshake", &peer->arena,
      L("ipv4", peer->ipv4), L("port", peer->port), L("recv", res_io.s));

  if (HANDSHAKE_LENGTH != res_io.s.len) {
    return ERR_HANDSHAKE_INVALID;
  }

  String prefix = slice_range(res_io.s, 0, 28);
  String prefix_expected = S("\x13"
                             "BitTorrent protocol"
                             "\x00"
                             "\x00"
                             "\x00"
                             "\x00"
                             "\x00"
                             "\x00"
                             "\x00"
                             "\x00");
  if (!string_eq(prefix, prefix_expected)) {
    return ERR_HANDSHAKE_INVALID;
  }

  String info_hash_received = slice_range(res_io.s, HANDSHAKE_LENGTH - 20, 0);
  if (!string_eq(info_hash_received, peer->info_hash)) {
    return ERR_HANDSHAKE_INVALID;
  }

  return 0;
}

[[maybe_unused]]
// TODO: Report if progress was made?
static Error peer_tick(Peer *peer, bool can_read, bool can_write) {
  log(LOG_LEVEL_INFO, "peer_tick", &peer->arena, L("ipv4", peer->ipv4),
      L("port", peer->port));

  Error err = 0;

  switch (peer->state) {
  case PEER_STATE_NONE: {
    if (can_write) {
      err = peer_send_handshake(peer);
      peer->state = PEER_STATE_HANDSHAKE_SENT;
      log(LOG_LEVEL_INFO, "peer sent handshake", &peer->arena,
          L("ipv4", peer->ipv4), L("port", peer->port), L("err", err));

      return err;
    }
    return 0;
  }
  case PEER_STATE_HANDSHAKE_SENT: {
    if (can_read) {
      err = peer_receive_handshake(peer);
      peer->state = PEER_SENT_HANDSHAKE_RECEIVED;
      log(LOG_LEVEL_INFO, "peer received handshake", &peer->arena,
          L("ipv4", peer->ipv4), L("port", peer->port), L("err", err));
      return err;
    }
    return 0;
  }
  case PEER_SENT_HANDSHAKE_RECEIVED: {
    // TODO
    return 0;
  }
  default:
    ASSERT(0);
  }
  ASSERT(0);
}

static void peer_end(Peer *peer) { writer_close(&peer->writer); }
