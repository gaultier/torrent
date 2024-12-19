#pragma once

#include "tracker.c"

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

[[nodiscard]] static Error peer_connect(Peer *peer, Arena *arena) {
  ASSERT(0 != peer->ipv4);
  ASSERT(0 != peer->port);

  int socket_peer = socket(AF_INET, SOCK_DGRAM, 0);
  if (-1 == socket_peer) {
    log(LOG_LEVEL_ERROR, "peer create socket", arena, L("ipv4", peer->ipv4),
        L("port", peer->port), L("err", errno));
    return (Error)errno;
  }
  struct sockaddr_in addr = {
      .sin_port = htons(peer->port),
      .sin_addr = {htonl(peer->ipv4)},
  };

  if (-1 == connect(socket_peer, (struct sockaddr *)&addr, sizeof(addr))) {
    log(LOG_LEVEL_ERROR, "peer connect", arena, L("ipv4", peer->ipv4),
        L("port", peer->port), L("err", errno));
    return (Error)errno;
  }
  peer->reader = reader_make_from_socket(socket_peer);
  peer->writer = writer_make_from_socket(socket_peer);

  log(LOG_LEVEL_INFO, "peer connected", arena, L("ipv4", peer->ipv4),
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

  ASSERT(68 == sb.len);
  return dyn_slice(String, sb);
}

[[nodiscard]] static Error peer_send_handshake(Peer *peer, String info_hash,
                                               Arena *arena) {
  String handshake = peer_make_handshake(info_hash, arena);
  Error err = writer_write_all(peer->writer, handshake);
  if (err) {
    log(LOG_LEVEL_ERROR, "peer handshake", arena, L("ipv4", peer->ipv4),
        L("port", peer->port), L("err", err));
    return err;
  }

  return 0;
}

[[maybe_unused]]
static void peer_run(Peer *peer, String info_hash, Arena *arena) {
  log(LOG_LEVEL_INFO, "running peer", arena, L("ipv4", peer->ipv4),
      L("port", peer->port));

  Error err = 0;

  if ((err = peer_send_handshake(peer, info_hash, arena))) {
    return;
  }

#if 0
  for (;;) {
    pause();
    // TODO
  }
#endif
}
