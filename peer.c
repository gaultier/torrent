#pragma once
#include "download.c"

// TODO: Timeouts.
// TODO: Timer-triggered keep-alives.
// TODO: Serve piece data.
// TODO: Retry on failure (with exp backoff?).

#include "submodules/cstd/lib.c"

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
  PeerMessage res;
} PeerMessageReadResult;

typedef struct {
  PgAllocator *allocator;
  PgIpv4Address address;
  u8 info_hash[PG_SHA1_DIGEST_LENGTH];
  PgLogger *logger;
  PgString remote_bitfield;
  bool remote_choked, remote_interested;
  bool local_choked, local_interested;
  bool remote_bitfield_received;
  Download *download;
  PeerState state;

  PieceDownloadDyn downloading_pieces;

  PgString piece_hashes;

  // TODO: Consider making libuv structs a pointer to reduce the size of the
  // Peer.
  uv_tcp_t uv_tcp;
  uv_connect_t uv_req_connect;

  PgRing recv;
  /* PgFile file; // TODO: Support multiple files. */
} Peer;

PG_DYN(Peer) PeerDyn;
PG_SLICE(Peer) PeerSlice;

static void pg_uv_alloc(uv_handle_t *handle, size_t suggested_size,
                        uv_buf_t *buf) {
  PG_ASSERT(handle);
  PG_ASSERT(handle->data);
  PG_ASSERT(buf);
  PgAllocator **allocator = handle->data;

  buf->base = pg_alloc(*allocator, sizeof(u8), _Alignof(u8), suggested_size);
  buf->len = suggested_size;
}

[[nodiscard]] static PgError peer_request_remote_data_maybe(Peer *peer);

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
peer_make(PgIpv4Address address, u8 info_hash[PG_SHA1_DIGEST_LENGTH],
          PgLogger *logger, Download *download, PgString piece_hashes,
          PgAllocator *allocator) {
  PG_ASSERT(piece_hashes.len == PG_SHA1_DIGEST_LENGTH * download->pieces_count);

  Peer peer = {0};
  peer.address = address;
  memcpy(peer.info_hash, info_hash, PG_SHA1_DIGEST_LENGTH);
  peer.logger = logger;
  peer.download = download;
  peer.piece_hashes = piece_hashes;
  peer.allocator = allocator;
  peer.remote_choked = true;
  peer.remote_interested = false;
  // TODO: Could do one big allocation for the Peer and then point
  // `remote_bitfield` to it + an offset.
  peer.remote_bitfield =
      pg_string_make(pg_div_ceil(download->pieces_count, 8), peer.allocator);
  PG_DYN_ENSURE_CAP(&peer.downloading_pieces,
                    download->concurrent_downloads_max, peer.allocator);
  PG_ASSERT(peer.downloading_pieces.cap > 0);

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

  // TODO: Could do one big allocation for the Peer and then point
  // `remote_bitfield` to it + an offset.
  pg_free(peer->allocator, peer->remote_bitfield.data,
          peer->remote_bitfield.len, 1);
  pg_free(peer->allocator, peer->downloading_pieces.data,
          peer->downloading_pieces.len, 1);
  pg_free(peer->allocator, peer, sizeof(*peer), 1);
}

static void peer_close_io_handles(Peer *peer) {
  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: start closing io handles",
         PG_L("address", peer->address));

  uv_close((uv_handle_t *)&peer->uv_tcp, peer_on_close);
}

[[nodiscard]] static PgError peer_read_handshake(Peer *peer) {
  PG_ASSERT(PEER_STATE_NONE == peer->state);

  u8 data[HANDSHAKE_LENGTH] = {0};
  PgString handshake = {
      .data = data,
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
  PgString info_hash = {.data = peer->info_hash, .len = PG_SHA1_DIGEST_LENGTH};
  if (!pg_string_eq(info_hash_received, info_hash)) {
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

static void peer_on_file_write(uv_fs_t *req) {
  PG_ASSERT(req->data);
  FsWriteRequest *fs_req = req->data;
  PG_ASSERT(fs_req->data);
  Peer *peer = fs_req->data;

  PG_ASSERT(fs_req->bufs_len > 0);

  u64 len = 0;
  for (u64 i = 0; i < fs_req->bufs_len; i++) {
    uv_buf_t buf = PG_C_ARRAY_AT(fs_req->bufs, fs_req->bufs_len, i);
    len += buf.len;
    pg_free(peer->allocator, buf.base, sizeof(u8), buf.len);
  }
  uv_fs_req_cleanup(req);
  pg_free(peer->allocator, fs_req, sizeof(FsWriteRequest), 1);

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: saved block data to disk",
         PG_L("address", peer->address), PG_L("len", len),
         PG_L("pieces_have_count", peer->download->pieces_have_count),
         PG_L("req.result", uv_fs_get_result(req)));
}

[[nodiscard]] static PgError peer_receive_block(Peer *peer,
                                                PeerMessagePiece msg) {
  PG_ASSERT(msg.data.len <= BLOCK_SIZE);
  PG_ASSERT(msg.data.len >= 0);

  BlockForDownloadIndex block_for_download = (BlockForDownloadIndex){
      (u32)(msg.index * peer->download->piece_length + msg.begin) / BLOCK_SIZE};
  PieceIndex piece = {msg.index};
  BlockForPieceIndex block_for_piece =
      download_convert_block_for_download_to_block_for_piece(
          peer->download, piece, block_for_download);

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: received piece message",
         PG_L("address", peer->address), PG_L("piece", piece.val),
         PG_L("begin", msg.begin), PG_L("data_len", msg.data.len));

  PieceDownload *pd = nullptr;
  u64 pd_index = 0;
  {
    PG_ASSERT(peer->downloading_pieces.len > 0);
    for (; pd_index < peer->downloading_pieces.len; pd_index++) {
      PieceDownload *it = PG_SLICE_AT_PTR(&peer->downloading_pieces, pd_index);
      if (it->piece.val == piece.val) {
        pd = it;
        break;
      }
    }
  }
  if (!pd) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: received unexpected block",
           PG_L("address", peer->address), PG_L("piece", piece.val),
           PG_L("begin", msg.begin), PG_L("data.len", msg.data.len),
           PG_L("block_for_download", block_for_download.val));
    return PG_ERR_INVALID_VALUE;
  }

  // From the spec:
  //
  // > It's possible for an unexpected piece to arrive if choke and unchoke
  // messages are sent in quick succession and/or transfer is going very slowly.
  //
  // In this case, ignore.
  if (pg_bitfield_get_ptr(pd->blocks_have, PG_STATIC_ARRAY_LEN(pd->blocks_have),
                          block_for_piece.val)) {
    pg_log(peer->logger, PG_LOG_LEVEL_DEBUG,
           "peer: received block we already have",
           PG_L("address", peer->address), PG_L("piece", piece.val),
           PG_L("begin", msg.begin), PG_L("data.len", msg.data.len),
           PG_L("block_for_download", block_for_download.val));
    return 0;
  }

  u32 blocks_count_for_piece =
      download_compute_blocks_count_for_piece(peer->download, pd->piece);
  PG_ASSERT(pd->block_downloads_len < blocks_count_for_piece);
  pd->block_downloads[pd->block_downloads_len++] = (BlockDownload){
      .data = msg.data,
      .block = block_for_piece,
  };

  pg_bitfield_set_ptr(pd->blocks_have, PG_STATIC_ARRAY_LEN(pd->blocks_have),
                      block_for_piece.val, true);
  PG_ASSERT(peer->download->pieces_have_count <= peer->download->pieces_count);

  PG_ASSERT(peer->download->concurrent_downloads_count > 0);
  peer->download->concurrent_downloads_count -= 1;

  if (pd->block_downloads_len < blocks_count_for_piece) {
    return 0;
  }

  // We have all blocks for this piece.
  PG_ASSERT(pd->block_downloads_len == blocks_count_for_piece);

  bool verified = download_verify_piece(peer->download, pd);
  if (!verified) {
    // TODO: Blacklist remote?
    return PG_ERR_INVALID_VALUE;
  }

  pg_bitfield_set(peer->download->pieces_have, piece.val, true);
  pg_bitfield_set(peer->download->pieces_downloading, piece.val, false);
  peer->download->pieces_have_count += 1;
  PG_ASSERT(peer->download->pieces_have_count <= peer->download->pieces_count);
  PG_SLICE_SWAP_REMOVE(&peer->downloading_pieces, pd_index);

  pg_log(peer->logger, PG_LOG_LEVEL_INFO, "peer: verified piece",
         PG_L("address", peer->address), PG_L("piece", piece.val),
         PG_L("pieces_count", peer->download->pieces_count));

  // Actual disk write here, the rest is just metadata bookkeeping/validation.

  FsWriteRequest *req = pg_alloc(peer->allocator, sizeof(FsWriteRequest),
                                 _Alignof(FsWriteRequest), 1);
  req->req.data = req;
  req->data = peer;
  for (u64 i = 0; i < pd->block_downloads_len; i++) {
    BlockDownload block_download =
        PG_C_ARRAY_AT(pd->block_downloads, pd->block_downloads_len, i);

    *PG_C_ARRAY_AT_PTR(req->bufs, PG_STATIC_ARRAY_LEN(req->bufs), i) =
        string_to_uv_buf(block_download.data);
    req->bufs_len += 1;

    // Check that they are in order.
    if (i > 0) {
      PG_ASSERT(
          block_download.block.val >
          PG_C_ARRAY_AT(pd->block_downloads, pd->block_downloads_len, i - 1)
              .block.val);
    }
  }

  u64 offset = (piece.val * peer->download->piece_length);
  PG_ASSERT(offset <= peer->download->total_file_size);

  int err_file =
      uv_fs_write(uv_default_loop(), &req->req, peer->download->file, req->bufs,
                  (u32)req->bufs_len, (i64)offset, peer_on_file_write);
  if (err_file) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR,
           "peer: failed to write piece to disk",
           PG_L("address", peer->address), PG_L("piece", piece.val),
           PG_L("begin", msg.begin), PG_L("data.len", msg.data.len),
           PG_L("err", err_file),
           PG_L("err_msg", pg_cstr_to_string((char *)uv_strerror(err_file))));
    // TODO: Retry?
    peer_close_io_handles(peer);
    return (PgError)err_file;
  }
  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: writing piece to disk",
         PG_L("address", peer->address), PG_L("piece", piece.val),
         PG_L("pieces_have_count", peer->download->pieces_have_count),
         PG_L("pieces_count", peer->download->pieces_count),
         PG_L("blocks_count", peer->download->blocks_count),
         PG_L("begin", msg.begin), PG_L("data_len", msg.data.len));

  // TODO: finish download when all pieces are there.

  return 0;
}

[[maybe_unused]] [[nodiscard]] static PgString
peer_encode_message(PeerMessage msg, PgAllocator *allocator) {

  Pgu8Dyn sb = {0};
  u64 cap = 17;
  if (msg.kind == PEER_MSG_KIND_BITFIELD) {
    cap += msg.bitfield.len;
  } else if (msg.kind == PEER_MSG_KIND_PIECE) {
    // OPTIMIZATION: download_compute_block_length.
    cap += BLOCK_SIZE;
  }
  PG_DYN_ENSURE_CAP(&sb, cap, allocator);

  switch (msg.kind) {
  case PEER_MSG_KIND_KEEP_ALIVE:
    pg_string_builder_append_u32_within_capacity(&sb, 0);
    break;

  case PEER_MSG_KIND_CHOKE:
  case PEER_MSG_KIND_UNCHOKE:
  case PEER_MSG_KIND_INTERESTED:
  case PEER_MSG_KIND_UNINTERESTED:
    pg_string_builder_append_u32_within_capacity(&sb, 1);
    *PG_DYN_PUSH_WITHIN_CAPACITY(&sb) = msg.kind;
    break;

  case PEER_MSG_KIND_HAVE:
    pg_string_builder_append_u32_within_capacity(&sb, 1 + sizeof(u32));
    *PG_DYN_PUSH_WITHIN_CAPACITY(&sb) = msg.kind;
    pg_string_builder_append_u32_within_capacity(&sb, msg.have);
    break;

  case PEER_MSG_KIND_BITFIELD:
    pg_string_builder_append_u32_within_capacity(&sb,
                                                 1 + (u32)msg.bitfield.len);
    *PG_DYN_PUSH_WITHIN_CAPACITY(&sb) = msg.kind;
    PG_DYN_APPEND_SLICE_WITHIN_CAPACITY(&sb, msg.bitfield);
    break;

  case PEER_MSG_KIND_REQUEST:
    pg_string_builder_append_u32_within_capacity(&sb, 1 + 3 * sizeof(u32));
    *PG_DYN_PUSH_WITHIN_CAPACITY(&sb) = msg.kind;
    pg_string_builder_append_u32_within_capacity(&sb, msg.request.index);
    pg_string_builder_append_u32_within_capacity(&sb, msg.request.begin);
    pg_string_builder_append_u32_within_capacity(&sb, msg.request.length);
    break;

  case PEER_MSG_KIND_PIECE:
    pg_string_builder_append_u32_within_capacity(
        &sb, 1 + 2 * sizeof(u32) + (u32)msg.piece.data.len);
    *PG_DYN_PUSH_WITHIN_CAPACITY(&sb) = msg.kind;
    pg_string_builder_append_u32_within_capacity(&sb, msg.piece.index);
    pg_string_builder_append_u32_within_capacity(&sb, msg.piece.begin);
    PG_DYN_APPEND_SLICE_WITHIN_CAPACITY(&sb, msg.piece.data);
    break;

  case PEER_MSG_KIND_CANCEL:
    pg_string_builder_append_u32_within_capacity(&sb, 1 + 3 * sizeof(u32));
    *PG_DYN_PUSH_WITHIN_CAPACITY(&sb) = msg.kind;
    pg_string_builder_append_u32_within_capacity(&sb, msg.cancel.index);
    pg_string_builder_append_u32_within_capacity(&sb, msg.cancel.begin);
    pg_string_builder_append_u32_within_capacity(&sb, msg.cancel.length);
    break;
  default:
    PG_ASSERT(0);
  }

  PG_ASSERT(sb.len >= sizeof(u32));

  PgString s = PG_DYN_SLICE(PgString, sb);
  return s;
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

  if (0 == length_announced) { // keep-alive?
    res.res.kind = PEER_MSG_KIND_KEEP_ALIVE;
  } else {
    PG_ASSERT(pg_ring_read_u8(&peer->recv, &res.res.kind));
  }

  switch (res.res.kind) {
  // No associated data.
  case PEER_MSG_KIND_KEEP_ALIVE:
  case PEER_MSG_KIND_CHOKE:
  case PEER_MSG_KIND_UNCHOKE:
  case PEER_MSG_KIND_INTERESTED:
  case PEER_MSG_KIND_UNINTERESTED:
    break;

  case PEER_MSG_KIND_HAVE: {
    if ((1 + sizeof(u32)) != length_announced) {
      res.err = PG_ERR_INVALID_VALUE;
      return res;
    }
    PG_ASSERT(pg_ring_read_u32(&peer->recv, &res.res.have));

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
    res.res.request.index = ntohl(index);
    res.res.request.begin = ntohl(begin);
    res.res.request.length = ntohl(data_length);

    break;
  }
  case PEER_MSG_KIND_PIECE: {
    if (length_announced < sizeof(res.res.kind) + 2 * sizeof(u32) ||
        length_announced >
            sizeof(res.res.kind) + 2 * sizeof(u32) + BLOCK_SIZE) {
      res.err = PG_ERR_INVALID_VALUE;
      return res;
    }
    u32 index = 0, begin = 0;
    PG_ASSERT(pg_ring_read_u32(&peer->recv, &index));
    PG_ASSERT(pg_ring_read_u32(&peer->recv, &begin));
    res.res.piece.index = ntohl(index);
    res.res.piece.begin = ntohl(begin);

    u32 data_len = length_announced -
                   (sizeof(res.res.kind) + sizeof(index) + sizeof(begin));

    // Validation.
    {
      PieceIndex piece_idx = {res.res.piece.index};

      if (res.res.piece.index >= peer->download->pieces_count) {
        res.err = PG_ERR_INVALID_VALUE;
        return res;
      }

      u32 blocks_count_for_piece =
          download_compute_blocks_count_for_piece(peer->download, piece_idx);
      if (res.res.piece.begin >= blocks_count_for_piece * BLOCK_SIZE) {
        res.err = PG_ERR_INVALID_VALUE;
        return res;
      }
      if (res.res.piece.begin % BLOCK_SIZE != 0) {
        res.err = PG_ERR_INVALID_VALUE;
        return res;
      }

      BlockForPieceIndex block_for_piece = {res.res.piece.begin / BLOCK_SIZE};
      if (block_for_piece.val >=
          download_compute_blocks_count_for_piece(peer->download, piece_idx)) {
        res.err = PG_ERR_INVALID_VALUE;
        return res;
      }

      u32 expected_data_len = download_compute_block_length(
          peer->download, block_for_piece, piece_idx);
      if (data_len != expected_data_len) {
        res.err = PG_ERR_INVALID_VALUE;
        return res;
      }
    }

    res.res.piece.data = pg_string_make(data_len, peer->allocator);
    PG_ASSERT(pg_ring_read_slice(&peer->recv, res.res.piece.data));

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
    res.res.cancel.index = ntohl(index);
    res.res.cancel.begin = ntohl(begin);
    res.res.cancel.length = ntohl(data_length);

    break;
  }
  default:
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: message unknown kind",
           PG_L("address", peer->address),
           PG_L("kind", peer_message_kind_to_string(res.res.kind)));
    res.err = PG_ERR_INVALID_VALUE;
    return res;
  }

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: received message",
         PG_L("address", peer->address),
         PG_L("length_announced", length_announced), PG_L("err", res.err),
         PG_L("err_s", pg_cstr_to_string(strerror((i32)res.err))),
         PG_L("kind", peer_message_kind_to_string(res.res.kind)),
         PG_L("recv_read_space", pg_ring_read_space(peer->recv)),
         PG_L("recv_write_space", pg_ring_write_space(peer->recv)));

  res.present = true;
  return res;
}

[[nodiscard]] static PgError peer_react_to_message(Peer *peer,
                                                   PeerMessage msg) {
  switch (msg.kind) {
  case PEER_MSG_KIND_CHOKE:
    peer->remote_choked = true;
    // TODO: Cancel on-going downloads?
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
    return peer_request_remote_data_maybe(peer);
  case PEER_MSG_KIND_BITFIELD:
    return peer_request_remote_data_maybe(peer);
  case PEER_MSG_KIND_REQUEST:
    // TODO
    break;
  case PEER_MSG_KIND_PIECE: {
    PgError err_receive = peer_receive_block(peer, msg.piece);
    if (err_receive) {
      return err_receive;
    }

    return peer_request_remote_data_maybe(peer);
  }
  case PEER_MSG_KIND_CANCEL:
    // TODO
    break;
  case PEER_MSG_KIND_KEEP_ALIVE:
    // TODO
    break;
  default:
    PG_ASSERT(0);
  }
  return 0;
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

      PgError err = peer_react_to_message(peer, res.res);
      if (err) {
        return err;
      }

      break;
    }
    default:
      PG_ASSERT(0);
    }
  }
  return 0;
}
static void peer_on_tcp_read(uv_stream_t *stream, ssize_t nread,
                             const uv_buf_t *buf) {
  PG_ASSERT(stream);
  PG_ASSERT(stream->data);
  PG_ASSERT(buf);

  Peer *peer = stream->data;

  if (nread < 0 && nread != UV_EOF) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to tcp read",
           PG_L("address", peer->address),
           PG_L("err", pg_cstr_to_string((char *)uv_strerror((i32)nread))));
    goto err;
  }
  PgString data = uv_buf_to_string(*buf);
  data.len = (u64)nread;

  if (0 == nread || nread == UV_EOF) {
    pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: tcp read EOF",
           PG_L("address", peer->address));
    // TODO: Should we still try to decode the last chunk of data (`buf`)?
    goto err;
  }

  PG_ASSERT(nread > 0);

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: tcp read ok",
         PG_L("address", peer->address), PG_L("nread", (u64)nread),
         PG_L("data", data));
  if (!pg_ring_write_slice(&peer->recv, data)) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: tcp read too big",
           PG_L("address", peer->address), PG_L("nread", (u64)nread),
           PG_L("recv_write_space", pg_ring_write_space(peer->recv)),
           PG_L("data", data));

    goto err;
  }

  PgError err_handle = peer_handle_recv_data(peer);
  if (err_handle) {
    goto err;
  }
  goto end;

err:
  peer_close_io_handles(peer);

end:
  pg_free(peer->allocator, buf->base, sizeof(u8), buf->len);
}

static void peer_on_tcp_write(uv_write_t *req, int status) {
  PG_ASSERT(req->data);
  WriteRequest *wq = req->data;
  PG_ASSERT(wq->data);
  Peer *peer = wq->data;

  u64 len = wq->buf.len;
  pg_free(peer->allocator, wq->buf.base, sizeof(u8), wq->buf.len);
  pg_free(peer->allocator, wq, sizeof(*wq), 1);

  if (status < 0) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to tcp write",
           PG_L("address", peer->address), PG_L("len", len),
           PG_L("err", pg_cstr_to_string((char *)uv_strerror(status))));
    peer_close_io_handles(peer);
    return;
  }

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: tcp write ok",
         PG_L("address", peer->address), PG_L("len", len));
}

[[nodiscard]] static PgError peer_ensure_local_interested(Peer *peer) {
  if (peer->local_interested) {
    return 0;
  }

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: announcing interest",
         PG_L("address", peer->address));

  PeerMessage msg = {.kind = PEER_MSG_KIND_INTERESTED};
  PgString msg_encoded = peer_encode_message(msg, peer->allocator);
  int err_write = do_write((uv_stream_t *)&peer->uv_tcp, msg_encoded,
                           peer->allocator, peer_on_tcp_write, peer);
  if (err_write < 0) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to tcp write",
           PG_L("address", peer->address),
           PG_L("err", pg_cstr_to_string((char *)uv_strerror(err_write))));
    peer_close_io_handles(peer);
    return (PgError)err_write;
  }

  // TODO: Should this be done in the callback `peer_on_tcp_write`?
  peer->local_interested = true;

  return 0;
}

[[nodiscard]] static PgError
peer_request_block(Peer *peer, BlockForDownloadIndex block_for_download) {
  PG_ASSERT(block_for_download.val < peer->download->blocks_count);
  PieceIndex piece =
      download_get_piece_for_block(peer->download, block_for_download);
  PG_ASSERT(piece.val < peer->download->pieces_count);
  PG_ASSERT(pg_bitfield_get(peer->remote_bitfield, piece.val));

  BlockForPieceIndex block_for_piece =
      download_convert_block_for_download_to_block_for_piece(
          peer->download, piece, block_for_download);

  u32 block_length =
      download_compute_block_length(peer->download, block_for_piece, piece);
  PG_ASSERT(block_length <= BLOCK_SIZE);
  PG_ASSERT(block_length > 0);

  PgError err_interested = peer_ensure_local_interested(peer);
  if (err_interested) {
    return err_interested;
  }

  PeerMessage msg = {
      .kind = PEER_MSG_KIND_REQUEST,
      .request =
          {
              .index = piece.val,
              .begin = block_for_piece.val * BLOCK_SIZE,
              .length = block_length,
          },
  };
  PG_ASSERT(msg.request.begin + msg.request.length <=
            peer->download->piece_length);

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "requesting block",
         PG_L("address", peer->address),
         PG_L("block_for_download", block_for_download.val),
         PG_L("block_for_piece", block_for_piece.val), PG_L("piece", piece.val),
         PG_L("begin", msg.request.begin), PG_L("block_length", block_length));

  PgString msg_encoded = peer_encode_message(msg, peer->allocator);
  int err_write = do_write((uv_stream_t *)&peer->uv_tcp, msg_encoded,
                           peer->allocator, peer_on_tcp_write, peer);
  if (err_write < 0) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to tcp write",
           PG_L("address", peer->address),
           PG_L("err", pg_cstr_to_string((char *)uv_strerror(err_write))));
    peer_close_io_handles(peer);
    return (PgError)err_write;
  }

  return 0;
}

[[nodiscard]] static PgError peer_request_remote_data_maybe(Peer *peer) {
  PG_ASSERT(peer->download->concurrent_downloads_count <=
            peer->download->concurrent_downloads_max);

  // TODO: Should we send 'interested' first?
  if (peer->remote_choked) {
    pg_log(peer->logger, PG_LOG_LEVEL_DEBUG,
           "peer: not requesting remote data since remote is choked",
           PG_L("address", peer->address));

    return 0;
  }

  u64 req_max = 16;

  for (u64 i = 0; i < req_max; i++) {

    if (peer->download->concurrent_downloads_count ==
        peer->download->concurrent_downloads_max) {
      pg_log(
          peer->logger, PG_LOG_LEVEL_DEBUG,
          "peer: not requesting remote data since max concurrent downloads is "
          "reached",
          PG_L("address", peer->address),
          PG_L("concurrent_downloads",
               peer->download->concurrent_downloads_count));

      return 0;
    }

    BlockForDownloadIndexOk res_block = download_pick_next_block(
        peer->download, peer->remote_bitfield, &peer->downloading_pieces);
    if (!res_block.ok) {
      pg_log(peer->logger, PG_LOG_LEVEL_DEBUG,
             "peer: not requesting remote data since all blocks are already "
             "downloaded",
             PG_L("address", peer->address));
      return 0;
    }

    peer->download->concurrent_downloads_count += 1;
    PG_ASSERT(peer->download->concurrent_downloads_count <=
              peer->download->concurrent_downloads_max);

    PgError err = peer_request_block(peer, res_block.res);
    if (err) {
      return err;
    }
  }
  return 0;
}

[[maybe_unused]] [[nodiscard]] static PgString
peer_make_handshake(u8 info_hash[PG_SHA1_DIGEST_LENGTH],
                    PgAllocator *allocator) {
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

  PgString info_hash_s = {.data = info_hash, .len = PG_SHA1_DIGEST_LENGTH};
  PG_DYN_APPEND_SLICE_WITHIN_CAPACITY(&sb, info_hash_s);

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
    peer_close_io_handles(peer);
    return;
  }

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: connected",
         PG_L("address", peer->address));

  PG_ASSERT(0 == peer->recv.data.len);
  peer->recv = pg_ring_make(2 * PG_KiB + 2 * BLOCK_SIZE, peer->allocator);

  PgString handshake = peer_make_handshake(peer->info_hash, peer->allocator);
  int err_write = do_write((uv_stream_t *)&peer->uv_tcp, handshake,
                           peer->allocator, peer_on_tcp_write, peer);
  if (err_write < 0) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to tcp write",
           PG_L("address", peer->address),
           PG_L("err", pg_cstr_to_string((char *)uv_strerror(err_write))));
    peer_close_io_handles(peer);
    return;
  }
  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: sending handshake",
         PG_L("address", peer->address));

  int err_read = uv_read_start((uv_stream_t *)&peer->uv_tcp, pg_uv_alloc,
                               peer_on_tcp_read);
  if (err_read < 0) {
    pg_log(peer->logger, PG_LOG_LEVEL_ERROR, "peer: failed to start tcp read",
           PG_L("address", peer->address),
           PG_L("err", pg_cstr_to_string((char *)uv_strerror(err_read))));
    peer_close_io_handles(peer);
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
    peer_close_io_handles(peer);
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
    peer_close_io_handles(peer);
    return (PgError)err_tcp_init;
  }

  pg_log(peer->logger, PG_LOG_LEVEL_DEBUG, "peer: started tcp connect",
         PG_L("address", peer->address));

  return 0;
}
