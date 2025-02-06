#pragma once

// TODO: Re-query tracker every N minutes.
// TODO: Retry on failure (with exp backoff?).

#include "bencode.c"
#include "peer.c"

static PgString uv_buf_to_string(uv_buf_t buf) {
  return (PgString){.data = (u8 *)buf.base, .len = buf.len};
}

typedef enum {
  TRACKER_EVENT_STARTED,
  TRACKER_EVENT_STOPPED,
  TRACKER_EVENT_COMPLETED,
} TrackerMetadataEvent;

typedef struct {
  PgString info_hash;
  PgString peer_id;
  u32 ip;
  u16 port;
  u64 downloaded, uploaded, left;
  TrackerMetadataEvent event;
  PgUrl announce;
} TrackerMetadata;

[[nodiscard]] static PgString
tracker_metadata_event_to_string(TrackerMetadataEvent event) {
  switch (event) {
  case TRACKER_EVENT_STARTED:
    return PG_S("started");
  case TRACKER_EVENT_STOPPED:
    return PG_S("stopped");
  case TRACKER_EVENT_COMPLETED:
    return PG_S("completed");
  default:
    PG_ASSERT(0);
  }
}

[[maybe_unused]]
static void tracker_compute_info_hash(Metainfo metainfo, PgString hash,
                                      PgArena arena) {
  BencodeValue value = {.kind = BENCODE_KIND_DICTIONARY};

  *PG_DYN_PUSH(&value.dict.keys, &arena) = PG_S("length");
  *PG_DYN_PUSH(&value.dict.values, &arena) = (BencodeValue){
      .kind = BENCODE_KIND_NUMBER,
      .num = metainfo.length,
  };

  *PG_DYN_PUSH(&value.dict.keys, &arena) = PG_S("name");
  *PG_DYN_PUSH(&value.dict.values, &arena) = (BencodeValue){
      .kind = BENCODE_KIND_STRING,
      .s = metainfo.name,
  };

  *PG_DYN_PUSH(&value.dict.keys, &arena) = PG_S("piece length");
  *PG_DYN_PUSH(&value.dict.values, &arena) = (BencodeValue){
      .kind = BENCODE_KIND_NUMBER,
      .num = metainfo.piece_length,
  };

  *PG_DYN_PUSH(&value.dict.keys, &arena) = PG_S("pieces");
  *PG_DYN_PUSH(&value.dict.values, &arena) = (BencodeValue){
      .kind = BENCODE_KIND_STRING,
      .s = metainfo.pieces,
  };

  // TODO: Add unknown keys in `info`?

  Pgu8Dyn sb = {0};
  PgWriter w = pg_writer_make_from_string_builder(&sb, &arena);
  PG_ASSERT(0 == bencode_encode(value, &w, &arena));
  PgString encoded = PG_DYN_SLICE(PgString, sb);

  u8 pg_sha1_hash[PG_SHA1_DIGEST_LENGTH] = {0};
  pg_sha1(encoded, pg_sha1_hash);
  PG_ASSERT(sizeof(pg_sha1_hash) == hash.len);
  memcpy(hash.data, pg_sha1_hash, hash.len);
}

typedef struct {
  PgIpv4AddressDyn peer_addresses;
  PgString failure;
  u64 interval_secs;
} TrackerResponse;

PG_RESULT(TrackerResponse) TrackerResponseResult;

typedef struct {
  PgError err;
  PgIpv4AddressDyn peer_addresses;
} ParseCompactPeersResult;

[[nodiscard]] static ParseCompactPeersResult
tracker_parse_compact_peers(PgString s, PgLogger *logger, PgArena *arena) {
  ParseCompactPeersResult res = {0};

  if (s.len % 6 != 0) {
    res.err = TORR_ERR_COMPACT_PEERS_INVALID;
    return res;
  }

  PgString remaining = s;
  for (u64 lim = 0; lim < s.len; lim++) {
    if (0 == remaining.len) {
      break;
    }

    PgString ipv4_str = PG_SLICE_RANGE(remaining, 0, 4);
    PgString port_str = PG_SLICE_RANGE(remaining, 4, 6);

    remaining = PG_SLICE_RANGE_START(remaining, 6);

    u32 ipv4_network_order = 0;
    memcpy(&ipv4_network_order, ipv4_str.data, ipv4_str.len);

    u16 port_network_order = 0;
    memcpy(&port_network_order, port_str.data, port_str.len);

    PgIpv4Address address = {
        .ip = ntohl(ipv4_network_order),
        .port = ntohs(port_network_order),
    };

    {
      pg_log(logger, PG_LOG_LEVEL_DEBUG, "tracker_parse_compact_peers",
             PG_L("res.peer_addresses.len", res.peer_addresses.len),
             PG_L("address", address));
    }
    *PG_DYN_PUSH(&res.peer_addresses, arena) = address;
  }

  return res;
}

[[nodiscard]] static TrackerResponseResult
tracker_parse_bencode_response(PgString s, PgLogger *logger, PgArena *arena) {
  TrackerResponseResult res = {0};

  // TODO: Optimize memory usage with a temp arena.

  BencodeValueDecodeResult tracker_response_bencode_res =
      bencode_decode_value(s, arena);
  if (tracker_response_bencode_res.err) {
    res.err = tracker_response_bencode_res.err;
    return res;
  }
  if (tracker_response_bencode_res.remaining.len != 0) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }

  if (BENCODE_KIND_DICTIONARY != tracker_response_bencode_res.value.kind) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }

  BencodeDictionary dict = tracker_response_bencode_res.value.dict;

  for (u64 i = 0; i < dict.keys.len; i++) {
    PgString key = PG_SLICE_AT(dict.keys, i);
    BencodeValue value = PG_SLICE_AT(dict.values, i);

    if (pg_string_eq(key, PG_S("failure reason"))) {
      if (BENCODE_KIND_STRING != value.kind) {
        res.err = TORR_ERR_BENCODE_INVALID;
        return res;
      }

      res.res.failure = value.s;
    } else if (pg_string_eq(key, PG_S("interval"))) {
      if (BENCODE_KIND_NUMBER != value.kind) {
        res.err = TORR_ERR_BENCODE_INVALID;
        return res;
      }
      res.res.interval_secs = value.num;
    } else if (pg_string_eq(key, PG_S("peers"))) {
      if (BENCODE_KIND_STRING != value.kind) {
        res.err = TORR_ERR_BENCODE_INVALID;
        return res; // TODO: Handle non-compact case i.e. BENCODE_LIST?
      }
      ParseCompactPeersResult res_parse_compact_peers =
          tracker_parse_compact_peers(value.s, logger, arena);

      if (res_parse_compact_peers.err) {
        res.err = res_parse_compact_peers.err;
        return res;
      }
      res.res.peer_addresses = res_parse_compact_peers.peer_addresses;
    }
  }

  return res;
}

[[maybe_unused]] [[nodiscard]] static PgHttpRequest
tracker_make_http_request(TrackerMetadata req_tracker, PgArena *arena) {
  PgHttpRequest res = {0};
  res.method = HTTP_METHOD_GET;
  res.url = req_tracker.announce;
  *PG_DYN_PUSH(&res.url.query_parameters, arena) = (PgKeyValue){
      .key = PG_S("info_hash"),
      .value = req_tracker.info_hash,
  };
  *PG_DYN_PUSH(&res.url.query_parameters, arena) = (PgKeyValue){
      .key = PG_S("peer_id"),
      .value = req_tracker.peer_id,
  };
  *PG_DYN_PUSH(&res.url.query_parameters, arena) = (PgKeyValue){
      .key = PG_S("port"),
      .value = pg_u64_to_string(req_tracker.port, arena),
  };
  *PG_DYN_PUSH(&res.url.query_parameters, arena) = (PgKeyValue){
      .key = PG_S("uploaded"),
      .value = pg_u64_to_string(req_tracker.uploaded, arena),
  };
  *PG_DYN_PUSH(&res.url.query_parameters, arena) = (PgKeyValue){
      .key = PG_S("downloaded"),
      .value = pg_u64_to_string(req_tracker.downloaded, arena),
  };
  *PG_DYN_PUSH(&res.url.query_parameters, arena) = (PgKeyValue){
      .key = PG_S("left"),
      .value = pg_u64_to_string(req_tracker.left, arena),
  };
  *PG_DYN_PUSH(&res.url.query_parameters, arena) = (PgKeyValue){
      .key = PG_S("event"),
      .value = tracker_metadata_event_to_string(req_tracker.event),
  };

  return res;
}

typedef enum {
  TRACKER_STATE_WILL_READ_HTTP_RESPONSE,
  TRACKER_STATE_WILL_READ_BODY,
  TRACKER_STATE_READ_BODY,
} TrackerState;

typedef struct {
  PgLogger *logger;
  TrackerState state;
  PgString host;
  u16 port;
  PgArena arena;
  TrackerMetadata metadata;
  Download *download;

  // libuv.
  uv_tcp_t uv_tcp;
  uv_connect_t uv_req_connect;
  uv_write_t uv_req_write;

  // HTTP response.
  PgRing http_recv;
  u64 http_response_content_length;

  // Options to spawn peers.
  // TODO: Decouple from tracker.
  u64 concurrent_pieces_download_max;
  u64 concurrent_blocks_download_max;
  PgString piece_hashes;
} Tracker;

static void tracker_uv_alloc(uv_handle_t *handle, size_t suggested_size,
                             uv_buf_t *buf) {
  PG_ASSERT(handle);
  PG_ASSERT(handle->data);
  PG_ASSERT(buf);

  // TODO: Maybe there is a clever way to hand out to libuv the correct part of
  // the ring buffer `http_recv` directly instead of allocating + copying.
  buf->base = malloc(suggested_size);
  buf->len = suggested_size;
}

[[maybe_unused]] [[nodiscard]]
static Tracker tracker_make(PgLogger *logger, PgString host, u16 port,
                            TrackerMetadata metadata, Download *download,
                            u64 concurrent_pieces_download_max,
                            u64 concurrent_blocks_download_max,
                            PgString piece_hashes) {
  PG_ASSERT(PG_SHA1_DIGEST_LENGTH == metadata.info_hash.len);
  PG_ASSERT(piece_hashes.len == PG_SHA1_DIGEST_LENGTH * download->pieces_count);

  Tracker tracker = {0};
  tracker.logger = logger;
  tracker.host = host;
  tracker.port = port;
  tracker.metadata = metadata;
  tracker.download = download;
  tracker.concurrent_pieces_download_max = concurrent_pieces_download_max;
  tracker.concurrent_blocks_download_max = concurrent_blocks_download_max;
  tracker.piece_hashes = piece_hashes;

  // Need to hold the HTTP request and response simultaneously (currently).
  tracker.arena = pg_arena_make_from_virtual_mem(32 * PG_KiB);
  tracker.http_recv = pg_ring_make(16 * PG_KiB, &tracker.arena);

  return tracker;
}

[[nodiscard]] static PgBoolResult
tracker_read_http_response_body(Tracker *tracker) {
  PG_ASSERT(TRACKER_STATE_WILL_READ_BODY == tracker->state);

  PgBoolResult res = {0};

  if (tracker->http_response_content_length != 0) {
    if (pg_ring_read_space(tracker->http_recv) ==
        tracker->http_response_content_length) {
      res.res = true;

      PgString s = pg_string_make(pg_ring_read_space(tracker->http_recv),
                                  &tracker->arena);
      PG_ASSERT(true == pg_ring_read_slice(&tracker->http_recv, s));

      TrackerResponseResult res_bencode =
          tracker_parse_bencode_response(s, tracker->logger, &tracker->arena);
      if (res_bencode.err) {
        pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
               "tracker: failed to decode bencode response",
               PG_L("err", res_bencode.err),
               PG_L("err_s", pg_cstr_to_string(strerror((i32)res_bencode.err))),
               PG_L("bencoded", s));

        res.err = res_bencode.err;
        return res;
      }

      pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG,
             "tracker: decoded bencode response",
             PG_L("failure_reason", res_bencode.res.failure),
             PG_L("peers.len", res_bencode.res.peer_addresses.len),
             PG_L("interval_secs", res_bencode.res.interval_secs));

#if 0
      PgIpv4AddressSlice peers =
          PG_DYN_SLICE(PgIpv4AddressSlice, res_bencode.res.peer_addresses);
      // TODO
      for (u64 i = 0; i < peers.len; i++) {
        PgIpv4Address addr = PG_SLICE_AT(peers, i);
        Peer *peer = calloc(sizeof(Peer), 1);
        *peer = peer_make(addr, tracker->metadata.info_hash, tracker->logger,
                          tracker->download, tracker->loop,
                          tracker->concurrent_pieces_download_max,
                          tracker->concurrent_blocks_download_max,
                          tracker->piece_hashes, tracker->download->file);

        PgError err_peer = peer_start(tracker->loop, peer);
        if (err_peer) {
          continue;
        }
      }
#endif

      return res;
    }
  } else {
    PG_ASSERT(0 && "TODO");
  }

  return res;
}

[[nodiscard]] static PgError tracker_try_parse_http_response(Tracker *tracker) {
  switch (tracker->state) {
  case TRACKER_STATE_WILL_READ_HTTP_RESPONSE: {
    PgHttpResponseReadResult res_http =
        pg_http_read_response(&tracker->http_recv, 128, &tracker->arena);
    if (res_http.err) {
      pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
             "tracker: failed to parse http response",
             PG_L("err", res_http.err),
             PG_L("err_s", pg_cstr_to_string(strerror((i32)res_http.err))));
      return res_http.err;
    }

    if (!res_http.done) {
      // Keep reading more.
      return 0;
    }

    PgHttpResponse resp = res_http.res;
    pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG, "tracker: read http response",
           PG_L("resp.status", resp.status),
           PG_L("resp.version_major", (u64)resp.version_major),
           PG_L("resp.version_minor", (u64)resp.version_minor),
           PG_L("resp.headers.len", resp.headers.len));

    PgU64Result res_content_length = pg_http_headers_parse_content_length(
        PG_DYN_SLICE(PgKeyValueSlice, resp.headers), tracker->arena);

    if (res_content_length.err) {
      pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
             "tracker: failed to parse http response content type",
             PG_L("err", res_http.err),
             PG_L("err_s", pg_cstr_to_string(strerror((i32)res_http.err))));
      return res_content_length.err;
    }

    pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG,
           "tracker: http response content length",
           PG_L("length", res_content_length.res));
    if (res_content_length.res > 0) {
      tracker->http_response_content_length = res_content_length.res;
    }

    tracker->state = TRACKER_STATE_WILL_READ_BODY;

    if (pg_ring_read_space(tracker->http_recv) <=
        tracker->http_response_content_length) {
      return 0;
    }

    [[fallthrough]];
  }
  case TRACKER_STATE_WILL_READ_BODY: {
    PgBoolResult res_body = tracker_read_http_response_body(tracker);
    if (res_body.err) {
      return res_body.err;
    }
    tracker->state = TRACKER_STATE_READ_BODY;
  } break;
  case TRACKER_STATE_READ_BODY: {
    PG_ASSERT(0 && "unreachable");
  }
  default:
    PG_ASSERT(0);
  }

  return 0;
}

#if 0
static void tracker_on_tcp_read(PgEventLoop *loop, PgOsHandle os_handle,
                                void *ctx, PgError io_err, PgString data) {
  PG_ASSERT(nullptr != ctx);
  Tracker *tracker = ctx;

  if (io_err) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR, "tracker: failed to tcp read",
           PG_L("err", io_err),
           PG_L("err_s", pg_cstr_to_string(strerror((i32)io_err))));
    // TODO: stop event loop?
    (void)pg_event_loop_handle_close(loop, os_handle);
    return;
  }

  pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG, "tracker: tcp read",
         PG_L("data", data));

  if (!pg_ring_write_slice(&tracker->http_response_recv, data)) {
    pg_log(
        tracker->logger, PG_LOG_LEVEL_ERROR, "tracker: http response too big",
        PG_L("data.len", data.len),
        PG_L("write_space", pg_ring_write_space(tracker->http_response_recv)));
    // TODO: stop event loop?
    (void)pg_event_loop_handle_close(loop, os_handle);
    return;
  }

  PgError err = 0;
  switch (tracker->state) {
  case TRACKER_STATE_WILL_READ_HTTP_RESPONSE:
    err = tracker_try_parse_http_response(tracker);
    if (err) {
      // TODO: stop event loop?
      (void)pg_event_loop_handle_close(loop, os_handle);
    }
    break;
  case TRACKER_STATE_WILL_READ_BODY: {
    PgBoolResult res_body = tracker_read_http_response_body(tracker);
    // TODO: Reset the tracker to the initial state, setup a timer for X minutes
    // to re-trigger the tracker fetch state machine.

    (void)res_body;
    (void)pg_event_loop_handle_close(loop, os_handle);

    // TODO.
    Pgu64Result res_timer = pg_event_loop_timer_start(
        loop, PG_CLOCK_KIND_MONOTONIC, 10 * PG_Seconds, 0 * PG_Seconds, tracker,
        tracker_on_timer);
    if (res_timer.err) {
      pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
             "tracker: failed to start timer", PG_L("err", err),
             PG_L("err_s", pg_cstr_to_string(strerror((i32)err))));
    }
  } break;
  default:
    PG_ASSERT(0);
    break;
  }
}
#endif

static void tracker_on_close(uv_handle_t *handle) {
  (void)handle;
  PG_ASSERT(handle->data);
  Tracker *tracker = handle->data;

  pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG, "tracker: closed io handles",
         PG_L("port", tracker->port));

  // TODO: Kick-start a retry here?
}

static void tracker_close_io_handles(Tracker *tracker) {
  pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG,
         "tracker: start closing io handles", PG_L("port", tracker->port));

  uv_close((uv_handle_t *)&tracker->uv_tcp, tracker_on_close);
  return;
}

static void tracker_on_tcp_read(uv_stream_t *stream, ssize_t nread,
                                const uv_buf_t *buf) {
  PG_ASSERT(stream);
  PG_ASSERT(stream->data);
  PG_ASSERT(buf);

  Tracker *tracker = stream->data;

  if (nread < 0 && nread != UV_EOF) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR, "tracker: failed to tcp read",
           PG_L("port", tracker->port),
           PG_L("err", pg_cstr_to_string((char *)uv_strerror((i32)nread))));
    tracker_close_io_handles(tracker);
    return;
  }
  PgString data = uv_buf_to_string(*buf);
  data.len = (u64)nread;

  if (0 == nread || nread == UV_EOF) {
    pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG, "tracker: tcp read EOF",
           PG_L("port", tracker->port));
    PgError err_http = tracker_try_parse_http_response(tracker);
    if (err_http) {
      // TODO?
    }
    tracker_close_io_handles(tracker);
    return;
  }

  if (nread > 0) {
    pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG, "tracker: tcp read ok",
           PG_L("port", tracker->port), PG_L("nread", (u64)nread),
           PG_L("data", data));
    if (!pg_ring_write_slice(&tracker->http_recv, data)) {
      pg_log(tracker->logger, PG_LOG_LEVEL_ERROR, "tracker: tcp read too big",
             PG_L("port", tracker->port), PG_L("nread", (u64)nread),
             PG_L("recv_write_space", pg_ring_write_space(tracker->http_recv)),
             PG_L("data", data));

      tracker_close_io_handles(tracker);
      return;
    }

    PgError err_http = tracker_try_parse_http_response(tracker);
    if (err_http) {
      tracker_close_io_handles(tracker);
      return;
    }

    // TODO: read body.
  }
}

static void tracker_on_tcp_write(uv_write_t *req, int status) {
  PG_ASSERT(req->handle);
  PG_ASSERT(req->handle->data);
  Tracker *tracker = req->handle->data;

  if (status < 0) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR, "tracker: failed to tcp write",
           PG_L("port", tracker->port),
           PG_L("err", pg_cstr_to_string((char *)uv_strerror(status))));
    tracker_close_io_handles(tracker);
    return;
  }

  pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG, "tracker: tcp write ok",
         PG_L("port", tracker->port));

  int err_read = uv_read_start((uv_stream_t *)&tracker->uv_tcp,
                               tracker_uv_alloc, tracker_on_tcp_read);
  if (err_read < 0) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
           "tracker: failed to start tcp read", PG_L("port", tracker->port),
           PG_L("err", pg_cstr_to_string((char *)uv_strerror(status))));
    tracker_close_io_handles(tracker);
    return;
  }
}

static void tracker_on_tcp_connect(uv_connect_t *req, int status) {
  PG_ASSERT(req->data);
  Tracker *tracker = req->data;

  if (status < 0) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
           "tracker: failed to tcp connect", PG_L("port", tracker->port),
           PG_L("err", pg_cstr_to_string((char *)uv_strerror(status))));
    tracker_close_io_handles(tracker);
    return;
  }

  pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG, "tracker: tcp connect ok",
         PG_L("port", tracker->port));

  PgHttpRequest http_req =
      tracker_make_http_request(tracker->metadata, &tracker->arena);
  PgString http_req_s = pg_http_request_to_string(http_req, &tracker->arena);

  // TODO: Consider if we can send the http request as multiple buffers to spare
  // an allocation?
  const uv_buf_t buf = {.base = (char *)http_req_s.data, .len = http_req_s.len};

  int err_write =
      uv_write(&tracker->uv_req_write, (uv_stream_t *)&tracker->uv_tcp, &buf, 1,
               tracker_on_tcp_write);
  if (err_write < 0) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
           "tracker: failed to tcp connect", PG_L("port", tracker->port),
           PG_L("err", pg_cstr_to_string((char *)uv_strerror(status))));
    tracker_close_io_handles(tracker);
    return;
  }
}

static void tracker_on_dns_resolve(uv_getaddrinfo_t *req, int status,
                                   struct addrinfo *res) {
  PG_ASSERT(req);
  PG_ASSERT(req->data);
  Tracker *tracker = req->data;

  if (status < 0) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
           "tracker: failed to dns resolve the announce url",
           PG_L("port", tracker->port), PG_L("err", status),
           PG_L("err_s", pg_cstr_to_string((char *)uv_strerror(status))));

    uv_freeaddrinfo(res);
    tracker_close_io_handles(tracker);
    return;
  }

  char human_readable_ip[256] = {0};
  uv_ip_name(res->ai_addr, human_readable_ip,
             PG_STATIC_ARRAY_LEN(human_readable_ip));

  pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG, "tracker: dns resolve successful",
         PG_L("port", tracker->port),
         PG_L("address", pg_cstr_to_string(human_readable_ip)));

  int err_tcp_init = uv_tcp_init(req->loop, &tracker->uv_tcp);
  if (err_tcp_init < 0) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR, "tracker: failed to tcp init",
           PG_L("port", tracker->port),
           PG_L("address", pg_cstr_to_string(human_readable_ip)));
    uv_freeaddrinfo(res);
    tracker_close_io_handles(tracker);
    return;
  }
  tracker->uv_tcp.data = tracker;
  tracker->uv_req_connect.data = tracker;

  if (res->ai_addr->sa_family == AF_INET) {
    struct sockaddr_in *addr = (struct sockaddr_in *)(void *)res->ai_addr;
    addr->sin_port = htons(tracker->port);
  } else {
    struct sockaddr_in6 *addr = (struct sockaddr_in6 *)(void *)res->ai_addr;
    addr->sin6_port = htons(tracker->port);
  }
  int err_tcp_connect =
      uv_tcp_connect(&tracker->uv_req_connect, &tracker->uv_tcp, res->ai_addr,
                     tracker_on_tcp_connect);
  if (err_tcp_connect < 0) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
           "tracker: failed to start tcp connect",
           PG_L("address", pg_cstr_to_string(human_readable_ip)),
           PG_L("port", tracker->port));
    uv_freeaddrinfo(res);
    tracker_close_io_handles(tracker);
    return;
  }

  pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG, "tracker: started tcp connect",
         PG_L("port", tracker->port),
         PG_L("address", pg_cstr_to_string(human_readable_ip)));
  uv_freeaddrinfo(res);
}
