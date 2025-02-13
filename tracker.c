#pragma once

// TODO: Re-query tracker every N minutes.
// TODO: Retry on failure (with exp backoff?).
// TODO: Use `try` allocations.

#include "bencode.c"
#include "peer.c"

typedef enum {
  TRACKER_EVENT_STARTED,
  TRACKER_EVENT_STOPPED,
  TRACKER_EVENT_COMPLETED,
} TrackerMetadataEvent;

typedef struct {
  PgSha1 info_hash;
  u8 peer_id[20];
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
tracker_parse_compact_peers(PgString s, PgLogger *logger,
                            PgAllocator *allocator) {
  ParseCompactPeersResult res = {0};

  if (s.len % 6 != 0) {
    res.err = PG_ERR_INVALID_VALUE;
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
    *PG_DYN_PUSH(&res.peer_addresses, allocator) = address;
  }

  return res;
}

[[nodiscard]] static TrackerResponseResult
tracker_parse_bencode_response(PgString s, PgLogger *logger,
                               PgAllocator *allocator) {
  TrackerResponseResult res = {0};

  // TODO: Optimize memory usage with a temp arena.

  BencodeValueDecodeResult tracker_response_bencode_res =
      bencode_decode_value(s, 0, allocator);
  if (tracker_response_bencode_res.err) {
    res.err = tracker_response_bencode_res.err;
    return res;
  }
  if (tracker_response_bencode_res.remaining.len != 0) {
    res.err = PG_ERR_INVALID_VALUE;
    return res;
  }

  if (BENCODE_KIND_DICTIONARY != tracker_response_bencode_res.value.kind) {
    res.err = PG_ERR_INVALID_VALUE;
    return res;
  }

  BencodeKeyValueDyn dict = tracker_response_bencode_res.value.dict;

  for (u64 i = 0; i < dict.len; i++) {
    BencodeKeyValue kv = PG_SLICE_AT(dict, i);

    if (pg_string_eq(kv.key, PG_S("failure reason"))) {
      if (BENCODE_KIND_STRING != kv.value.kind) {
        res.err = PG_ERR_INVALID_VALUE;
        return res;
      }

      res.res.failure = kv.value.s;
    } else if (pg_string_eq(kv.key, PG_S("interval"))) {
      if (BENCODE_KIND_NUMBER != kv.value.kind) {
        res.err = PG_ERR_INVALID_VALUE;
        return res;
      }
      res.res.interval_secs = kv.value.num;
    } else if (pg_string_eq(kv.key, PG_S("peers"))) {
      if (BENCODE_KIND_STRING != kv.value.kind) {
        res.err = PG_ERR_INVALID_VALUE;
        return res; // TODO: Handle non-compact case i.e. BENCODE_LIST?
      }
      ParseCompactPeersResult res_parse_compact_peers =
          tracker_parse_compact_peers(kv.value.s, logger, allocator);

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
tracker_make_http_request(TrackerMetadata *req_tracker, PgArena *arena) {
  PgHttpRequest res = {0};
  res.method = HTTP_METHOD_GET;
  res.url = req_tracker->announce;

  PgArenaAllocator arena_allocator = pg_make_arena_allocator(arena);
  PgAllocator *allocator = pg_arena_allocator_as_allocator(&arena_allocator);

  PG_DYN_ENSURE_CAP(&res.url.query_parameters, 7, allocator);

  *PG_DYN_PUSH_WITHIN_CAPACITY(&res.url.query_parameters) = (PgKeyValue){
      .key = PG_S("info_hash"),
      .value =
          (PgString){
              .data = req_tracker->info_hash.data,
              .len = PG_STATIC_ARRAY_LEN(req_tracker->info_hash.data),
          },
  };
  *PG_DYN_PUSH_WITHIN_CAPACITY(&res.url.query_parameters) = (PgKeyValue){
      .key = PG_S("peer_id"),
      .value =
          (PgString){
              .data = req_tracker->peer_id,
              .len = PG_STATIC_ARRAY_LEN(req_tracker->peer_id),
          },
  };
  *PG_DYN_PUSH_WITHIN_CAPACITY(&res.url.query_parameters) = (PgKeyValue){
      .key = PG_S("port"),
      .value = pg_u64_to_string(req_tracker->port, allocator),
  };
  *PG_DYN_PUSH_WITHIN_CAPACITY(&res.url.query_parameters) = (PgKeyValue){
      .key = PG_S("uploaded"),
      .value = pg_u64_to_string(req_tracker->uploaded, allocator),
  };
  *PG_DYN_PUSH_WITHIN_CAPACITY(&res.url.query_parameters) = (PgKeyValue){
      .key = PG_S("downloaded"),
      .value = pg_u64_to_string(req_tracker->downloaded, allocator),
  };
  *PG_DYN_PUSH_WITHIN_CAPACITY(&res.url.query_parameters) = (PgKeyValue){
      .key = PG_S("left"),
      .value = pg_u64_to_string(req_tracker->left, allocator),
  };
  *PG_DYN_PUSH_WITHIN_CAPACITY(&res.url.query_parameters) = (PgKeyValue){
      .key = PG_S("event"),
      .value = tracker_metadata_event_to_string(req_tracker->event),
  };

  return res;
}

typedef enum {
  TRACKER_STATE_WILL_READ_HTTP_RESPONSE,
  TRACKER_STATE_WILL_READ_BODY,
  TRACKER_STATE_READ_BODY,
} TrackerState;

typedef struct {
  // FIXME: Only used to spawn peers. Use a pool instead.
  PgAllocator *allocator;
  PgLogger *logger;
  Configuration *cfg;
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
  uv_timer_t uv_tcp_timeout;
  uv_getaddrinfo_t uv_dns_req;

  // HTTP response.
  PgRing http_recv;
  u64 http_response_content_length;

  PgString piece_hashes;

} Tracker;

PG_RESULT(Tracker) TrackerResult;

[[maybe_unused]] [[nodiscard]]
static PgError tracker_init(Tracker *tracker, PgLogger *logger,
                            Configuration *cfg, PgString host, u16 port,
                            Download *download, PgString piece_hashes,
                            u16 port_torrent_ours, PgUrl announce_url,
                            PgSha1 info_hash, PgAllocator *allocator) {
  PG_ASSERT(piece_hashes.len == PG_SHA1_DIGEST_LENGTH * download->pieces_count);

  *tracker = (Tracker){0};
  tracker->logger = logger;
  tracker->cfg = cfg;
  tracker->host = host;
  tracker->port = port;
  tracker->download = download;
  tracker->piece_hashes = piece_hashes;
  tracker->allocator = allocator;

  tracker->metadata = (TrackerMetadata){
      .info_hash = info_hash,
      .port = port_torrent_ours,
      .left = download->total_size, // FIXME
      .event = TRACKER_EVENT_STARTED,
      .announce = announce_url,
  };

  tracker->uv_tcp_timeout.data = tracker;
  (void)uv_timer_init(uv_default_loop(), &tracker->uv_tcp_timeout);

  tracker->uv_tcp.data = tracker;
  int err_tcp_init = uv_tcp_init(uv_default_loop(), &tracker->uv_tcp);
  if (err_tcp_init < 0) {
    pg_log(logger, PG_LOG_LEVEL_ERROR, "tracker-> failed to tcp init",
           PG_L("port", port), PG_L("host", host));
    return (PgError)err_tcp_init;
  }

  // Need to hold the HTTP request and response simultaneously (currently).
  tracker->arena =
      pg_arena_make_from_virtual_mem(cfg->tracker_max_http_request_bytes +
                                     cfg->tracker_max_http_response_bytes);
  PgArenaAllocator arena_allocator = pg_make_arena_allocator(&tracker->arena);
  tracker->http_recv =
      pg_ring_make(cfg->tracker_max_http_request_bytes,
                   pg_arena_allocator_as_allocator(&arena_allocator));

  return 0;
}

[[nodiscard]] static PgBoolResult
tracker_read_http_response_body(Tracker *tracker) {
  PG_ASSERT(TRACKER_STATE_WILL_READ_BODY == tracker->state);

  PgBoolResult res = {0};
  PgArenaAllocator arena_allocator = pg_make_arena_allocator(&tracker->arena);
  PgAllocator *allocator = pg_arena_allocator_as_allocator(&arena_allocator);

  if (tracker->http_response_content_length != 0) {
    if (pg_ring_read_space(tracker->http_recv) ==
        tracker->http_response_content_length) {
      res.res = true;

      PgString s =
          pg_string_make(pg_ring_read_space(tracker->http_recv), allocator);
      PG_ASSERT(true == pg_ring_read_slice(&tracker->http_recv, s));

      TrackerResponseResult res_bencode =
          tracker_parse_bencode_response(s, tracker->logger, allocator);
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

      PgIpv4AddressSlice peers =
          PG_DYN_SLICE(PgIpv4AddressSlice, res_bencode.res.peer_addresses);

      for (u64 i = 0; i < peers.len; i++) {
        PgIpv4Address addr = PG_SLICE_AT(peers, i);
        pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG, "tracker: peer announced",
               PG_L("addr", addr), PG_L("host", tracker->host),
               PG_L("port", tracker->port));
        Peer *peer =
            pg_alloc(tracker->allocator, sizeof(Peer), _Alignof(Peer), 1);
        *peer = peer_make(addr, tracker->metadata.info_hash, tracker->logger,
                          tracker->download, tracker->piece_hashes,
                          tracker->allocator);

        PgError err_peer = peer_start(peer);
        if (err_peer) {
          continue;
        }
      }

      return res;
    }
  } else {
    PG_ASSERT(0 && "TODO");
  }

  return res;
}

[[nodiscard]] static PgError tracker_try_parse_http_response(Tracker *tracker) {
  PgArenaAllocator arena_allocator = pg_make_arena_allocator(&tracker->arena);
  PgAllocator *allocator = pg_arena_allocator_as_allocator(&arena_allocator);

  switch (tracker->state) {
  case TRACKER_STATE_WILL_READ_HTTP_RESPONSE: {
    PgHttpResponseReadResult res_http =
        pg_http_read_response(&tracker->http_recv, 128, allocator);
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
  uv_timer_stop(&tracker->uv_tcp_timeout);
  uv_cancel((uv_req_t *)&tracker->uv_dns_req);
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
    pg_free(tracker->allocator, buf->base, sizeof(u8), buf->len);
    tracker_close_io_handles(tracker);
    return;
  }
  PgString data = uv_buf_to_string(*buf);
  data.len = (u64)nread;

  if (0 == nread || nread == UV_EOF) {
    pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG, "tracker: tcp read EOF",
           PG_L("port", tracker->port));

    pg_free(tracker->allocator, buf->base, sizeof(u8), buf->len);

    PgError err_http = tracker_try_parse_http_response(tracker);
    if (err_http) {
      // TODO?
    }
    tracker_close_io_handles(tracker);
    return;
  }

  PG_ASSERT(nread > 0);

  pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG, "tracker: tcp read ok",
         PG_L("port", tracker->port), PG_L("nread", (u64)nread),
         PG_L("data", data));
  if (!pg_ring_write_slice(&tracker->http_recv, data)) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR, "tracker: tcp read too big",
           PG_L("port", tracker->port), PG_L("nread", (u64)nread),
           PG_L("recv_write_space", pg_ring_write_space(tracker->http_recv)),
           PG_L("data", data));

    pg_free(tracker->allocator, buf->base, sizeof(u8), buf->len);
    tracker_close_io_handles(tracker);
    return;
  }
  pg_free(tracker->allocator, buf->base, sizeof(u8), buf->len);

  PgError err_http = tracker_try_parse_http_response(tracker);
  if (err_http) {
    tracker_close_io_handles(tracker);
    return;
  }
}

static void tracker_on_tcp_write(uv_write_t *req, int err_write) {
  PG_ASSERT(req->data);
  WriteRequest *wq = req->data;
  PG_ASSERT(wq->data);
  Tracker *tracker = wq->data;

  u64 len = wq->buf.len;
  pg_free(tracker->allocator, wq->buf.base, sizeof(u8), wq->buf.len);
  pg_free(tracker->allocator, wq, sizeof(*wq), 1);

  if (err_write < 0) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR, "tracker: failed to tcp write",
           PG_L("port", tracker->port), PG_L("len", len),
           PG_L("err", err_write),
           PG_L("err_msg", pg_cstr_to_string((char *)uv_strerror(err_write))));
    tracker_close_io_handles(tracker);
    return;
  }

  pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG, "tracker: tcp write ok",
         PG_L("len", len), PG_L("port", tracker->port));

  int err_read = uv_read_start((uv_stream_t *)&tracker->uv_tcp, pg_uv_alloc,
                               tracker_on_tcp_read);
  if (err_read < 0) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
           "tracker: failed to start tcp read", PG_L("port", tracker->port),
           PG_L("err", err_read),
           PG_L("err_msg", pg_cstr_to_string((char *)uv_strerror(err_read))));
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
      tracker_make_http_request(&tracker->metadata, &tracker->arena);
  PgString http_req_s = pg_http_request_to_string(http_req, tracker->allocator);
  int err_write = do_write((uv_stream_t *)&tracker->uv_tcp, http_req_s,
                           tracker->allocator, tracker_on_tcp_write, tracker);

  if (err_write < 0) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR, "tracker: failed to tcp write",
           PG_L("port", tracker->port),
           PG_L("err", pg_cstr_to_string((char *)uv_strerror(err_write))));
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

static void tracker_on_timeout(uv_timer_t *timer) {
  PG_ASSERT(timer);
  PG_ASSERT(timer->data);
  Tracker *tracker = timer->data;

  // If all operations are finished in time, ok.
  if (TRACKER_STATE_READ_BODY == tracker->state) {
    uv_timer_stop(timer);
    return;
  }

  pg_log(tracker->logger, PG_LOG_LEVEL_ERROR, "tracker: timed out",
         PG_L("host", tracker->host), PG_L("port", tracker->port),
         PG_L("state", tracker->state));
  tracker_close_io_handles(tracker);

  // TODO: Start another timer to retry in X seconds?
}

[[maybe_unused]] static PgError tracker_start_dns_resolve(Tracker *tracker,
                                                          PgUrl url) {
  pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG, "tracker: dns resolving",
         PG_L("host", url.host), PG_L("port", url.port));

  tracker->uv_dns_req.data = tracker;
  PgArenaAllocator arena_allocator = pg_make_arena_allocator(&tracker->arena);
  PgAllocator *allocator = pg_arena_allocator_as_allocator(&arena_allocator);

  struct addrinfo hints = {0};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  int err_getaddrinfo = uv_getaddrinfo(
      uv_default_loop(), &tracker->uv_dns_req, tracker_on_dns_resolve,
      pg_string_to_cstr(url.host, allocator),
      pg_string_to_cstr(pg_u64_to_string(url.port, allocator), allocator),
      &hints);

  if (err_getaddrinfo < 0) {
    pg_log(
        tracker->logger, PG_LOG_LEVEL_ERROR,
        "tracker: failed to start dns resolving", PG_L("err", err_getaddrinfo),
        PG_L("host", url.host), PG_L("port", url.port),
        PG_L("err_s", pg_cstr_to_string((char *)uv_strerror(err_getaddrinfo))));
    return (PgError)-err_getaddrinfo;
  }

  u64 timeout_ms = pg_ns_to_ms(tracker->cfg->tracker_round_trip_timeout_ns);
  int err_timer = uv_timer_start(&tracker->uv_tcp_timeout, tracker_on_timeout,
                                 timeout_ms, 0);
  if (err_timer < 0) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
           "tracker: failed to start timeout timer", PG_L("host", url.host),
           PG_L("port", url.port),
           PG_L("err_s", pg_cstr_to_string((char *)uv_strerror(err_timer))));
    // Still continue as normal.
  }

  return 0;
}
