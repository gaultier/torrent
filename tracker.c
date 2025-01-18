#pragma once

// TODO: Re-query tracker every N minutes.
// TODO: Retry on failure (with exp backoff?).

#include "bencode.c"
#include "peer.c"

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

[[maybe_unused]] [[nodiscard]] static PgString
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

  u8 pg_sha1_hash[20] = {0};
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
      pg_log(logger, PG_LOG_LEVEL_INFO, "tracker_parse_compact_peers",
             PG_L("res.peer_addresses.len", res.peer_addresses.len),
             PG_L("address", address));
    }
    *PG_DYN_PUSH(&res.peer_addresses, arena) = address;
  }

  return res;
}

[[maybe_unused]] [[nodiscard]] static TrackerResponseResult
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
} TrackerState;

typedef struct {
  PgLogger *logger;
  TrackerState state;
  PgString host;
  u16 port;
  PgArena arena;
  TrackerMetadata metadata;
  PgEventLoop *loop;

  PgRing http_response_recv;
  u64 http_response_content_length;
} Tracker;

[[maybe_unused]] [[nodiscard]]
static Tracker tracker_make(PgLogger *logger, PgString host, u16 port,
                            TrackerMetadata metadata, PgEventLoop *loop) {
  Tracker tracker = {0};
  tracker.logger = logger;
  tracker.host = host;
  tracker.port = port;
  tracker.metadata = metadata;
  tracker.loop = loop;

  tracker.arena = pg_arena_make_from_virtual_mem(12 * PG_KiB);

  return tracker;
}

[[nodiscard]] [[maybe_unused]] static PgError
tracker_try_parse_http_response(Tracker *tracker) {
  PG_ASSERT(TRACKER_STATE_WILL_READ_HTTP_RESPONSE == tracker->state);

  PgHttpResponseReadResult res_http =
      pg_http_read_response(&tracker->http_response_recv, 128, &tracker->arena);
  if (res_http.err) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
           "tracker: failed to parse http response", PG_L("err", res_http.err));
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

  Pgu64Result res_content_length = pg_http_headers_parse_content_length(
      PG_DYN_SLICE(PgKeyValueSlice, resp.headers), tracker->arena);

  if (res_content_length.err) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
           "tracker: failed to parse http response content type",
           PG_L("err", res_http.err));
    return res_content_length.err;
  }

  pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG,
         "tracker: http response content length",
         PG_L("length", res_content_length.res));
  if (res_content_length.res > 0) {
    tracker->http_response_content_length = res_content_length.res;
  }

  tracker->state = TRACKER_STATE_WILL_READ_BODY;

  return 0;
}

[[nodiscard]] [[maybe_unused]] static PgBoolResult
tracker_read_http_response_body(Tracker *tracker) {
  PG_ASSERT(TRACKER_STATE_WILL_READ_BODY == tracker->state);

  PgBoolResult res = {0};

  if (tracker->http_response_content_length != 0) {
    if (pg_ring_read_space(tracker->http_response_recv) ==
        tracker->http_response_content_length) {
      res.res = true;

      PgString s = pg_string_make(
          pg_ring_read_space(tracker->http_response_recv), &tracker->arena);
      PG_ASSERT(true == pg_ring_read_slice(&tracker->http_response_recv, s));

      TrackerResponseResult res_bencode =
          tracker_parse_bencode_response(s, tracker->logger, &tracker->arena);
      if (res_bencode.err) {
        pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
               "tracker: failed to decode bencode response",
               PG_L("err", res_bencode.err), PG_L("bencoded", s));

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
      // TODO
      for (u64 i = 0; i < peers.len; i++) {
        PgIpv4Address addr = PG_SLICE_AT(peers, i);
        Peer *peer = calloc(sizeof(Peer), 1);
        *peer = peer_make(addr, tracker->metadata.info_hash, tracker->logger,
                          tracker->loop);

        PgError err_peer = peer_start(tracker->loop, peer);
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

[[maybe_unused]]
static void tracker_on_timer(PgEventLoop *loop, u64 os_handle, void *ctx) {

  Tracker *tracker = ctx;
  pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG, "tracker: timer triggered",
         PG_L("os_handle", os_handle));

  // TODO
  (void)loop;
}

[[maybe_unused]]
static void tracker_on_tcp_read(PgEventLoop *loop, u64 os_handle, void *ctx,
                                PgError io_err, PgString data) {
  PG_ASSERT(nullptr != ctx);
  Tracker *tracker = ctx;

  if (io_err) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR, "tracker: failed to tcp read",
           PG_L("err", io_err));
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

    Pgu64Result res_timer =
        pg_event_loop_timer_start(loop, PG_CLOCK_KIND_MONOTONIC,
                                  10 * PG_Seconds, tracker, tracker_on_timer);
    if (res_timer.err) {
      pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
             "tracker: failed to start timer", PG_L("err", err));
    }
  } break;
  default:
    PG_ASSERT(0);
    break;
  }
}

[[maybe_unused]]
static void tracker_on_tcp_write(PgEventLoop *loop, u64 os_handle, void *ctx,
                                 PgError err) {
  PG_ASSERT(nullptr != ctx);
  Tracker *tracker = ctx;

  if (err) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR, "tracker: failed to tcp write",
           PG_L("err", err));
    // TODO: stop event loop?
    (void)pg_event_loop_handle_close(loop, os_handle);
    return;
  }

  PgError err_read =
      pg_event_loop_read_start(loop, os_handle, tracker_on_tcp_read);
  if (err_read) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
           "tracker: failed to start tcp read", PG_L("err", err_read));
    // TODO: stop event loop?
    (void)pg_event_loop_handle_close(loop, os_handle);
    return;
  }

  tracker->http_response_recv = pg_ring_make(4096, &tracker->arena);
}

[[maybe_unused]]
static void tracker_on_dns_resolve(PgEventLoop *loop, u64 os_handle, void *ctx,
                                   PgError err, PgIpv4Address address) {
  PG_ASSERT(nullptr != ctx);
  Tracker *tracker = ctx;

  if (err) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
           "tracker: failed to dns resolve the announce url", PG_L("err", err));

    (void)pg_event_loop_handle_close(loop, os_handle);
    // TODO: Maybe stop the event loop?

    return;
  }

  pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG, "tracker: dns resolve successful",
         PG_L("address", address));

  {
    PgArena arena_tmp = tracker->arena;
    PgHttpRequest http_req =
        tracker_make_http_request(tracker->metadata, &arena_tmp);

    PgString http_req_s = pg_http_request_to_string(http_req, &arena_tmp);

    PgError err_write =
        pg_event_loop_write(loop, os_handle, http_req_s, tracker_on_tcp_write);
    if (err_write) {
      pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
             "tracker: failed to start tcp write", PG_L("err", err_write));
      (void)pg_event_loop_handle_close(loop, os_handle);
      // TODO: Maybe stop the event loop?
    }
  }
}
