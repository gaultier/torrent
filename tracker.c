#pragma once
#include "bencode.c"

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
  bencode_encode(value, &sb, &arena);
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

    PgString pg_net_ipv4_str = PG_SLICE_RANGE(remaining, 0, 4);
    PgString port_str = PG_SLICE_RANGE(remaining, 4, 6);

    remaining = PG_SLICE_RANGE_START(remaining, 6);

    u32 pg_net_ipv4_network_order = 0;
    memcpy(&pg_net_ipv4_network_order, pg_net_ipv4_str.data,
           pg_net_ipv4_str.len);

    u16 port_network_order = 0;
    memcpy(&port_network_order, port_str.data, port_str.len);

    PgIpv4Address address = {
        .ip = ntohl(pg_net_ipv4_network_order),
        .port = ntohs(port_network_order),
    };

    {
      PgString pg_net_ipv4_addr_str =
          pg_net_ipv4_address_to_string(address, arena);
      pg_log(logger, PG_LOG_LEVEL_INFO, "tracker_parse_compact_peers", *arena,
             PG_L("res.peer_addresses.len", res.peer_addresses.len),
             PG_L("ip", address.ip), PG_L("port", address.port),
             PG_L("address", pg_net_ipv4_addr_str));
    }
    *PG_DYN_PUSH(&res.peer_addresses, arena) = address;
  }

  return res;
}

[[maybe_unused]] [[nodiscard]] static TrackerResponseResult
tracker_parse_response(PgString s, PgLogger *logger, PgArena *arena) {
  TrackerResponseResult res = {0};

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
  TRACKER_STATE_NONE,
  TRACKER_STATE_SENT_REQUEST,
  TRACKER_STATE_RECEIVED_RESPONSE,
} TrackerState;

typedef struct {
  PgLogger *logger;
  TrackerState state;
  PgString host;
  u16 port;
  PgArena arena;
  TrackerMetadata metadata;
} Tracker;

[[maybe_unused]] [[nodiscard]]
static Tracker tracker_make(PgLogger *logger, PgString host, u16 port,
                            TrackerMetadata metadata) {
  Tracker tracker = {0};
  tracker.logger = logger;
  tracker.host = host;
  tracker.port = port;
  tracker.metadata = metadata;

  tracker.arena = pg_arena_make_from_virtual_mem(4 * PG_KiB);

  return tracker;
}
[[maybe_unused]]
static void tracker_on_tcp_read(PgEventLoop *loop, u64 os_handle, void *ctx,
                                PgError err, PgString data) {
  PG_ASSERT(nullptr != ctx);
  Tracker *tracker = ctx;

  if (err) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR, "tracker: failed to tcp read",
           tracker->arena, PG_L("err", err));
    // TODO: stop event loop?
    (void)pg_event_loop_handle_close(loop, os_handle);
    return;
  }

  pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG, "tracker: tcp read",
         tracker->arena, PG_L("data", data));

  // TODO: Parse http.
}

[[maybe_unused]]
static void tracker_on_tcp_write(PgEventLoop *loop, u64 os_handle, void *ctx,
                                 PgError err) {
  PG_ASSERT(nullptr != ctx);
  Tracker *tracker = ctx;

  if (err) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR, "tracker: failed to tcp write",
           tracker->arena, PG_L("err", err));
    // TODO: stop event loop?
    (void)pg_event_loop_handle_close(loop, os_handle);
    return;
  }

  PgError err_read =
      pg_event_loop_read_start(loop, os_handle, tracker_on_tcp_read);
  if (err_read) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
           "tracker: failed to start tcp read", tracker->arena,
           PG_L("err", err_read));
    // TODO: stop event loop?
    (void)pg_event_loop_handle_close(loop, os_handle);
    return;
  }
}

[[maybe_unused]]
static void tracker_on_dns_resolve(PgEventLoop *loop, u64 os_handle, void *ctx,
                                   PgError err, PgIpv4Address address) {
  PG_ASSERT(nullptr != ctx);
  Tracker *tracker = ctx;

  if (err) {
    pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
           "tracker: failed to dns resolve the announce url", tracker->arena,
           PG_L("err", err));

    (void)pg_event_loop_handle_close(loop, os_handle);
    // TODO: Maybe stop the event loop?

    return;
  }

  pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG, "tracker: dns resolve successful",
         tracker->arena, PG_L("ip", address.ip), PG_L("port", address.port));

  {
    PgArena arena_tmp = tracker->arena;
    PgHttpRequest http_req =
        tracker_make_http_request(tracker->metadata, &arena_tmp);

    PgString http_req_s = pg_http_request_to_string(http_req, &arena_tmp);

    PgError err_write =
        pg_event_loop_write(loop, os_handle, http_req_s, tracker_on_tcp_write);
    if (err_write) {
      pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
             "tracker: failed to start tcp write", tracker->arena,
             PG_L("err", err_write));
      (void)pg_event_loop_handle_close(loop, os_handle);
      // TODO: Maybe stop the event loop?
    }
  }
}

#if 0
[[maybe_unused]] [[nodiscard]]
static PgError tracker_handle_event(Tracker *tracker, PgAioEvent event_watch,
                                    PgAioEventDyn *events_change,
                                    PgArena *events_arena) {

  switch (tracker->state) {
  case TRACKER_STATE_NONE: {
    if (0 == (PG_AIO_EVENT_KIND_OUT & event_watch.kind)) {
      // Failed to connect or invalid API use.
      return (PgError)PG_ERR_INVALID_VALUE;
    }

    {
      PgArena pg_arena_tmp = tracker->arena;
      PgHttpRequest tracker_http_req =
          tracker_make_http_request(tracker->metadata, &pg_arena_tmp);
      PgError err =
          pg_http_write_request(&tracker->rg, tracker_http_req, pg_arena_tmp);
      PG_ASSERT(!err); // Ring buffer too small.
    }

    pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG,
           "wrote http request to ring buffer", tracker->arena,
           PG_L("write_space", pg_ring_write_space(tracker->rg)),
           PG_L("read_space", pg_ring_read_space(tracker->rg)));

    tracker->state = TRACKER_STATE_SENT_REQUEST;

    *PG_DYN_PUSH(events_change, events_arena) = (PgAioEvent){
        .kind = PG_AIO_EVENT_KIND_IN,
        .os_handle = (u64)tracker->socket,
        .action = PG_AIO_EVENT_ACTION_MOD,
    };
  } break;
  case TRACKER_STATE_SENT_REQUEST: {
    PgArena pg_arena_tmp = tracker->arena;
    PgHttpResponseReadResult res_http =
        pg_http_read_response(&tracker->rg, 128, &pg_arena_tmp);
    if (res_http.err) {
      pg_log(tracker->logger, PG_LOG_LEVEL_ERROR,
             "invalid tracker http response", pg_arena_tmp,
             PG_L("err", res_http.err));
      return res_http.err;
    }
    pg_log(tracker->logger, PG_LOG_LEVEL_DEBUG, "read http tracker response",
           pg_arena_tmp, PG_L("http.status", res_http.res.status));
    tracker->state = TRACKER_STATE_RECEIVED_RESPONSE;

    *PG_DYN_PUSH(events_change, events_arena) = (PgAioEvent){
        .os_handle = (u64)tracker->socket,
        .action = PG_AIO_EVENT_ACTION_DEL,
    };
  } break;
  case TRACKER_STATE_RECEIVED_RESPONSE: {

    // TODO: timer of ~1m to retrigger the state machine from the start.
  } break;
  default:
    PG_ASSERT(0);
    break;
  }
  return (PgError)0;
}
#endif
