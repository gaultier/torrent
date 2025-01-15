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
  Url announce;
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
tracker_parse_compact_peers(PgString s, Logger *logger, PgArena *arena) {
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
    memcpy(&pg_net_ipv4_network_order, pg_net_ipv4_str.data, pg_net_ipv4_str.len);

    u16 port_network_order = 0;
    memcpy(&port_network_order, port_str.data, port_str.len);

    PgIpv4Address address = {
        .ip = ntohl(pg_net_ipv4_network_order),
        .port = ntohs(port_network_order),
    };

    {
      PgString pg_net_ipv4_addr_str = pg_net_ipv4_address_to_string(address, arena);
      logger_log(logger, LOG_LEVEL_INFO, "tracker_parse_compact_peers", *arena,
                 L("res.peer_addresses.len", res.peer_addresses.len),
                 L("ip", address.ip), L("port", address.port),
                 L("address", pg_net_ipv4_addr_str));
    }
    *PG_DYN_PUSH(&res.peer_addresses, arena) = address;
  }

  return res;
}

[[maybe_unused]] [[nodiscard]] static TrackerResponseResult
tracker_parse_response(PgString s, Logger *logger, PgArena *arena) {
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

[[maybe_unused]] [[nodiscard]] static HttpRequest
tracker_make_http_request(TrackerMetadata req_tracker, PgArena *arena) {
  HttpRequest res = {0};
  res.method = HTTP_METHOD_GET;
  res.url = req_tracker.announce;
  *PG_DYN_PUSH(&res.url.query_parameters, arena) = (KeyValue){
      .key = PG_S("info_hash"),
      .value = req_tracker.info_hash,
  };
  *PG_DYN_PUSH(&res.url.query_parameters, arena) = (KeyValue){
      .key = PG_S("peer_id"),
      .value = req_tracker.peer_id,
  };
  *PG_DYN_PUSH(&res.url.query_parameters, arena) = (KeyValue){
      .key = PG_S("port"),
      .value = pg_u64_to_string(req_tracker.port, arena),
  };
  *PG_DYN_PUSH(&res.url.query_parameters, arena) = (KeyValue){
      .key = PG_S("uploaded"),
      .value = pg_u64_to_string(req_tracker.uploaded, arena),
  };
  *PG_DYN_PUSH(&res.url.query_parameters, arena) = (KeyValue){
      .key = PG_S("downloaded"),
      .value = pg_u64_to_string(req_tracker.downloaded, arena),
  };
  *PG_DYN_PUSH(&res.url.query_parameters, arena) = (KeyValue){
      .key = PG_S("left"),
      .value = pg_u64_to_string(req_tracker.left, arena),
  };
  *PG_DYN_PUSH(&res.url.query_parameters, arena) = (KeyValue){
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
  Logger *logger;
  TrackerState state;
  PgSocket socket;
  PgString host;
  u16 port;
  PgArena arena;
  RingBuffer rg;
  Reader reader;
  Writer writer;
  TrackerMetadata metadata;
} Tracker;

[[maybe_unused]] [[nodiscard]]
static Tracker tracker_make(Logger *logger, PgString host, u16 port,
                            TrackerMetadata metadata) {
  Tracker tracker = {0};
  tracker.logger = logger;
  tracker.host = host;
  tracker.port = port;
  tracker.metadata = metadata;

  tracker.arena = pg_arena_make_from_virtual_mem(4 * PG_KiB);
  tracker.rg = (RingBuffer){.data = pg_string_make(2048, &tracker.arena)};

  return tracker;
}

[[maybe_unused]] [[nodiscard]]
static PgError tracker_connect(Tracker *tracker) {
  {
    PgDnsResolveIpv4AddressSocketResult res_dns =
        net_dns_resolve_ipv4_tcp(tracker->host, tracker->port, tracker->arena);
    if (res_dns.err) {
      logger_log(tracker->logger, LOG_LEVEL_ERROR,
                 "failed to dns resolve the tracker announce url",
                 tracker->arena, L("err", res_dns.err));
      return res_dns.err;
    }
    PG_ASSERT(0 != res_dns.res.socket);
    tracker->socket = res_dns.res.socket;

    logger_log(tracker->logger, LOG_LEVEL_DEBUG,
               "dns resolved tracker announce url", tracker->arena,
               L("host", tracker->host), L("port", tracker->port),
               L("ip", res_dns.res.address.ip));
  }
  {
    PgError err = net_socket_set_blocking(tracker->socket, false);
    if (err) {
      logger_log(tracker->logger, LOG_LEVEL_ERROR,
                 "failed to set socket to non blocking", tracker->arena,
                 L("err", err));
      return err;
    }
  }

  tracker->reader = reader_make_from_socket(tracker->socket);
  tracker->writer = writer_make_from_socket(tracker->socket);

  return (PgError)0;
}

[[maybe_unused]] [[nodiscard]]
static PgError tracker_handle_event(Tracker *tracker, PgAioEvent event_watch,
                                  PgAioEventDyn *events_change,
                                  PgArena *events_arena) {

  switch (tracker->state) {
  case TRACKER_STATE_NONE: {
    if (0 == (PG_AIO_EVENT_KIND_OUT & event_watch.kind)) {
      // Failed to connect or invalid API use.
      return (PgError)EINVAL;
    }

    {
      PgArena pg_arena_tmp = tracker->arena;
      HttpRequest tracker_http_req =
          tracker_make_http_request(tracker->metadata, &pg_arena_tmp);
      PgError err = http_write_request(&tracker->rg, tracker_http_req, pg_arena_tmp);
      PG_ASSERT(!err); // Ring buffer too small.
    }

    logger_log(tracker->logger, LOG_LEVEL_DEBUG,
               "wrote http request to ring buffer", tracker->arena,
               L("write_space", ring_buffer_write_space(tracker->rg)),
               L("read_space", ring_buffer_read_space(tracker->rg)));

    tracker->state = TRACKER_STATE_SENT_REQUEST;

    *PG_DYN_PUSH(events_change, events_arena) = (PgAioEvent){
        .kind = PG_AIO_EVENT_KIND_IN,
        .socket = tracker->socket,
        .action = PG_AIO_EVENT_ACTION_MOD,
    };
  } break;
  case TRACKER_STATE_SENT_REQUEST: {
    PgArena pg_arena_tmp = tracker->arena;
    HttpResponseReadResult res_http =
        http_read_response(&tracker->rg, 128, &pg_arena_tmp);
    if (res_http.err) {
      logger_log(tracker->logger, LOG_LEVEL_ERROR,
                 "invalid tracker http response", pg_arena_tmp,
                 L("err", res_http.err));
      return res_http.err;
    }
    logger_log(tracker->logger, LOG_LEVEL_DEBUG, "read http tracker response",
               pg_arena_tmp, L("http.status", res_http.res.status));
    tracker->state = TRACKER_STATE_RECEIVED_RESPONSE;

    *PG_DYN_PUSH(events_change, events_arena) = (PgAioEvent){
        .socket = tracker->socket,
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
