#pragma once
#include "bencode.c"

typedef enum {
  TRACKER_EVENT_STARTED,
  TRACKER_EVENT_STOPPED,
  TRACKER_EVENT_COMPLETED,
} TrackerRequestEvent;

typedef struct {
  String info_hash;
  String peer_id;
  u32 ip;
  u16 port;
  u64 downloaded, uploaded, left;
  TrackerRequestEvent event;
  Url announce;
} TrackerRequest;

[[maybe_unused]] [[nodiscard]] static String
tracker_request_event_to_string(TrackerRequestEvent event) {
  switch (event) {
  case TRACKER_EVENT_STARTED:
    return S("started");
  case TRACKER_EVENT_STOPPED:
    return S("stopped");
  case TRACKER_EVENT_COMPLETED:
    return S("completed");
  default:
    ASSERT(0);
  }
}

static void tracker_compute_info_hash(Metainfo metainfo, String hash,
                                      Arena arena) {
  BencodeValue value = {.kind = BENCODE_KIND_DICTIONARY};

  *dyn_push(&value.dict.keys, &arena) = S("length");
  *dyn_push(&value.dict.values, &arena) = (BencodeValue){
      .kind = BENCODE_KIND_NUMBER,
      .num = metainfo.length,
  };

  *dyn_push(&value.dict.keys, &arena) = S("name");
  *dyn_push(&value.dict.values, &arena) = (BencodeValue){
      .kind = BENCODE_KIND_STRING,
      .s = metainfo.name,
  };

  *dyn_push(&value.dict.keys, &arena) = S("piece length");
  *dyn_push(&value.dict.values, &arena) = (BencodeValue){
      .kind = BENCODE_KIND_NUMBER,
      .num = metainfo.piece_length,
  };

  *dyn_push(&value.dict.keys, &arena) = S("pieces");
  *dyn_push(&value.dict.values, &arena) = (BencodeValue){
      .kind = BENCODE_KIND_STRING,
      .s = metainfo.pieces,
  };

  // TODO: Add unknown keys in `info`?

  DynU8 sb = {0};
  bencode_encode(value, &sb, &arena);
  String encoded = dyn_slice(String, sb);

  u8 sha1_hash[20] = {0};
  sha1(encoded, sha1_hash);
  ASSERT(sizeof(sha1_hash) == hash.len);
  memcpy(hash.data, sha1_hash, hash.len);
}

typedef struct {
  DynIpv4Address peer_addresses;
  String failure;
  u64 interval_secs;
} TrackerResponse;

RESULT(TrackerResponse) TrackerResponseResult;

typedef struct {
  Error err;
  DynIpv4Address peer_addresses;
} ParseCompactPeersResult;

[[nodiscard]] static ParseCompactPeersResult
tracker_parse_compact_peers(String s, Logger *logger, Arena *arena) {
  ParseCompactPeersResult res = {0};

  if (s.len % 6 != 0) {
    res.err = TORR_ERR_COMPACT_PEERS_INVALID;
    return res;
  }

  String remaining = s;
  for (u64 lim = 0; lim < s.len; lim++) {
    if (0 == remaining.len) {
      break;
    }

    String ipv4_str = slice_range(remaining, 0, 4);
    String port_str = slice_range(remaining, 4, 6);

    remaining = slice_range_start(remaining, 6);

    u32 ipv4_network_order = 0;
    memcpy(&ipv4_network_order, ipv4_str.data, ipv4_str.len);

    u16 port_network_order = 0;
    memcpy(&port_network_order, port_str.data, port_str.len);

    Ipv4Address address = {
        .ip = ntohl(ipv4_network_order),
        .port = ntohs(port_network_order),
    };

    {
      String ipv4_addr_str = ipv4_address_to_string(address, arena);
      logger_log(logger, LOG_LEVEL_INFO, "tracker_parse_compact_peers", *arena,
                 L("res.peer_addresses.len", res.peer_addresses.len),
                 L("ip", address.ip), L("port", address.port),
                 L("address", ipv4_addr_str));
    }
    *dyn_push(&res.peer_addresses, arena) = address;
  }

  return res;
}

[[maybe_unused]] [[nodiscard]] static TrackerResponseResult
tracker_parse_response(String s, Logger *logger, Arena *arena) {
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
    String key = slice_at(dict.keys, i);
    BencodeValue value = slice_at(dict.values, i);

    if (string_eq(key, S("failure reason"))) {
      if (BENCODE_KIND_STRING != value.kind) {
        res.err = TORR_ERR_BENCODE_INVALID;
        return res;
      }

      res.res.failure = value.s;
    } else if (string_eq(key, S("interval"))) {
      if (BENCODE_KIND_NUMBER != value.kind) {
        res.err = TORR_ERR_BENCODE_INVALID;
        return res;
      }
      res.res.interval_secs = value.num;
    } else if (string_eq(key, S("peers"))) {
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
tracker_make_request(TrackerRequest req_tracker, Arena *arena) {
  HttpRequest res = {0};
  res.method = HTTP_METHOD_GET;
  res.url = req_tracker.announce;
  *dyn_push(&res.url.query_parameters, arena) = (KeyValue){
      .key = S("info_hash"),
      .value = req_tracker.info_hash,
  };
  *dyn_push(&res.url.query_parameters, arena) = (KeyValue){
      .key = S("peer_id"),
      .value = req_tracker.peer_id,
  };
  *dyn_push(&res.url.query_parameters, arena) = (KeyValue){
      .key = S("port"),
      .value = u64_to_string(req_tracker.port, arena),
  };
  *dyn_push(&res.url.query_parameters, arena) = (KeyValue){
      .key = S("uploaded"),
      .value = u64_to_string(req_tracker.uploaded, arena),
  };
  *dyn_push(&res.url.query_parameters, arena) = (KeyValue){
      .key = S("downloaded"),
      .value = u64_to_string(req_tracker.downloaded, arena),
  };
  *dyn_push(&res.url.query_parameters, arena) = (KeyValue){
      .key = S("left"),
      .value = u64_to_string(req_tracker.left, arena),
  };
  *dyn_push(&res.url.query_parameters, arena) = (KeyValue){
      .key = S("event"),
      .value = tracker_request_event_to_string(req_tracker.event),
  };

  return res;
}
