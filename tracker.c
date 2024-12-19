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
                                      Arena *arena) {
  BencodeValue value = {.kind = BENCODE_KIND_DICTIONARY};

  *dyn_push(&value.dict.keys, arena) = S("length");
  *dyn_push(&value.dict.values, arena) = (BencodeValue){
      .kind = BENCODE_KIND_NUMBER,
      .num = metainfo.length,
  };

  *dyn_push(&value.dict.keys, arena) = S("name");
  *dyn_push(&value.dict.values, arena) = (BencodeValue){
      .kind = BENCODE_KIND_STRING,
      .s = metainfo.name,
  };

  *dyn_push(&value.dict.keys, arena) = S("piece length");
  *dyn_push(&value.dict.values, arena) = (BencodeValue){
      .kind = BENCODE_KIND_NUMBER,
      .num = metainfo.piece_length,
  };

  *dyn_push(&value.dict.keys, arena) = S("pieces");
  *dyn_push(&value.dict.values, arena) = (BencodeValue){
      .kind = BENCODE_KIND_STRING,
      .s = metainfo.pieces,
  };

  // TODO: Add unknown keys in `info`?

  DynU8 sb = {0};
  bencode_encode(value, &sb, arena);
  String encoded = dyn_slice(String, sb);

  u8 sha1_hash[20] = {0};
  sha1(encoded, sha1_hash);
  ASSERT(sizeof(sha1_hash) == hash.len);
  memcpy(hash.data, sha1_hash, hash.len);
}

typedef struct {
  u32 ipv4;
  u16 port;
  Writer writer;
} Peer;

typedef struct {
  Peer *data;
  u64 len, cap;
} DynPeer;

typedef struct {
  DynPeer peers;
  String failure;
  u64 interval_secs;
} TrackerResponse;

typedef struct {
  Status status;
  TrackerResponse resp;
} TrackerResponseResult;

typedef struct {
  Status status;
  DynPeer peers;
} ParseCompactPeersResult;
[[nodiscard]] static ParseCompactPeersResult
tracker_parse_compact_peers(String s, Arena *arena) {
  ParseCompactPeersResult res = {0};

  if (s.len % 6 != 0) {
    return res;
  }

  String remaining = s;
  for (u64 lim = 0; lim < s.len; lim++) {
    if (0 == remaining.len) {
      break;
    }

    String ipv4_str = slice_range(remaining, 0, 4);
    String port_str = slice_range(remaining, 4, 6);

    remaining = slice_range(remaining, 6, 0);

    u32 ipv4_network_order = 0;
    memcpy(&ipv4_network_order, ipv4_str.data, ipv4_str.len);

    u16 port_network_order = 0;
    memcpy(&port_network_order, port_str.data, port_str.len);

    Peer peer = {
        .ipv4 = ntohl(ipv4_network_order),
        .port = ntohs(port_network_order),
    };
    *dyn_push(&res.peers, arena) = peer;
  }

  res.status = STATUS_OK;
  return res;
}

[[nodiscard]] static TrackerResponseResult
tracker_parse_response(String s, Arena *arena) {
  TrackerResponseResult res = {0};

  BencodeValueDecodeResult tracker_response_bencode_res =
      bencode_decode_value(s, arena);
  if (STATUS_OK != tracker_response_bencode_res.status) {
    return res;
  }
  if (tracker_response_bencode_res.remaining.len != 0) {
    return res;
  }

  if (BENCODE_KIND_DICTIONARY != tracker_response_bencode_res.value.kind) {
    return res;
  }

  BencodeDictionary dict = tracker_response_bencode_res.value.dict;

  for (u64 i = 0; i < dict.keys.len; i++) {
    String key = slice_at(dict.keys, i);
    BencodeValue value = slice_at(dict.values, i);

    if (string_eq(key, S("failure reason"))) {
      if (BENCODE_KIND_STRING != value.kind) {
        return res;
      }

      res.resp.failure = value.s;
    } else if (string_eq(key, S("interval"))) {
      if (BENCODE_KIND_NUMBER != value.kind) {
        return res;
      }
      res.resp.interval_secs = value.num;
    } else if (string_eq(key, S("peers"))) {
      if (BENCODE_KIND_STRING != value.kind) {
        return res; // TODO: Handle non-compact case i.e. BENCODE_LIST?
      }
      ParseCompactPeersResult res_parse_compact_peers =
          tracker_parse_compact_peers(value.s, arena);

      if (STATUS_OK != res_parse_compact_peers.status) {
        return res;
      }
      res.resp.peers = res_parse_compact_peers.peers;
    }
  }

  res.status = STATUS_OK;
  return res;
}

[[maybe_unused]] [[nodiscard]] static TrackerResponseResult
tracker_send_get_req(TrackerRequest req_tracker, Arena *arena) {
  TrackerResponseResult res = {0};

  HttpRequest req_http = {0};
  req_http.method = HM_GET;
  req_http.path_components = req_tracker.announce.path_components;
  *dyn_push(&req_http.url_parameters, arena) = (KeyValue){
      .key = S("info_hash"),
      .value = req_tracker.info_hash,
  };
  *dyn_push(&req_http.url_parameters, arena) = (KeyValue){
      .key = S("peer_id"),
      .value = req_tracker.peer_id,
  };
  *dyn_push(&req_http.url_parameters, arena) = (KeyValue){
      .key = S("port"),
      .value = u64_to_string(req_tracker.port, arena),
  };
  *dyn_push(&req_http.url_parameters, arena) = (KeyValue){
      .key = S("uploaded"),
      .value = u64_to_string(req_tracker.uploaded, arena),
  };
  *dyn_push(&req_http.url_parameters, arena) = (KeyValue){
      .key = S("downloaded"),
      .value = u64_to_string(req_tracker.downloaded, arena),
  };
  *dyn_push(&req_http.url_parameters, arena) = (KeyValue){
      .key = S("left"),
      .value = u64_to_string(req_tracker.left, arena),
  };
  *dyn_push(&req_http.url_parameters, arena) = (KeyValue){
      .key = S("event"),
      .value = tracker_request_event_to_string(req_tracker.event),
  };

  HttpResponse resp = http_client_request(
      req_tracker.announce.host, req_tracker.announce.port, req_http, arena);
  if (resp.err) {
    return res;
  }
  if (200 != resp.status) {
    return res;
  }

  return tracker_parse_response(resp.body, arena);
}
