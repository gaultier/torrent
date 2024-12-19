#pragma once
#include "bencode.c"

typedef enum {
  TRACKER_EVENT_STARTED,
  TRACKER_EVENT_STOPPED,
  TRACKER_EVENT_COMPLETED,
} TrackerRequestEvent;

typedef struct {
  u8 info_hash[20];
  u8 peer_id[20];
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

static void tracker_compute_info_hash(Metainfo metainfo, u8 hash[20],
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

  sha1(encoded, hash);
}

typedef struct {
  String id;
  String address; // DNS name or IP address.
  u16 port;
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
      // TODO
    }
  }

  res.status = STATUS_OK;
  return res;
}

[[nodiscard]] static TrackerResponseResult
tracker_send_get_req(TrackerRequest req_tracker, Arena *arena) {
  TrackerResponseResult res = {0};

  HttpRequest req_http = {0};
  req_http.method = HM_GET;
  req_http.path_components = req_tracker.announce.path_components;
  *dyn_push(&req_http.url_parameters, arena) = (KeyValue){
      .key = S("info_hash"),
      .value =
          (String){
              .data = req_tracker.info_hash,
              .len = sizeof(req_tracker.info_hash),
          },
  };
  *dyn_push(&req_http.url_parameters, arena) = (KeyValue){
      .key = S("peer_id"),
      .value =
          (String){
              .data = req_tracker.peer_id,
              .len = sizeof(req_tracker.peer_id),
          },
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
