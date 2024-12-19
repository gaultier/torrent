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
  Status status;
  BencodeValue response;
} TrackerResponse;

[[nodiscard]]
static TrackerResponse tracker_send_get_req(TrackerRequest req_tracker,
                                            Arena *arena) {
  TrackerResponse res = {0};

  HttpRequest req_http = {0};
  req_http.method = HM_GET;
  req_http.path_components = req_tracker.announce.path_components;
  *dyn_push(&req_http.url_parameters, arena) = (KeyValue){
      .key = S("peer_id"),
      .value =
          (String){
              .data = req_tracker.peer_id,
              .len = 20,
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

  struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(req_tracker.announce.port),
  };
  HttpResponse resp = http_client_request((struct sockaddr *)&addr,
                                          sizeof(addr), req_http, arena);
  if (resp.err) {
    return res;
  }
  if (200 != resp.status) {
    return res;
  }

  BencodeValueDecodeResult tracker_response_bencode_res =
      bencode_decode_value(resp.body, arena);
  if (STATUS_OK != tracker_response_bencode_res.status) {
    return res;
  }
  if (tracker_response_bencode_res.remaining.len != 0) {
    return res;
  }

  res.response = tracker_response_bencode_res.value;

  return res;
}
