#pragma once
#include "bencode.c"
#include "submodules/c-http/http.c"
#include "submodules/cstd/lib.c"

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
static TrackerResponse tracker_send_get_req(TrackerRequest req, Arena *arena) {
  TrackerResponse res = {0};

  HttpRequest http_req = {0};
  http_req.method = HM_GET;
  *dyn_push(&http_req.path_components, arena) = S("announce"); // FIXME
  u16 port = 6969;                                             // FIXME.

  struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(port),
  };
  HttpResponse resp = http_client_request((struct sockaddr *)&addr,
                                          sizeof(addr), http_req, arena);
  if (resp.err) {
    return res;
  }

  return res;
}
