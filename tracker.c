#pragma once
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
