#pragma once

#include "submodules/cstd/lib.c"

typedef struct {
  // Torrent file.
  u64 torrent_file_max_size;
  u64 torrent_file_max_bencode_alloc_bytes;

  // Download.
  u64 download_max_concurrent_downloads;

  // Tracker.
  u64 tracker_max_http_recv_size;
  u64 tracker_round_trip_timeout_seconds;

  // Peer.

} Configuration;
