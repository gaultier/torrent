#pragma once

#include "submodules/cstd/lib.c"

typedef struct {
  // Torrent file.
  u64 torrent_file_max_size;
  u64 torrent_file_max_bencode_alloc_bytes;

  // Download.
  u64 download_max_concurrent_downloads;

  // Tracker.
  u64 tracker_max_http_request_bytes;
  u64 tracker_max_http_response_bytes;
  u64 tracker_round_trip_timeout_ns;

  // Peer.
  // TODO

  // Metrics
  u64 metrics_interval_ns;
} Configuration;
