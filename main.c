#include "tracker.c"

// Lifetimes:
// - Logger: whole program duration, creating in main at the start.
// - Download: when a torrent file is added => create a Download from it. Keep
// Download around until all pieces are downloaded (and verified).
//   Serving pieces does not require the pieces hash, only the info_hash and the
//   pieces/blocks counts/sizes for validation of requests. All of that does not
//   required dynamic allocation. So we can tear down the download when all
//   pieces are downloaded. That allows for freeing the pieces hash which is big
//   (~40Kib or even more).
// - Tracker: one tracker per torrent file download. One time allocation with
// its own arena. When all pieces are downloaded, still keep it to report stats
// to the tracker so that
//   other peers can find us. The tracker only needs a recv/send buffer which
//   are limited by the configuration before creating the tracker so the tracker
//   arena can be sized exactly.
// - Peer: Each peer has its own arena (check if that really is feasible).
// Ideally, exactly (i.e. minimally) sized ahead of time.
// - Download->Peer relationship: a Download spawns peers.
//   But: we should also spawn peers with a periodic timer to serve pieces, if
//   there are zero peers running, once we implement this. Or, just have one
//   socket listener that spawns peers on a new connection.
// - read/write peer data: handled by the peer. Should use a pool allocator for
// efficiency since there lifetime is short and the rate is high. The pool
// should support
//   heterogeneous sizes since some rw requests are very short (e.g.
//   keep-alives) but others are big (e.g. bitfield, blocks).
//   Pool implementation: contiguous array with metadata for each slot
//   containing the size, or free list where items come from the arena.
// - read peer data: allocated by libuv due to `uv_read_start` with the
// allocator we provide (should be a pool allocator).
//   Released (returned to pool) when stored to disk (be it with an error or
//   not) or failing verification.
//  - write peer data: same.
//  - Peers should come from a pool with a handle and a generation counter to
//  avoid the case of a async callback trying to use a `Peer*` where the peer
//  has already been 'freed'.
//

static void download_on_timer(uv_timer_t *timer) {
  PG_ASSERT(timer);
  PG_ASSERT(timer->data);

  Download *download = timer->data;
  pg_log(
      download->logger, PG_LOG_LEVEL_INFO, "download: metrics",
      PG_L("concurrent_downloads_count", download->concurrent_downloads_count),
      PG_L("concurrent_downloads_max",
           download->cfg->download_max_concurrent_downloads),
      PG_L("peers_active", download->peers_active_count),
      PG_L("pieces_count", download->pieces_count),
      PG_L("pieces_have", pg_bitfield_count(download->pieces_have)));
}

int main(int argc, char *argv[]) {
  PG_ASSERT(argc == 2);

  PgLogger logger = pg_log_make_logger_stdout_logfmt(PG_LOG_LEVEL_INFO);
  // PgLogger logger = pg_log_make_logger_stdout_logfmt(PG_LOG_LEVEL_DEBUG);
  PgRng rng = pg_rand_make();

  PgAllocator *general_allocator = nullptr;
  char heap_profile_path[PG_PATH_MAX] = {0};
  u64 heap_profile_path_len = PG_PATH_MAX;
  PgTracingAllocator tracing_allocator = {0};
  PgHeapAllocator heap_allocator = {0};

  // Pick a general allocator.
  {
    if (0 == uv_os_getenv("HEAPPROFILE", heap_profile_path,
                          &heap_profile_path_len)) {
      uv_fs_t heap_profile_open_req = {0};
      int heap_profile_file = uv_fs_open(
          uv_default_loop(), &heap_profile_open_req, heap_profile_path,
          UV_FS_O_APPEND | UV_FS_O_CREAT, 0600, nullptr);
      if (heap_profile_file < 0) {
        pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to open heap profile file",
               PG_L("err", heap_profile_file),
               PG_L("err_s", pg_cstr_to_string(strerror(heap_profile_file))),
               PG_L("path", pg_cstr_to_string(heap_profile_path)));
      } else {
        PG_ASSERT(heap_profile_file > 0);
        tracing_allocator = pg_make_tracing_allocator(heap_profile_file);
        general_allocator =
            pg_tracing_allocator_as_allocator(&tracing_allocator);

        pg_log(&logger, PG_LOG_LEVEL_DEBUG, "using tracing allocator",
               PG_L("heap_profile_file", heap_profile_file));
      }
    }
    // The tracing allocator could not be properly initialized, resort to the
    // standard (libc) allocator.
    if (!general_allocator) {
      heap_allocator = pg_make_heap_allocator();
      general_allocator = pg_heap_allocator_as_allocator(&heap_allocator);

      pg_log(&logger, PG_LOG_LEVEL_DEBUG, "using general heap allocator",
             PG_L("_", PG_S("_")));
    }
  }

  Configuration cfg = {
      .torrent_file_max_size = 5 * PG_MiB,
      .torrent_file_max_bencode_alloc_bytes = 12 * PG_KiB,
      .tracker_max_http_request_bytes = 64 * PG_KiB,
      .tracker_max_http_response_bytes = 64 * PG_KiB,
      .tracker_round_trip_timeout_ns = 20 * PG_Seconds,
      .metrics_interval_ns = 1 * PG_Seconds,
      .download_max_concurrent_downloads = 500,
  };

  char *torrent_file_path_c = argv[1];
  PgString torrent_file_path = pg_cstr_to_string(torrent_file_path_c);
  TorrentFileResult res_torrent_file =
      torrent_file_read_file(torrent_file_path, &cfg, &logger);
  if (res_torrent_file.err) {
    return 1;
  }
  // Shorthands.
  TorrentFile torrent = res_torrent_file.res;
  Metainfo metainfo = torrent.metainfo;

  if (pg_string_eq(PG_S("https"), metainfo.announce.scheme)) {
    pg_log(&logger, PG_LOG_LEVEL_ERROR,
           "announce url is using https but it is not yet implemented",
           PG_L("path", torrent_file_path),
           PG_L("announce.scheme", metainfo.announce.scheme),
           PG_L("announce.host", metainfo.announce.host));
    return 1;
  }

  PgFileResult res_target_file =
      download_file_create_if_not_exists(metainfo.name, metainfo.length);
  if (res_target_file.err) {
    pg_log(
        &logger, PG_LOG_LEVEL_ERROR, "failed to create download file",
        PG_L("path", metainfo.name), PG_L("err", res_target_file.err),
        PG_L("err_s", pg_cstr_to_string(strerror((i32)res_target_file.err))));
    return 1;
  }

  u16 port_ours_torrent = 6881;
  TrackerMetadata tracker_metadata = {
      .port = port_ours_torrent,
      .left = metainfo.length,
      .event = TRACKER_EVENT_STARTED,
      .announce = metainfo.announce,
  };
  torrent_compute_info_hash(
      PG_SLICE_RANGE(torrent.file_data, metainfo.info_start, metainfo.info_end),
      tracker_metadata.info_hash);
  u32 pieces_count =
      download_compute_pieces_count(metainfo.piece_length, metainfo.length);
  PG_ASSERT(pieces_count > 0);

  // Download.
  Download download =
      download_make(&logger, &rng, &cfg, metainfo.piece_length, metainfo.length,
                    metainfo.pieces, res_target_file.res);
  pg_log(&logger, PG_LOG_LEVEL_DEBUG, "download", PG_L("path", metainfo.name),
         PG_L("pieces_count", download.pieces_count),
         PG_L("blocks_count", download.blocks_count),
         PG_L("max_blocks_per_piece_count", download.blocks_per_piece_max),
         PG_L("piece_length", download.piece_length),
         PG_L("total_file_size", download.total_size),
         PG_L("last_piece_blocks_count",
              download_compute_blocks_count_for_piece(
                  &download, (PieceIndex){download.pieces_count - 1})),
         PG_L("last_piece_size",
              download_compute_piece_length(
                  &download, (PieceIndex){download.pieces_count - 1})),
         PG_L("last_block_size",
              download_compute_piece_length(
                  &download, (PieceIndex){download.pieces_count - 1}) -
                  (download_compute_blocks_count_for_piece(
                       &download, (PieceIndex){download.pieces_count - 1}) -
                   1) *
                      BLOCK_SIZE));

  PgStringResult res_bitfield_pieces = download_load_bitfield_pieces_from_disk(
      &download, metainfo.name, metainfo.pieces);
  if (res_bitfield_pieces.err) {
    pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to load bitfield from file",
           PG_L("path", metainfo.name), PG_L("err", res_bitfield_pieces.err),
           PG_L("err_s",
                pg_cstr_to_string(strerror((i32)res_bitfield_pieces.err))));
    return 1;
  }
  pg_log(&logger, PG_LOG_LEVEL_DEBUG, "loaded bitfield from file",
         PG_L("path", metainfo.name),
         PG_L("local_bitfield_have_count",
              pg_bitfield_count(download.pieces_have)));

  // Start tracker client.
  Tracker tracker = tracker_make(&logger, &cfg, metainfo.announce.host,
                                 metainfo.announce.port, tracker_metadata,
                                 &download, metainfo.pieces, general_allocator);
  if (tracker_start_dns_resolve(&tracker, metainfo.announce)) {
    return 1;
  }

  // Metrics.
  uv_timer_t download_metrics_timer = {0};
  download_metrics_timer.data = &download;
  {
    int err_timer_init =
        uv_timer_init(uv_default_loop(), &download_metrics_timer);
    if (err_timer_init < 0) {
      pg_log(&logger, PG_LOG_LEVEL_ERROR,
             "failed to init download metrics timer",
             PG_L("path", metainfo.name), PG_L("err", err_timer_init));
      return 1;
    }

    int err_timer_start =
        uv_timer_start(&download_metrics_timer, download_on_timer,
                       pg_ns_to_ms(cfg.metrics_interval_ns),
                       pg_ns_to_ms(cfg.metrics_interval_ns));
    if (err_timer_start < 0) {
      pg_log(&logger, PG_LOG_LEVEL_ERROR,
             "failed to start download metrics timer",
             PG_L("path", metainfo.name), PG_L("err", err_timer_start));
      return 1;
    }
  }

  uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}
