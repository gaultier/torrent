#include "tracker.c"

// Lifetimes:
// - [x] Rng, Logger, Configuration: whole program duration, creating in main at
// the start.
// - [x] Download: when a torrent file is added => create a Download from it.
// Keep Download around until all pieces are downloaded (and verified).
//   Serving pieces does not require the pieces hash, only the info_hash and the
//   pieces/blocks counts/sizes for validation of requests. All of that does not
//   required dynamic allocation. So we can/could tear down the download when
//   all pieces are downloaded. That allows for freeing the pieces hash which is
//   big
//   (~40Kib or even more).
// - [x] Tracker: one tracker per torrent file download. One time allocation
// with its own arena. When all pieces are downloaded, still keep it to report
// stats to the tracker so that
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

static uv_timer_t download_metrics_timer = {0};

static void download_on_timer(uv_timer_t *timer) {
  PG_ASSERT(timer);
  PG_ASSERT(timer->data);

  Download *download = timer->data;
  pg_log(download->logger, PG_LOG_LEVEL_INFO, "download: metrics",
         pg_log_cu64("concurrent_downloads_count",
                     download->concurrent_downloads_count),
         pg_log_cu64("concurrent_downloads_max",
                     download->cfg->download_max_concurrent_downloads),
         pg_log_cu64("peers_active", download->peers_active_count),
         pg_log_cu64("pieces_count", download->pieces_count),
         pg_log_cu64("pieces_have", pg_bitfield_count(download->pieces_have)));
}

typedef struct {
  Download *download;
  Metainfo *metainfo;
  TorrentFile *torrent;
  Configuration *cfg;
  PgAllocator *general_allocator;
} Prepare;

static void on_prepare(uv_prepare_t *uv_prepare) {
  PG_ASSERT(uv_prepare);
  PG_ASSERT(uv_prepare->data);
  Prepare *prepare = uv_prepare->data;

  PgError err = 0;

  PgStringResult res_bitfield_pieces = download_load_bitfield_pieces_from_disk(
      prepare->download, prepare->metainfo->name, prepare->metainfo->pieces);
  if (res_bitfield_pieces.err) {
    pg_log(prepare->download->logger, PG_LOG_LEVEL_ERROR,
           "failed to load bitfield from file",
           pg_log_cs("path", prepare->metainfo->name),
           pg_log_cerr("err", res_bitfield_pieces.err),
           pg_log_cs("err_s", pg_cstr_to_string(
                                  strerror((i32)res_bitfield_pieces.err))));

    err = res_bitfield_pieces.err;
    goto end;
  }
  // TODO: Use `uv_fs_xxx` functions to read the file asynchronously, instead of
  // blocking I/O, which forces us to update the loop time manually.
  uv_update_time(uv_default_loop());
  pg_log(prepare->download->logger, PG_LOG_LEVEL_DEBUG,
         "loaded bitfield from file",
         pg_log_cs("path", prepare->metainfo->name),
         pg_log_cu64("local_bitfield_have_count",
                     pg_bitfield_count(prepare->download->pieces_have)));

  // Start tracker client.
  u16 port_torrent_ours = 6881;
  PgSha1 info_hash = pg_sha1(PG_SLICE_RANGE(prepare->torrent->file_data,
                                            prepare->metainfo->info_start,
                                            prepare->metainfo->info_end));
  Tracker *tracker = calloc(sizeof(Tracker), 1);
  PgError err_tracker = tracker_init(
      tracker, prepare->download->logger, prepare->cfg,
      prepare->metainfo->announce.host, prepare->metainfo->announce.port,
      prepare->download, prepare->metainfo->pieces, port_torrent_ours,
      prepare->metainfo->announce, info_hash, prepare->general_allocator);
  if (err_tracker) {
    pg_log(prepare->download->logger, PG_LOG_LEVEL_ERROR,
           "failed to create tracker",
           pg_log_cs("path", prepare->metainfo->name),
           pg_log_cerr("err", err_tracker),
           pg_log_cs("err_s", pg_cstr_to_string(strerror((i32)err_tracker))));

    err = err_tracker;
    goto end;
  }

  err = tracker_start_dns_resolve(tracker, prepare->metainfo->announce);
  if (err) {
    goto end;
  }

  // Metrics.
  download_metrics_timer.data = prepare->download;
  {
    PG_ASSERT(0 == uv_timer_init(uv_default_loop(), &download_metrics_timer));

    int err_timer_start =
        uv_timer_start(&download_metrics_timer, download_on_timer,
                       pg_ns_to_ms(prepare->cfg->metrics_interval_ns),
                       pg_ns_to_ms(prepare->cfg->metrics_interval_ns));
    if (err_timer_start < 0) {
      pg_log(prepare->download->logger, PG_LOG_LEVEL_ERROR,
             "failed to start download metrics timer",
             pg_log_cs("path", prepare->metainfo->name),
             pg_log_ci32("err", err_timer_start));

      err = (PgError)err_timer_start;
      goto end;
    }
  }

end:
  if (err) {
    pg_log(prepare->download->logger, PG_LOG_LEVEL_ERROR,
           "setup failed, stopping",
           pg_log_cs("path", prepare->metainfo->name));
    uv_stop(uv_default_loop());
  }
  uv_prepare_stop(uv_prepare);

  pg_log(prepare->download->logger, PG_LOG_LEVEL_INFO, "setup finished",
         pg_log_cs("path", prepare->metainfo->name));
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
                          (usize *)&heap_profile_path_len)) {
      uv_fs_t heap_profile_open_req = {0};
      int heap_profile_file = uv_fs_open(
          uv_default_loop(), &heap_profile_open_req, heap_profile_path,
          UV_FS_O_APPEND | UV_FS_O_CREAT, 0600, nullptr);
      if (heap_profile_file < 0) {
        pg_log(
            &logger, PG_LOG_LEVEL_ERROR, "failed to open heap profile file",
            pg_log_ci32("err", heap_profile_file),
            pg_log_cs("err_s", pg_cstr_to_string(strerror(heap_profile_file))),
            pg_log_cs("path", pg_cstr_to_string(heap_profile_path)));
      } else {
        PG_ASSERT(heap_profile_file > 0);
        tracing_allocator = pg_make_tracing_allocator(
            (PgFileDescriptor){.fd = heap_profile_file});
        general_allocator =
            pg_tracing_allocator_as_allocator(&tracing_allocator);

        pg_log(&logger, PG_LOG_LEVEL_DEBUG, "using tracing allocator",
               pg_log_ci32("heap_profile_file", heap_profile_file));
      }
    }
    // The tracing allocator could not be properly initialized, resort to the
    // standard (libc) allocator.
    if (!general_allocator) {
      heap_allocator = pg_make_heap_allocator();
      general_allocator = pg_heap_allocator_as_allocator(&heap_allocator);

      pg_log(&logger, PG_LOG_LEVEL_DEBUG, "using general heap allocator",
             pg_log_cs("_", PG_S("_")));
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
           pg_log_cs("path", torrent_file_path),
           pg_log_cs("announce.scheme", metainfo.announce.scheme),
           pg_log_cs("announce.host", metainfo.announce.host));
    return 1;
  }

  PgFileResult res_target_file =
      download_file_create_if_not_exists(metainfo.name, metainfo.length);
  if (res_target_file.err) {
    pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to create download file",
           pg_log_cs("path", metainfo.name),
           pg_log_cerr("err", res_target_file.err),
           pg_log_cs("err_s",
                     pg_cstr_to_string(strerror((i32)res_target_file.err))));
    return 1;
  }

  // Download.
  Download download =
      download_make(&logger, &rng, &cfg, metainfo.piece_length, metainfo.length,
                    metainfo.pieces, res_target_file.res);
  pg_log(
      &logger, PG_LOG_LEVEL_DEBUG, "download", pg_log_cs("path", metainfo.name),
      pg_log_cu64("pieces_count", download.pieces_count),
      pg_log_cu64("blocks_count", download.blocks_count),
      pg_log_cu64("max_blocks_per_piece_count", download.blocks_per_piece_max),
      pg_log_cu64("piece_length", download.piece_length),
      pg_log_cu64("total_file_size", download.total_size),
      pg_log_cu32("last_piece_blocks_count",
                  download_compute_blocks_count_for_piece(
                      &download, (PieceIndex){download.pieces_count - 1})),
      pg_log_cu32("last_piece_size",
                  download_compute_piece_length(
                      &download, (PieceIndex){download.pieces_count - 1})),
      pg_log_cu32("last_block_size",
                  download_compute_piece_length(
                      &download, (PieceIndex){download.pieces_count - 1}) -
                      (download_compute_blocks_count_for_piece(
                           &download, (PieceIndex){download.pieces_count - 1}) -
                       1) *
                          BLOCK_SIZE));

  // libuv async operations from this point on.
  Prepare prepare = {
      .download = &download,
      .cfg = &cfg,
      .metainfo = &metainfo,
      .torrent = &torrent,
      .general_allocator = general_allocator,
  };
  uv_prepare_t uv_prepare = {.data = &prepare};
  PG_ASSERT(0 == uv_prepare_init(uv_default_loop(), &uv_prepare));
  uv_prepare_start(&uv_prepare, on_prepare);

  uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}
