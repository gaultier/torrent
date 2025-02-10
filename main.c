#include "tracker.c"

#include "submodules/libuv/include/uv.h"

static void download_on_timer(uv_timer_t *timer) {
  PG_ASSERT(timer);
  PG_ASSERT(timer->data);

  Download *download = timer->data;
  pg_log(download->logger, PG_LOG_LEVEL_INFO, "download: metrics",
         PG_L("pieces_count", download->pieces_count),
         PG_L("pieces_have", pg_bitfield_count(download->pieces_have)));
}

int main(int argc, char *argv[]) {
  PG_ASSERT(argc == 2);

  PgLogger logger = pg_log_make_logger_stdout_logfmt(PG_LOG_LEVEL_DEBUG);
  PgRng rng = pg_rand_make();

  PgArena arena = pg_arena_make_from_virtual_mem(1 * PG_MiB);
  PgArenaAllocator arena_allocator = pg_make_arena_allocator(&arena);

  PgAllocator *general_allocator = nullptr;
  char heap_profile_path[PG_PATH_MAX] = {0};
  u64 heap_profile_path_len = PG_PATH_MAX;
  PgTracingAllocator tracing_allocator = {0};
  PgHeapAllocator heap_allocator = {0};

  if (0 ==
      uv_os_getenv("HEAPPROFILE", heap_profile_path, &heap_profile_path_len)) {
    uv_fs_t heap_profile_open_req = {0};
    int heap_profile_file =
        uv_fs_open(uv_default_loop(), &heap_profile_open_req, heap_profile_path,
                   O_APPEND | O_CREAT, 0600, nullptr);
    if (heap_profile_file < 0) {
      pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to open heap profile file",
             PG_L("err", heap_profile_file),
             PG_L("err_s", pg_cstr_to_string(strerror(heap_profile_file))),
             PG_L("path", pg_cstr_to_string(heap_profile_path)));
    } else {
      PG_ASSERT(heap_profile_file > 0);
      tracing_allocator = pg_make_tracing_allocator(heap_profile_file);
      general_allocator = pg_tracing_allocator_as_allocator(&tracing_allocator);

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

  char *torrent_file_path_c = argv[1];
  PgString torrent_file_path = pg_cstr_to_string(torrent_file_path_c);
  PgString torrent_file_data = {0};
  {
    uv_fs_t req = {0};
    int err_open = uv_fs_open(uv_default_loop(), &req, torrent_file_path_c,
                              O_RDONLY, 0600, nullptr);
    if (err_open < 0) {
      pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to open torrent file",
             PG_L("err", err_open),
             PG_L("err_s", pg_cstr_to_string(strerror(err_open))),
             PG_L("path", torrent_file_path));
      return 1;
    }
    uv_file file = err_open;
    PG_ASSERT(file > 0);

    int err_stat = uv_fs_fstat(uv_default_loop(), &req, file, nullptr);
    if (err_stat < 0) {
      pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to stat torrent file",
             PG_L("err", err_stat),
             PG_L("err_s", pg_cstr_to_string(strerror(err_stat))),
             PG_L("path", torrent_file_path));
      return 1;
    }

    torrent_file_data = pg_string_make(req.statbuf.st_size, general_allocator);
    uv_buf_t buf = string_to_uv_buf(torrent_file_data);
    int err_read =
        uv_fs_read(uv_default_loop(), &req, file, &buf, 1, 0, nullptr);
    if (err_read < 0) {
      pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to read torrent file",
             PG_L("err", err_read),
             PG_L("err_s", pg_cstr_to_string(strerror(err_read))),
             PG_L("path", torrent_file_path));
      return 1;
    }

    pg_log(&logger, PG_LOG_LEVEL_DEBUG, "read torrent file",
           PG_L("path", torrent_file_path), PG_L("len", torrent_file_data.len));

    (void)uv_fs_close(uv_default_loop(), &req, file, nullptr);
    uv_fs_req_cleanup(&req);
  }
  PG_ASSERT(torrent_file_data.len > 0);

  DecodeMetaInfoResult res_decode_metainfo = bencode_decode_metainfo(
      torrent_file_data, pg_arena_allocator_as_allocator(&arena_allocator));
  if (res_decode_metainfo.err) {
    pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to decode metainfo",
           PG_L("err", res_decode_metainfo.err),
           PG_L("err_s",
                pg_cstr_to_string(strerror((i32)res_decode_metainfo.err))));
    return 1;
  }

  pg_log(&logger, PG_LOG_LEVEL_DEBUG, "decoded torrent file",
         PG_L("path", torrent_file_path));

  if (pg_string_eq(PG_S("https"), res_decode_metainfo.res.announce.scheme)) {
    pg_log(&logger, PG_LOG_LEVEL_ERROR,
           "announce url is using https but it is not yet implemented",
           PG_L("path", torrent_file_path),
           PG_L("announce.scheme", res_decode_metainfo.res.announce.scheme),
           PG_L("announce.host", res_decode_metainfo.res.announce.host));
    return 1;
  }

  PgFileResult target_file_res = download_file_create_if_not_exists(
      res_decode_metainfo.res.name, res_decode_metainfo.res.length);
  if (target_file_res.err) {
    pg_log(
        &logger, PG_LOG_LEVEL_ERROR, "failed to create download file",
        PG_L("path", res_decode_metainfo.res.name),
        PG_L("err", target_file_res.err),
        PG_L("err_s", pg_cstr_to_string(strerror((i32)target_file_res.err))));
    return 1;
  }

  u16 port_ours_torrent = 6881;
  TrackerMetadata tracker_metadata = {
      .port = port_ours_torrent,
      .left = res_decode_metainfo.res.length,
      .event = TRACKER_EVENT_STARTED,
      .announce = res_decode_metainfo.res.announce,
      .info_hash = pg_string_make(
          PG_SHA1_DIGEST_LENGTH,
          pg_arena_allocator_as_allocator(
              &arena_allocator)), // FIXME: Should use tracker's arena?
      .peer_id = pg_string_make(
          20, pg_arena_allocator_as_allocator(
                  &arena_allocator)), // FIXME: Should use tracker's arena?
  };
  tracker_compute_info_hash(res_decode_metainfo.res, tracker_metadata.info_hash,
                            arena);
  u32 pieces_count = download_compute_pieces_count(
      res_decode_metainfo.res.piece_length, res_decode_metainfo.res.length);
  PG_ASSERT(pieces_count > 0);

  // TODO: Tweak.
  u64 concurrent_download_max = 30;
  Download download = {
      .pieces_have =
          pg_string_make(pg_div_ceil(pieces_count, 8), general_allocator),
      .pieces_count = pieces_count,
      .blocks_count =
          (u32)pg_div_ceil(res_decode_metainfo.res.length, BLOCK_SIZE),
      .max_blocks_per_piece_count = download_compute_max_blocks_per_piece_count(
          res_decode_metainfo.res.piece_length),
      .piece_length = res_decode_metainfo.res.piece_length,
      .total_file_size = res_decode_metainfo.res.length,
      .file = target_file_res.res,
      .logger = &logger,
      .rng = &rng,
      .concurrent_downloads_max = concurrent_download_max,
      .pieces_hash = res_decode_metainfo.res.pieces,
  };
  PG_ASSERT(download.max_blocks_per_piece_count > 0);
  pg_log(
      &logger, PG_LOG_LEVEL_DEBUG, "download",
      PG_L("path", res_decode_metainfo.res.name),
      PG_L("pieces_count", download.pieces_count),
      PG_L("blocks_count", download.blocks_count),
      PG_L("max_blocks_per_piece_count", download.max_blocks_per_piece_count),
      PG_L("piece_length", download.piece_length),
      PG_L("total_file_size", download.total_file_size),
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
      &download, res_decode_metainfo.res.name, res_decode_metainfo.res.pieces);
  if (res_bitfield_pieces.err) {
    pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to load bitfield from file",
           PG_L("path", res_decode_metainfo.res.name),
           PG_L("err", res_bitfield_pieces.err),
           PG_L("err_s",
                pg_cstr_to_string(strerror((i32)res_bitfield_pieces.err))));
    return 1;
  }
  pg_log(&logger, PG_LOG_LEVEL_DEBUG, "loaded bitfield from file",
         PG_L("path", res_decode_metainfo.res.name),
         PG_L("local_bitfield_have_count",
              pg_bitfield_count(download.pieces_have)));

  PgUrl announce = res_decode_metainfo.res.announce;

  Tracker tracker = tracker_make(
      &logger, announce.host, announce.port, tracker_metadata, &download,
      res_decode_metainfo.res.pieces, general_allocator);

  uv_timer_t download_metrics_timer = {0};
  download_metrics_timer.data = &download;
  {
    int err_timer_init =
        uv_timer_init(uv_default_loop(), &download_metrics_timer);
    if (err_timer_init < 0) {
      pg_log(&logger, PG_LOG_LEVEL_ERROR,
             "failed to init download metrics timer",
             PG_L("path", res_decode_metainfo.res.name),
             PG_L("err", err_timer_init));
      return 1;
    }

    int err_timer_start = uv_timer_start(&download_metrics_timer,
                                         download_on_timer, 1'000, 1'000);
    if (err_timer_start < 0) {
      pg_log(&logger, PG_LOG_LEVEL_ERROR,
             "failed to start download metrics timer",
             PG_L("path", res_decode_metainfo.res.name),
             PG_L("err", err_timer_start));
      return 1;
    }
  }

  if (tracker_start_dns_resolve(&tracker, announce)) {
    return 1;
  }

  uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}
