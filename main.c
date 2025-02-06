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

  PgArena arena = pg_arena_make_from_virtual_mem(1 * PG_MiB);
  PgLogger logger = pg_log_make_logger_stdout_logfmt(PG_LOG_LEVEL_DEBUG);
  PgRng rng = pg_rand_make();

  PgString torrent_file_path = pg_cstr_to_string(argv[1]);
  PgStringResult res_torrent_file_read =
      pg_file_read_full(torrent_file_path, &arena);
  if (0 != res_torrent_file_read.err) {
    pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to read torrent file",
           PG_L("err", res_torrent_file_read.err),
           PG_L("err_s",
                pg_cstr_to_string(strerror((i32)res_torrent_file_read.err))),
           PG_L("path", torrent_file_path));
    return 1;
  }
  pg_log(&logger, PG_LOG_LEVEL_DEBUG, "read torrent file",
         PG_L("path", torrent_file_path),
         PG_L("len", res_torrent_file_read.res.len));

  DecodeMetaInfoResult res_decode_metainfo =
      bencode_decode_metainfo(res_torrent_file_read.res, &arena);
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
      res_decode_metainfo.res.name, res_decode_metainfo.res.length, arena);
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
      .info_hash = pg_string_make(PG_SHA1_DIGEST_LENGTH,
                                  &arena), // FIXME: Should use tracker's arena?
      .peer_id =
          pg_string_make(20, &arena), // FIXME: Should use tracker's arena?
  };
  tracker_compute_info_hash(res_decode_metainfo.res, tracker_metadata.info_hash,
                            arena);
  u32 pieces_count = download_compute_pieces_count(
      res_decode_metainfo.res.piece_length, res_decode_metainfo.res.length);
  PG_ASSERT(pieces_count > 0);

  PgStringResult res_bitfield_pieces = download_load_bitfield_pieces_from_disk(
      res_decode_metainfo.res.name, res_decode_metainfo.res.pieces,
      res_decode_metainfo.res.piece_length, pieces_count, &logger, &arena);
  if (res_bitfield_pieces.err) {
    pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to load bitfield from file",
           PG_L("path", res_decode_metainfo.res.name),
           PG_L("err", res_bitfield_pieces.err),
           PG_L("err_s",
                pg_cstr_to_string(strerror((i32)res_bitfield_pieces.err))));
    return 1;
  }

  Download download = {
      .pieces_have = res_bitfield_pieces.res,
      .pieces_count = pieces_count,
      .max_blocks_per_piece_count = download_compute_max_blocks_per_piece_count(
          res_decode_metainfo.res.piece_length),
      .piece_length = res_decode_metainfo.res.piece_length,
      .total_file_size = res_decode_metainfo.res.length,
      .file = target_file_res.res,
      .logger = &logger,
      .rng = &rng,
  };
  PG_ASSERT(download.max_blocks_per_piece_count > 0);

  pg_log(&logger, PG_LOG_LEVEL_DEBUG, "loaded bitfield from file",
         PG_L("path", res_decode_metainfo.res.name),
         PG_L("local_bitfield_have_count",
              pg_bitfield_count(download.pieces_have)));

  PgUrl announce = res_decode_metainfo.res.announce;

  u64 concurrent_pieces_download_max = 5;
  u64 concurrent_blocks_download_max = 5;
  Tracker tracker = tracker_make(
      uv_default_loop(), &logger, announce.host, announce.port,
      tracker_metadata, &download, concurrent_pieces_download_max,
      concurrent_blocks_download_max, res_decode_metainfo.res.pieces);
  (void)tracker;

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

  {
    pg_log(&logger, PG_LOG_LEVEL_DEBUG, "tracker: dns resolving",
           PG_L("host", announce.host));

    uv_getaddrinfo_t dns_req = {0};
    dns_req.data = &tracker;
    struct addrinfo hints = {0};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    int err_getaddrinfo = uv_getaddrinfo(
        uv_default_loop(), &dns_req, tracker_on_dns_resolve,
        pg_string_to_cstr(announce.host, &arena),
        pg_string_to_cstr(pg_u64_to_string(announce.port, &arena), &arena),
        &hints);
    if (err_getaddrinfo < 0) {
      pg_log(&logger, PG_LOG_LEVEL_ERROR,
             "failed to create an event loop dns request for the tracker",
             PG_L("err", err_getaddrinfo),
             PG_L("err_s",
                  pg_cstr_to_string((char *)uv_strerror(err_getaddrinfo))));
      return 1;
    }
  }

  uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}
