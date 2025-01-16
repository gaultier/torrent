#include "peer.c"
#include "tracker.c"

int main(int argc, char *argv[]) {
  PG_ASSERT(argc == 2);

  PgArena arena = pg_arena_make_from_virtual_mem(128 * PG_KiB);
  PgLogger logger = pg_log_make_logger_stdout_json(PG_LOG_LEVEL_DEBUG);

  PgAioQueueResult res_queue_create = pg_aio_queue_create();
  if (res_queue_create.err) {
    pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to create aio queue", arena,
           PG_L("err", res_queue_create.err));
    return 1;
  }
  PgAioQueue queue = res_queue_create.res;
  (void)queue; // FIXME.

  PgString torrent_file_path = cstr_to_string(argv[1]);
  PgStringResult res_torrent_file_read =
      pg_file_read_full(torrent_file_path, &arena);
  if (0 != res_torrent_file_read.err) {
    pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to read torrent file", arena,
           PG_L("err", res_torrent_file_read.err),
           PG_L("path", torrent_file_path));
    return 1;
  }
  pg_log(&logger, PG_LOG_LEVEL_DEBUG, "read torrent file", arena,
         PG_L("path", torrent_file_path),
         PG_L("len", res_torrent_file_read.res.len));

  DecodeMetaInfoResult res_decode_metainfo =
      bencode_decode_metainfo(res_torrent_file_read.res, &arena);
  if (res_decode_metainfo.err) {
    pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to decode metainfo", arena,
           PG_L("err", res_decode_metainfo.err));
    return 1;
  }

  pg_log(&logger, PG_LOG_LEVEL_DEBUG, "decoded torrent file", arena,
         PG_L("path", torrent_file_path));

  u16 port_ours_torrent = 6881;
  TrackerMetadata tracker_metadata = {
      .port = port_ours_torrent,
      .left = res_decode_metainfo.res.length,
      .event = TRACKER_EVENT_STARTED,
      .announce = res_decode_metainfo.res.announce,
      .info_hash =
          pg_string_make(20, &arena), // FIXME: Should use tracker's arena?
      .peer_id =
          pg_string_make(20, &arena), // FIXME: Should use tracker's arena?
  };
  tracker_compute_info_hash(res_decode_metainfo.res, tracker_metadata.info_hash,
                            arena);

  PgUrl announce = res_decode_metainfo.res.announce;
  Tracker tracker =
      tracker_make(&logger, announce.host, announce.port, tracker_metadata);
  {
    PgError err = tracker_connect(&tracker);
    if (err) {
      return 1;
    }
  }
  PgEventLoopResult res_loop =
      pg_event_loop_make_loop(pg_arena_make_from_virtual_mem(256 * PG_KiB));
  if (res_loop.err) {
    pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to create event loop", arena,
           PG_L("err", res_loop.err));
    return 1;
  }
  PgEventLoop loop = res_loop.res;
  {
    Pgu64Result res_tracker = pg_event_loop_dns_resolve_ipv4_tcp(
        &loop, announce.host, announce.port, tracker_on_dns_resolve, &tracker);
    if (res_tracker.err) {
      pg_log(&logger, PG_LOG_LEVEL_ERROR,
             "failed to create an event loop dns request for the tracker",
             arena, PG_L("err", res_tracker.err));
      return 1;
    }
    u64 tracker_handle = res_tracker.res;
  }

  PgError err_loop = pg_event_loop_run(&loop, -1);
  if (err_loop) {
    pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to run the event loop", arena,
           PG_L("err", err_loop));
    return 1;
  }
}
