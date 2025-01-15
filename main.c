#include "peer.c"
#include "tracker.c"

int main(int argc, char *argv[]) {
  PG_ASSERT(argc == 2);

  PgArena arena = pg_arena_make_from_virtual_mem(128 * PG_KiB);
  PgLogger logger = pg_log_logger_make_stdout_json(PG_LOG_LEVEL_DEBUG);

  PgAioQueueCreateResult res_queue_create = pg_aio_queue_create();
  if (res_queue_create.err) {
    pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to create aio queue", arena,
           PG_L("err", res_queue_create.err));
    return 1;
  }
  PgAioQueue queue = res_queue_create.res;
  (void)queue; // FIXME.

  PgString torrent_file_path = cstr_to_string(argv[1]);
  PgStringResult res_torrent_file_read =
      file_read_full(torrent_file_path, &arena);
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
  {
    PgAioEvent event = {
        .socket = tracker.socket,
        .kind = PG_AIO_EVENT_KIND_OUT,
        .action = PG_AIO_EVENT_ACTION_ADD,
    };
    PgError err = pg_aio_queue_ctl_one(queue, event);
    if (err) {
      pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to watch for an I/O event",
             arena, PG_L("err", err));
      return 1;
    }
  }

  PgAioEventSlice events_watch = PG_SLICE_MAKE(PgAioEvent, 16, &arena);
  PgAioEventDyn events_change = {0};
  PG_DYN_ENSURE_CAP(&events_change, 128, &arena);

  for (;;) {
    PG_ASSERT(0 == events_change.len);

    Pgu64Result res_wait = pg_aio_queue_wait(queue, events_watch, -1, arena);
    if (res_wait.err) {
      pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to wait for events", arena,
             PG_L("err", res_decode_metainfo.err));
      return 1;
    }

    for (u64 i = 0; i < res_wait.res; i++) {
      PgAioEvent event_watch = PG_SLICE_AT(events_watch, i);
      if (PG_AIO_EVENT_KIND_ERR & event_watch.kind) {
        pg_log(&logger, PG_LOG_LEVEL_ERROR, "event error", arena,
               PG_L("socket", (PgSocket)event_watch.socket));
        (void)pg_net_socket_close(event_watch.socket);
        continue;
      }

      if (event_watch.socket == tracker.socket) {
        if ((PG_AIO_EVENT_KIND_IN & event_watch.kind) &&
            pg_ring_write_space(tracker.rg) > 0) {
          {
            Pgu64Result res_read =
                pg_reader_read(&tracker.reader, &tracker.rg, arena);
            if (res_read.err) {
              pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to read", arena,
                     PG_L("err", res_read.err),
                     PG_L("socket", (PgSocket)event_watch.socket));
              (void)pg_net_socket_close(event_watch.socket);
              continue;
            }
            pg_log(&logger, PG_LOG_LEVEL_DEBUG, "read", arena,
                   PG_L("count", res_read.res),
                   PG_L("socket", (PgSocket)event_watch.socket));
          }
        }
        {
          PgError err = tracker_handle_event(&tracker, event_watch,
                                             &events_change, &arena);
          if (err) {
            (void)pg_net_socket_close(event_watch.socket);
            continue;
          }
        }

        if ((PG_AIO_EVENT_KIND_OUT & event_watch.kind) &&
            pg_ring_read_space(tracker.rg) > 0) {
          {
            Pgu64Result res_write =
                pg_writer_write(&tracker.writer, &tracker.rg, arena);
            if (res_write.err) {
              pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to write", arena,
                     PG_L("err", res_write.err),
                     PG_L("socket", (PgSocket)event_watch.socket));
              (void)pg_net_socket_close(event_watch.socket);
              continue;
            }
            pg_log(&logger, PG_LOG_LEVEL_DEBUG, "written", arena,
                   PG_L("len", res_write.res),
                   PG_L("socket", (PgSocket)event_watch.socket));
          }
        }
      }
    }

    {
      PgError err =
          pg_aio_queue_ctl(queue, PG_DYN_SLICE(PgAioEventSlice, events_change));
      if (err) {
        pg_log(&logger, PG_LOG_LEVEL_ERROR, "failed to watch for I/O events",
               arena, PG_L("err", err));
        return 1;
      }
      events_change.len = 0;
    }
  }
}
