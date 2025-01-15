#if 0
#include "peer.c"
 static const u64 liveness_seconds = 15;
#endif

#include "tracker.c"

int main(int argc, char *argv[]) {
  PG_ASSERT(argc == 2);

  Arena arena = arena_make_from_virtual_mem(128 * PG_KiB);
  Logger logger = log_logger_make_stdout_json(LOG_LEVEL_DEBUG);

  PgAioQueueCreateResult res_queue_create = aio_queue_create();
  if (res_queue_create.err) {
    logger_log(&logger, LOG_LEVEL_ERROR, "failed to create aio queue", arena,
               L("err", res_queue_create.err));
    return 1;
  }
  AioQueue queue = res_queue_create.res;
  (void)queue; // FIXME.

  PgString torrent_file_path = cstr_to_string(argv[1]);
  PgStringResult res_torrent_file_read =
      file_read_full(torrent_file_path, &arena);
  if (0 != res_torrent_file_read.err) {
    logger_log(&logger, LOG_LEVEL_ERROR, "failed to read torrent file", arena,
               L("err", res_torrent_file_read.err),
               L("path", torrent_file_path));
    return 1;
  }
  logger_log(&logger, LOG_LEVEL_DEBUG, "read torrent file", arena,
             L("path", torrent_file_path),
             L("len", res_torrent_file_read.res.len));

  DecodeMetaInfoResult res_decode_metainfo =
      bencode_decode_metainfo(res_torrent_file_read.res, &arena);
  if (res_decode_metainfo.err) {
    logger_log(&logger, LOG_LEVEL_ERROR, "failed to decode metainfo", arena,
               L("err", res_decode_metainfo.err));
    return 1;
  }

  logger_log(&logger, LOG_LEVEL_DEBUG, "decoded torrent file", arena,
             L("path", torrent_file_path));

  u16 port_ours_torrent = 6881;
  TrackerMetadata tracker_metadata = {
      .port = port_ours_torrent,
      .left = res_decode_metainfo.res.length,
      .event = TRACKER_EVENT_STARTED,
      .announce = res_decode_metainfo.res.announce,
      .info_hash =
          string_make(20, &arena),        // FIXME: Should use tracker's arena?
      .peer_id = string_make(20, &arena), // FIXME: Should use tracker's arena?
  };
  tracker_compute_info_hash(res_decode_metainfo.res, tracker_metadata.info_hash,
                            arena);

  Url announce = res_decode_metainfo.res.announce;
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
    PgError err = aio_queue_ctl_one(queue, event);
    if (err) {
      logger_log(&logger, LOG_LEVEL_ERROR, "failed to watch for an I/O event",
                 arena, L("err", err));
      return 1;
    }
  }

  PgAioEventSlice events_watch = slice_make(PgAioEvent, 16, &arena);
  DynAioEvent events_change = {0};
  dyn_ensure_cap(&events_change, 128, &arena);

  for (;;) {
    PG_ASSERT(0 == events_change.len);

    IoCountResult res_wait = aio_queue_wait(queue, events_watch, -1, arena);
    if (res_wait.err) {
      logger_log(&logger, LOG_LEVEL_ERROR, "failed to wait for events", arena,
                 L("err", res_decode_metainfo.err));
      return 1;
    }

    for (u64 i = 0; i < res_wait.res; i++) {
      PgAioEvent event_watch = slice_at(events_watch, i);
      if (PG_AIO_EVENT_KIND_ERR & event_watch.kind) {
        logger_log(&logger, LOG_LEVEL_ERROR, "event error", arena,
                   L("socket", (Socket)event_watch.socket));
        (void)net_socket_close(event_watch.socket);
        continue;
      }

      if (event_watch.socket == tracker.socket) {
        if ((PG_AIO_EVENT_KIND_IN & event_watch.kind) &&
            ring_buffer_write_space(tracker.rg) > 0) {
          {
            IoCountResult res_read =
                reader_read(&tracker.reader, &tracker.rg, arena);
            if (res_read.err) {
              logger_log(&logger, LOG_LEVEL_ERROR, "failed to read", arena,
                         L("err", res_read.err),
                         L("socket", (Socket)event_watch.socket));
              (void)net_socket_close(event_watch.socket);
              continue;
            }
            logger_log(&logger, LOG_LEVEL_DEBUG, "read", arena,
                       L("count", res_read.res),
                       L("socket", (Socket)event_watch.socket));
          }
        }
        {
          PgError err = tracker_handle_event(&tracker, event_watch,
                                           &events_change, &arena);
          if (err) {
            (void)net_socket_close(event_watch.socket);
            continue;
          }
        }

        if ((PG_AIO_EVENT_KIND_OUT & event_watch.kind) &&
            ring_buffer_read_space(tracker.rg) > 0) {
          {
            IoCountResult res_write =
                writer_write(&tracker.writer, &tracker.rg, arena);
            if (res_write.err) {
              logger_log(&logger, LOG_LEVEL_ERROR, "failed to write", arena,
                         L("err", res_write.err),
                         L("socket", (Socket)event_watch.socket));
              (void)net_socket_close(event_watch.socket);
              continue;
            }
            logger_log(&logger, LOG_LEVEL_DEBUG, "written", arena,
                       L("len", res_write.res),
                       L("socket", (Socket)event_watch.socket));
          }
        }
      }
    }

    {
      PgError err = aio_queue_ctl(queue, dyn_slice(PgAioEventSlice, events_change));
      if (err) {
        logger_log(&logger, LOG_LEVEL_ERROR, "failed to watch for I/O events",
                   arena, L("err", err));
        return 1;
      }
      events_change.len = 0;
    }
  }
}
