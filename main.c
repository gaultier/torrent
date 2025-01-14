#if 0
#include "peer.c"
 static const u64 liveness_seconds = 15;
#endif

#include "tracker.c"

int main(int argc, char *argv[]) {
  ASSERT(argc == 2);

  Arena arena = arena_make_from_virtual_mem(128 * KiB);
  Logger logger = log_logger_make_stdout_json(LOG_LEVEL_DEBUG);

  AioQueueCreateResult res_queue_create = net_aio_queue_create();
  if (res_queue_create.err) {
    logger_log(&logger, LOG_LEVEL_ERROR, "failed to create aio queue", arena,
               L("err", res_queue_create.err));
    return 1;
  }
  AioQueue queue = res_queue_create.res;
  (void)queue; // FIXME.

  String torrent_file_path = cstr_to_string(argv[1]);
  StringResult res_torrent_file_read =
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
  TrackerRequest tracker_req = {
      .port = port_ours_torrent,
      .left = res_decode_metainfo.res.length,
      .event = TRACKER_EVENT_STARTED,
      .announce = res_decode_metainfo.res.announce,
      .info_hash = string_make(20, &arena),
      .peer_id = string_make(20, &arena),
  };
  tracker_compute_info_hash(res_decode_metainfo.res, tracker_req.info_hash,
                            arena);

  Socket tracker_socket = 0;
  {
    DnsResolveIpv4AddressSocketResult res_dns = net_dns_resolve_ipv4_tcp(
        tracker_req.announce.host, tracker_req.announce.port, arena);
    if (res_dns.err) {
      logger_log(&logger, LOG_LEVEL_ERROR,
                 "failed to dns resolve the tracker announce url", arena,
                 L("err", res_dns.err));
      return 1;
    }
    ASSERT(0 != res_dns.res.socket);
    tracker_socket = res_dns.res.socket;

    logger_log(&logger, LOG_LEVEL_DEBUG, "dns resolved tracker announce url",
               arena, L("url.host", tracker_req.announce.host),
               L("url.port", tracker_req.announce.port),
               L("ip", res_dns.res.address.ip));
  }
  {
    Error err = net_socket_set_blocking(tracker_socket, false);
    if (err) {
      logger_log(&logger, LOG_LEVEL_ERROR,
                 "failed to set socket to non blocking", arena, L("err", err));
      return 1;
    }
  }

  {
    AioEvent event = {
        .socket = tracker_socket,
        .kind = AIO_EVENT_KIND_OUT,
        .action = AIO_EVENT_ACTION_KIND_ADD,
    };
    Error err = net_aio_queue_ctl_one(queue, event);
    if (err) {
      logger_log(&logger, LOG_LEVEL_ERROR, "failed to watch for an I/O event",
                 arena, L("err", res_decode_metainfo.err));
      return 1;
    }
  }
  RingBuffer tracker_io = {.data = string_make(4096, &arena)};
  HttpRequest tracker_http_req = tracker_make_request(tracker_req, &arena);
  Reader tracker_reader = reader_make_from_socket(tracker_socket);
  Writer tracker_writer = writer_make_from_socket(tracker_socket);

  AioEventSlice events_watch = slice_make(AioEvent, 16, &arena);
  for (;;) {
    IoCountResult res_wait = net_aio_queue_wait(queue, events_watch, -1, arena);
    if (res_wait.err) {
      logger_log(&logger, LOG_LEVEL_ERROR, "failed to wait for events", arena,
                 L("err", res_decode_metainfo.err));
      return 1;
    }

    for (u64 i = 0; i < res_wait.res; i++) {
      AioEvent event_watch = slice_at(events_watch, i);
      if (AIO_EVENT_KIND_ERR & event_watch.kind) {
        logger_log(&logger, LOG_LEVEL_ERROR, "event error", arena,
                   L("socket", (Socket)event_watch.socket));
        (void)net_socket_close(event_watch.socket);
        continue;
      }

      if (event_watch.socket == tracker_socket) {
        if (AIO_EVENT_KIND_OUT & event_watch.kind) {
          {
            Error err =
                http_write_request(&tracker_io, tracker_http_req, arena);
            if (err) {
              logger_log(&logger, LOG_LEVEL_ERROR,
                         "failed to write http request to ring buffer", arena,
                         L("write_space", ring_buffer_write_space(tracker_io)));
              (void)net_socket_close(event_watch.socket);
              continue;
            }
          }
          logger_log(&logger, LOG_LEVEL_DEBUG,
                     "wrote http request to ring buffer", arena,
                     L("write_space", ring_buffer_write_space(tracker_io)));

          {
            Error err = writer_write(&tracker_writer, &tracker_io, arena).err;
            if (err) {
              logger_log(&logger, LOG_LEVEL_ERROR,
                         "failed to write http request to socket", arena,
                         L("err", err));
              (void)net_socket_close(event_watch.socket);
              continue;
            }
          }
          {
            AioEvent event_change = {
                .socket = tracker_socket,
                .kind = AIO_EVENT_KIND_IN,
                .action = AIO_EVENT_ACTION_KIND_MOD,
            };
            Error err = net_aio_queue_ctl_one(queue, event_change);
            if (err) {
              logger_log(&logger, LOG_LEVEL_ERROR,
                         "failed to watch for an I/O event", arena,
                         L("err", res_decode_metainfo.err));
              return 1;
            }
          }
          // TODO: Reset ring buffer?
          logger_log(&logger, LOG_LEVEL_DEBUG, "watching for tracker response",
                     arena,
                     L("read_space", ring_buffer_read_space(tracker_io)));
        } else if (AIO_EVENT_KIND_IN & event_watch.kind) {
          {
            IoCountResult res_io =
                reader_read(&tracker_reader, &tracker_io, arena);
            if (res_io.err) {
              logger_log(&logger, LOG_LEVEL_ERROR,
                         "failed to read tracker response data", arena,
                         L("err", res_io.err));
              (void)net_socket_close(event_watch.socket);
              continue;
            }
            logger_log(&logger, LOG_LEVEL_DEBUG, "read tracker response data",
                       arena, L("count", res_io.res));
          }
          HttpResponseReadResult res_http = {0};
          {
            res_http = http_read_response(&tracker_io, 128, &arena);
            if (res_http.err) {
              logger_log(&logger, LOG_LEVEL_ERROR,
                         "invalid tracker http response", arena,
                         L("err", res_http.err));
              (void)net_socket_close(event_watch.socket);
              continue;
            }
          }
          logger_log(&logger, LOG_LEVEL_DEBUG, "read http tracker response",
                     arena, L("http.status", res_http.res.status));
          (void)net_socket_close(event_watch.socket);
          continue;

        } else {
          ASSERT(0);
        }
      }
    }
  }

#if 0
  TrackerResponseResult res_tracker = tracker_send_get_req(tracker_req, &arena);
  if (res_tracker.err) {
    log(LOG_LEVEL_ERROR, "tracker response", &arena, L("err", res_tracker.err));
    return 1;
  }
  log(LOG_LEVEL_INFO, "tracker response", &arena,
      L("addresses count", res_tracker.res.peer_addresses.len));

  DynIpv4Address peer_addresses = res_tracker.res.peer_addresses;
  ASSERT(20 == tracker_req.info_hash.len);

  DynPeer peers_active = {0};
  u64 PEERS_ACTIVE_DESIRED_COUNT = 4;
  dyn_ensure_cap(&peers_active, PEERS_ACTIVE_DESIRED_COUNT, &arena);

  Dynpollfd poll_fds = {0};
  dyn_ensure_cap(&poll_fds, PEERS_ACTIVE_DESIRED_COUNT, &arena);

  for (;;) {
    // Try to reach the desired count of active peers.
    {
      u64 to_pick = peers_active.len < PEERS_ACTIVE_DESIRED_COUNT
                        ? PEERS_ACTIVE_DESIRED_COUNT - peers_active.len
                        : 0;
      peer_pick_random(&peer_addresses, &peers_active, to_pick,
                       tracker_req.info_hash, &arena);
    }

    // Spawn peers and register them to the poll list to be able to wait on them
    // with timeout.
    {
      poll_fds.len = 0;
      for (u64 i = 0; i < peers_active.len; i++) {
        Peer *peer = slice_at_ptr(&peers_active, i);
        peer_spawn(peer);

        *dyn_push(&poll_fds, &arena) = (pollfd){
            .fd = peer->pipe_child_to_parent[0],
            .events = POLLIN | POLLHUP,
        };
      }
    }
    ASSERT(peers_active.len == poll_fds.len);

    // Poll.
    {
      if (-1 ==
          poll(poll_fds.data, poll_fds.len, (int)liveness_seconds * 1000)) {
        log(LOG_LEVEL_ERROR, "failed to poll(2)", &arena, L("err", errno));
        exit(errno);
      }
    }

    //
    {
      for (u64 i = 0; i < poll_fds.len; i++) {
        pollfd event = slice_at(poll_fds, i);
        Peer *peer = slice_at_ptr(&peers_active, i);

        if (event.revents & POLLIN) { // Child is live!
          u64 live_ns = 0;
          read(event.fd, &live_ns, sizeof(live_ns));

          log(LOG_LEVEL_INFO, "peer live message", &arena,
              L("ipv4", peer->address.ip), L("port", peer->address.port),
              L("poll.revents", (int)event.revents),
              L("peers_active.len", peers_active.len),
              L("duration_since_last_live_message_ns",
                live_ns - peer->liveness_last_message_ns));
          peer->liveness_last_message_ns = live_ns;
        } else if (event.revents &
                   (POLLHUP |
                    POLLERR)) { // Pipe closed, or error: Kill the child.
          peer->tombstone = true;
          log(LOG_LEVEL_INFO, "peer child pipe closed or errored", &arena,
              L("ipv4", peer->address.ip), L("port", peer->address.port),
              L("poll.revents", (int)event.revents),
              L("peers_active.len", peers_active.len));
        } else if (event.revents == 0) { // Timeout?
          u64 now_ns = monotonic_now_ns();
          ASSERT(now_ns >= peer->liveness_last_message_ns);

          u64 duration_ns = now_ns - peer->liveness_last_message_ns;
          if (duration_ns >= (liveness_seconds * 1000'000'000)) {
            peer->tombstone = true;
            log(LOG_LEVEL_INFO, "peer timed out", &arena,
                L("ipv4", peer->address.ip), L("port", peer->address.port),
                L("poll.revents", (int)event.revents),
                L("peers_active.len", peers_active.len),
                L("duration_ns", duration_ns));
          }
        }
      }
    }
    ASSERT(peers_active.len == poll_fds.len);

    // Garbage collect.
    for (u64 i = 0; i < peers_active.len; i++) {
      Peer peer = slice_at(peers_active, i);
      if (!peer.tombstone) {
        continue;
      }

      log(LOG_LEVEL_INFO, "garbage collect peer", &arena,
          L("ipv4", peer.address.ip), L("port", peer.address.port), L("i", i),
          L("peers_active.len", peers_active.len));
      kill(peer.pid, SIGKILL);
      slice_swap_remove(&peers_active, i);
      i -= 1;
    }
  }
#endif
}
