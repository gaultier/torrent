#include "peer.c"

typedef struct {
  struct pollfd *data;
  u64 len;
} SlicePollFd;

int main(int argc, char *argv[]) {
  ASSERT(argc == 2);

  struct sigaction sa = {.sa_flags = SA_NOCLDWAIT};
  if (-1 == sigaction(SIGCHLD, &sa, nullptr)) {
    exit(errno);
  }

  Arena arena = arena_make_from_virtual_mem(128 * KiB);

  String torrent_file_path = cstr_to_string(argv[1]);
  ReadFileResult res_torrent_file_read =
      file_read_full(torrent_file_path, &arena);
  if (0 != res_torrent_file_read.error) {
    log(LOG_LEVEL_ERROR, "read torrent file", &arena,
        L("err", res_torrent_file_read.error), L("path", torrent_file_path));
    return errno;
  }

  DecodeMetaInfoResult res_decode_metainfo =
      decode_metainfo(res_torrent_file_read.content, &arena);
  if (STATUS_OK != res_decode_metainfo.status) {
    log(LOG_LEVEL_ERROR, "decode metainfo", &arena,
        L("err", res_decode_metainfo.status));
    return 1;
  }

  u16 port_ours_torrent = 6881;
  TrackerRequest req_tracker = {
      .port = port_ours_torrent,
      .left = res_decode_metainfo.metainfo.length,
      .event = TRACKER_EVENT_STARTED,
      .announce = res_decode_metainfo.metainfo.announce,
      .info_hash = (String){.data = arena_alloc(&arena, 1, 1, 20), .len = 20},
      .peer_id = (String){.data = arena_alloc(&arena, 1, 1, 20), .len = 20},
  };
  tracker_compute_info_hash(res_decode_metainfo.metainfo, req_tracker.info_hash,
                            &arena);

  TrackerResponseResult res_tracker = tracker_send_get_req(req_tracker, &arena);
  if (STATUS_OK != res_tracker.status) {
    log(LOG_LEVEL_ERROR, "tracker response", &arena,
        L("err", res_tracker.status));
    return 1;
  }

  DynPeer peers_all = res_tracker.resp.peers;
  ASSERT(20 == req_tracker.info_hash.len);

  DynPeer peers_active = {0};
  dyn_ensure_cap(&peers_active, 5, &arena);
  peer_pick_random(&peers_all, &peers_active, 5, &arena);

  SlicePollFd poll_fds = {
      .data = arena_new(&arena, struct pollfd, peers_active.len),
      .len = peers_active.len,
  };
  for (;;) {
    poll_fds.len = peers_active.len;

    for (u64 i = 0; i < peers_active.len; i++) {
      Peer *peer = dyn_at_ptr(&peers_active, i);
      {
        struct pollfd *poll_fd = AT_PTR(poll_fds.data, poll_fds.len, i);
        poll_fd->events = POLL_IN;
        poll_fd->fd = (int)(u64)peer->reader.ctx;
        poll_fd->revents = 0;
      }

      int res_poll = poll(poll_fds.data, poll_fds.len, -1);
      if (-1 == res_poll) {
        exit(errno);
      }
      struct pollfd poll_fd = slice_at(poll_fds, i);

      if (poll_fd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        int error = 0;
        socklen_t errlen = sizeof(error);
        getsockopt(poll_fd.fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen);

        log(LOG_LEVEL_ERROR, "peer socket error/end", &arena,
            L("ipv4", peer->ipv4), L("port", peer->port),
            L("fd.revents", (u64)poll_fd.revents), L("err", error),
            L("peer_count", peers_active.len));

        peer_end(peer);
        slice_swap_remove(&peers_active, i);
        i -= 1;
        continue;
      }

      bool can_read = poll_fd.revents & POLL_IN;
      peer_tick(peer, can_read, false);
    }
  }
}
