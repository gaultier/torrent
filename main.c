#include "peer.c"
#include <sys/poll.h>

typedef struct {
  struct pollfd *data;
  u64 len;
} SlicePollFd;

int main(int argc, char *argv[]) {
  ASSERT(argc == 2);

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

  for (u64 i = 0; i < peers_active.len; i++) {
    Peer *peer = dyn_at_ptr(&peers_active, i);
    peer->arena = arena_make_from_virtual_mem(4 * KiB);
    Error err = peer_connect(peer);
    if (err) {
      log(LOG_LEVEL_ERROR, "peer connect", &arena, L("ipv4", peer->ipv4),
          L("port", peer->port), L("err", err));
      peer_end(peer);
      slice_swap_remove(&peers_active, i);
      i -= 1;
    }

    peer->io_subscription = IO_OP_WILL_READ;
  }

  for (;;) {
    for (u64 i = 0; i < peers_active.len; i++) {
      Peer *peer = AT_PTR(peers_active.data, peers_active.len, i);
      struct pollfd *fd = AT_PTR(poll_fds.data, poll_fds.len, i);
      fd->fd = (int)(u64)peer->reader.ctx;
      ASSERT(fd->fd > 0);
      fd->events |= (peer->io_subscription & IO_OP_WILL_READ) ? POLLIN : 0;
      fd->events |= (peer->io_subscription & IO_OP_WILL_WRITE) ? POLLOUT : 0;

      log(LOG_LEVEL_INFO, "queued peer for polling", &arena,
          L("ipv4", peer->ipv4), L("port", peer->port),
          L("fd.events", (int)fd->events), L("poll_fds.len", poll_fds.len));
    }

    ASSERT(poll_fds.len == peers_active.len);

    int res_poll = poll(poll_fds.data, poll_fds.len, -1);
    if (-1 == res_poll) {
      log(LOG_LEVEL_ERROR, "poll", &arena, L("err", errno));
      return errno;
    }

    for (u64 i = 0; i < peers_active.len; i++) {
      Peer *peer = dyn_at_ptr(&peers_active, i);
      struct pollfd fd = slice_at(poll_fds, i);

      if (fd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        int error = 0;
        socklen_t errlen = sizeof(error);
        getsockopt(fd.fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen);

        log(LOG_LEVEL_ERROR, "peer socket error/end", &arena,
            L("ipv4", peer->ipv4), L("port", peer->port),
            L("fd.revents", (u64)fd.revents), L("err", error),
            L("peer_count", peers_active.len));

        peer_end(peer);
        slice_swap_remove(&peers_active, i);
        slice_swap_remove(&poll_fds, i);
        i -= 1;
        continue;
      }

      bool can_read = fd.revents & POLLIN;
      bool can_write = fd.revents & POLLOUT;
      if (!(can_read || can_write)) {
        continue;
      }

      PeerTickResult res_peer_tick = peer_tick(peer, can_read, can_write);
      if (res_peer_tick.err) {
        log(LOG_LEVEL_ERROR, "peer_tick", &arena, L("ipv4", peer->ipv4),
            L("port", peer->port), L("err", res_peer_tick.err));

        peer_end(peer);
        slice_swap_remove(&peers_active, i);
        slice_swap_remove(&poll_fds, i);
        i -= 1;
        continue;
      }

      log(LOG_LEVEL_INFO, "peer_tick", &arena, L("ipv4", peer->ipv4),
          L("port", peer->port),
          L("res.io_subscription", res_peer_tick.io_subscription));
      peer->io_subscription = res_peer_tick.io_subscription;
    }
  }
}
