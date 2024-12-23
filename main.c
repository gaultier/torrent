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

  DynPeer peers = res_tracker.resp.peers;
  *dyn_push(&peers, &arena) = (Peer){
      .ipv4 = 2130706433,
      .port = 1234,
      .info_hash = req_tracker.info_hash,
  };
  SlicePollFd poll_fds = {
      .data = arena_new(&arena, struct pollfd, peers.len),
      .len = peers.len,
  };

  {
    u64 i = 0;
    while (i < peers.len) {
      Peer *peer = dyn_at_ptr(&peers, i);
      peer->arena = arena_make_from_virtual_mem(4 * KiB);
      Error err = peer_connect(peer);
      if (err) {
        log(LOG_LEVEL_ERROR, "peer connect", &arena, L("ipv4", peer->ipv4),
            L("port", peer->port), L("err", err));
        peer_end(peer);
        slice_swap_remove(&peers, i);
        continue;
      }
      i += 1;
    }
  }

  for (;;) {
    struct timespec ts_now = {0};
    ASSERT(0 == clock_gettime(CLOCK_MONOTONIC, &ts_now));
    u64 now_ns = (u64)ts_now.tv_sec * 1000'1000'1000 + (u64)ts_now.tv_nsec;

    poll_fds.len = 0;
    for (u64 i = 0; i < peers.len; i++) {
      Peer *peer = AT_PTR(peers.data, peers.len, i);
      if (!(0 == peer->next_tick_ns || peer->next_tick_ns >= now_ns)) {
        continue;
      }

      peer->suspended = false;
      poll_fds.len += 1;

      struct pollfd *fd = AT_PTR(poll_fds.data, poll_fds.len, poll_fds.len - 1);
      fd->fd = (int)(u64)peer->reader.ctx;
      ASSERT(fd->fd > 0);
      fd->events = POLLIN | POLLOUT;

      log(LOG_LEVEL_INFO, "queued peer for polling", &arena,
          L("ipv4", peer->ipv4), L("port", peer->port));
    }

    ASSERT(poll_fds.len <= peers.len);

    int res_poll = poll(poll_fds.data, poll_fds.len, -1);
    if (-1 == res_poll) {
      log(LOG_LEVEL_ERROR, "poll", &arena, L("err", errno));
      return errno;
    }

    u64 i = 0;
    while (i < peers.len) {
      Peer *peer = dyn_at_ptr(&peers, i);
      if (peer->suspended) {
        log(LOG_LEVEL_INFO, "skipping suspended peer", &arena,
            L("ipv4", peer->ipv4), L("port", peer->port), L("now_ns", now_ns),
            L("peer.next_tick_ns", peer->next_tick_ns));
        continue;
      }

      struct pollfd fd = slice_at(poll_fds, i);

      if (fd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        int error = 0;
        socklen_t errlen = sizeof(error);
        getsockopt(fd.fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen);

        log(LOG_LEVEL_ERROR, "peer socket error/end", &arena,
            L("ipv4", peer->ipv4), L("port", peer->port),
            L("fd.revents", (u64)fd.revents), L("err", error),
            L("peer_count", peers.len));

        peer_end(peer);
        slice_swap_remove(&peers, i);
        slice_swap_remove(&poll_fds, i);
        continue;
      }

      bool can_read = fd.revents & POLLIN;
      bool can_write = fd.revents & POLLOUT;
      if (!(can_read || can_write)) {
        struct timespec ts = {0};
        ASSERT(0 == clock_gettime(CLOCK_MONOTONIC, &ts));
        u64 ts_ns = (u64)ts.tv_sec * 1000'1000'1000 + (u64)ts.tv_nsec;
        peer->next_tick_ns = ts_ns + 5'1000'1000'1000 /* 5s */;
        peer->suspended = true;
        log(LOG_LEVEL_INFO, "delaying inactive peer", &arena,
            L("ipv4", peer->ipv4), L("port", peer->port), L("now_ns", ts_ns),
            L("peer.next_tick_ns", peer->next_tick_ns));
        continue;
      }

      PeerTickResult res_peer_tick = peer_tick(peer, can_read, can_write);
      if (res_peer_tick.err) {
        log(LOG_LEVEL_ERROR, "peer_tick", &arena, L("ipv4", peer->ipv4),
            L("port", peer->port), L("err", res_peer_tick.err));

        peer_end(peer);
        slice_swap_remove(&peers, i);
        slice_swap_remove(&poll_fds, i);
        continue;
      }
      log(LOG_LEVEL_INFO, "peer_tick", &arena, L("ipv4", peer->ipv4),
          L("port", peer->port),
          L("progressed", (u32)res_peer_tick.progressed));
      if (!res_peer_tick.progressed) {
        struct timespec ts = {0};
        ASSERT(0 == clock_gettime(CLOCK_MONOTONIC, &ts));
        u64 ts_ns = (u64)ts.tv_sec * 1000'1000'1000 + (u64)ts.tv_nsec;
        peer->next_tick_ns = ts_ns + 5'1000'1000'1000 /* 5s */;
        peer->suspended = true;
        log(LOG_LEVEL_INFO, "delaying unprogressed peer", &arena,
            L("ipv4", peer->ipv4), L("port", peer->port), L("now_ns", now_ns),
            L("peer.next_tick_ns", peer->next_tick_ns));
      } else {
        peer->next_tick_ns = 0;
        peer->suspended = false;
      }
    }
    usleep(100'000);
    i += 1;
  }
}
