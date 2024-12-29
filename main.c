#include "peer.c"
#include <sys/poll.h>

typedef struct pollfd pollfd;
DYN(pollfd);

static const u64 liveness_seconds = 15;

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
  log(LOG_LEVEL_INFO, "tracker response", &arena,
      L("addresses count", res_tracker.resp.peer_addresses.len));

  DynIpv4Address peer_addresses = res_tracker.resp.peer_addresses;
  ASSERT(20 == req_tracker.info_hash.len);

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
                       req_tracker.info_hash, &arena);
    }

    // Spawn peers and register them to the poll list to be able to wait on them
    // with timeout.
    {
      poll_fds.len = 0;
      for (u64 i = 0; i < peers_active.len; i++) {
        Peer *peer = slice_at_ptr(&peers_active, i);
        peer_spawn(peer);

        *dyn_push(&poll_fds, &arena) = (pollfd){
            .fd = peer->parent_child_liveness_pipe[0],
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
          peer->liveness_last_message_ns = live_ns;
          log(LOG_LEVEL_INFO, "peer live message", &arena,
              L("ipv4", peer->address.ip), L("port", peer->address.port),
              L("poll.revents", (int)event.revents),
              L("peers_active.len", peers_active.len), L("live_ns", live_ns));
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
          if (duration_ns > liveness_seconds * 1000'1000'1000) {
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

#if 0
  DynPeer peers_active = {0};
  dyn_ensure_cap(&peers_active, PEERS_ACTIVE_DESIRED_COUNT, &arena);
  peer_pick_random(&peer_addresses, &peers_active, PEERS_ACTIVE_DESIRED_COUNT,
                   req_tracker.info_hash, &arena);

  int epollfd = epoll_create1(0);
  if (-1 == epollfd) {
    log(LOG_LEVEL_ERROR, "epoll_create1", &arena, L("err", errno));
    return errno;
  }

  for (;;) {
    for (u64 i = 0; i < peers_active.len; i++) {
      Peer *peer = dyn_at_ptr(&peers_active, i);
      if (peer->tombstone) {
        peer_end(peer);
        slice_swap_remove(&peers_active, i);
        i -= 1;
      }
    }

    if (peers_active.len < PEERS_ACTIVE_DESIRED_COUNT) {
      peer_pick_random(&peer_addresses, &peers_active,
                       PEERS_ACTIVE_DESIRED_COUNT - peers_active.len,
                       req_tracker.info_hash, &arena);
    }

    for (u64 i = 0; i < peers_active.len; i++) {
      Peer *peer = dyn_at_ptr(&peers_active, i);
      if (peer->tombstone) {
        continue;
      }

      {
        Error err = peer_connect_if_needed(peer);
        if (err) {
          peer->tombstone = true;
          continue;
        }
      }
      {
        ASSERT(PEER_STATE_NONE != peer->state);

        struct epoll_event ev = {0};
        ev.events = EPOLLIN;
        ev.data.fd = (int)(u64)peer->reader.ctx;
        ASSERT(0 != ev.data.fd);

        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ev.data.fd, &ev) == -1) {
          if (EEXIST != errno) {
            log(LOG_LEVEL_ERROR, "epoll_ctl add", &arena, L("err", errno));
            return errno;
          }
        }
      }
    }
#define MAX_EVENTS 10
    struct epoll_event events[MAX_EVENTS] = {0};
    int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
    if (-1 == nfds) {
      log(LOG_LEVEL_ERROR, "epoll_wait", &arena, L("err", errno));
      exit(errno);
    }

    for (int i = 0; i < nfds; i++) {
      struct epoll_event ev = events[i];
      Peer *peer = nullptr;
      for (u64 j = 0; j < peers_active.len; j++) {
        Peer *p = dyn_at_ptr(&peers_active, j);
        if ((int)(u64)p->reader.ctx == ev.data.fd) {
          peer = p;
          break;
        }
      }
      ASSERT(nullptr != peer);

      if (ev.events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
        int error = 0;
        socklen_t errlen = sizeof(error);
        getsockopt(ev.data.fd, SOL_SOCKET, SO_ERROR, (void *)&error, &errlen);

        log(LOG_LEVEL_ERROR, "peer socket error/end", &arena,
            L("ipv4", peer->address.ip), L("port", peer->address.port),
            L("events", (u64)ev.events), L("err", error),
            L("peer_count", peers_active.len));

        peer->tombstone = true;
        continue;
      }

      bool can_read = ev.events & EPOLLIN;
      if (!can_read) {
        continue;
      }
      PeerTickResult res_tick = peer_tick(peer, can_read, true);
      if (res_tick.err) {
        log(LOG_LEVEL_ERROR, "peer tick err, del", &arena,
            L("ipv4", peer->address.ip), L("port", peer->address.port),
            L("events", (u64)ev.events), L("err", res_tick.err));

        peer->tombstone = true;
      }
    }
  }
#endif
}
