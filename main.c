#include "peer.c"
#include "submodules/c-http/submodules/cstd/lib.c"
#include <sys/epoll.h>

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
  log(LOG_LEVEL_INFO, "tracker response", &arena,
      L("addresses count", res_tracker.resp.peer_addresses.len));

  DynIpv4Address peer_addresses = res_tracker.resp.peer_addresses;
  ASSERT(20 == req_tracker.info_hash.len);

  DynPeer peers_active = {0};
  for (u64 i = 0; i < MIN(3, peer_addresses.len); i++) {
    Ipv4Address address = slice_at(peer_addresses, i);
    Peer peer = peer_make(address, req_tracker.info_hash);
    *dyn_push(&peers_active, &arena) = peer;
    peer_spawn(&peer);
  }
  sleep(10000);

#if 0
  u64 PEERS_ACTIVE_DESIRED_COUNT = 16;
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
