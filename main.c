#include "peer.c"
#include "tracker.c"
#include <sys/poll.h>

typedef struct pollfd pollfd;
DYN(pollfd);

static const u64 liveness_seconds = 15;

int main(int argc, char *argv[]) {
  ASSERT(argc == 2);

  Arena arena = arena_make_from_virtual_mem(128 * KiB);

  AioQueueCreateResult res_queue_create = net_aio_queue_create();
  if (res_queue_create.err) {
    log(LOG_LEVEL_ERROR, "create aio queue", &arena,
        L("err", res_queue_create.err));
    return 1;
  }
  AioQueue queue = res_queue_create.res;

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
  if (res_decode_metainfo.err) {
    log(LOG_LEVEL_ERROR, "decode metainfo", &arena,
        L("err", res_decode_metainfo.err));
    return 1;
  }

  u16 port_ours_torrent = 6881;
  TrackerRequest req_tracker = {
      .port = port_ours_torrent,
      .left = res_decode_metainfo.res.length,
      .event = TRACKER_EVENT_STARTED,
      .announce = res_decode_metainfo.res.announce,
      .info_hash = (String){.data = arena_alloc(&arena, 1, 1, 20), .len = 20},
      .peer_id = (String){.data = arena_alloc(&arena, 1, 1, 20), .len = 20},
  };
  tracker_compute_info_hash(res_decode_metainfo.res, req_tracker.info_hash,
                            &arena);

  TrackerResponseResult res_tracker = tracker_send_get_req(req_tracker, &arena);
  if (res_tracker.err) {
    log(LOG_LEVEL_ERROR, "tracker response", &arena, L("err", res_tracker.err));
    return 1;
  }
  log(LOG_LEVEL_INFO, "tracker response", &arena,
      L("addresses count", res_tracker.res.peer_addresses.len));

  DynIpv4Address peer_addresses = res_tracker.res.peer_addresses;
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
}
