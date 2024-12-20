#include "peer.c"
#include <sys/poll.h>

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

  struct pollfd *fds = arena_new(&arena, struct pollfd, peers.len);
  for (u64 i = 0; i < peers.len; i++) {
    Peer *peer = dyn_at_ptr(&peers, i);
    peer->arena = arena_make_from_virtual_mem(4 * KiB);
    Error err = peer_connect(peer);
    if (err) {
      log(LOG_LEVEL_ERROR, "peer connect", &arena, L("ipv4", peer->ipv4),
          L("port", peer->port), L("err", err));
      // TODO: Remove peer.
      continue;
    }

    struct pollfd *fd = AT_PTR(fds, peers.len, i);
    fd->fd = (int)(u64)peer->reader.ctx;
    fd->events = POLLIN | POLLOUT;
  }

  for (;;) {
    int res_poll = poll(fds, peers.len, 0);
    if (-1 == res_poll) {
      log(LOG_LEVEL_ERROR, "poll", &arena, L("err", errno));
      return errno;
    }

    for (u64 i = 0; i < peers.len; i++) {
      struct pollfd fd = AT(fds, peers.len, i);
      Peer *peer = dyn_at_ptr(&peers, i);

      if ((fd.revents & POLLERR) || (fd.revents & POLLHUP)) {
        log(LOG_LEVEL_ERROR, "peer socket error/end", &arena,
            L("ipv4", peer->ipv4), L("port", peer->port),
            L("fd.revents", (u64)fd.revents));
        // TODO: Remove peer.
        continue;
      }

      bool can_read = fd.revents & POLLIN;
      bool can_write = fd.revents & POLLOUT;
      Error err = peer_tick(peer, can_read, can_write);
      if (err) {
        log(LOG_LEVEL_ERROR, "peer_tick error", &arena, L("ipv4", peer->ipv4),
            L("port", peer->port), L("err", err));
        // TODO: Remove peer.
        continue;
      }
    }
  }
}
