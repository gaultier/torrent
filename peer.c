#pragma once

#include "tracker.c"

[[noreturn]]
static void peer_run(Peer peer, Arena *arena) {
  log(LOG_LEVEL_INFO, "running peer", arena, L("ipv4", peer.ipv4),
      L("port", peer.port));

  for (;;) {
    // TODO
  }
}
