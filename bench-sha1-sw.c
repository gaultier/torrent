#include "sha1_sw.c"
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static bool is_chunk_valid(uint8_t *chunk, uint64_t chunk_len,
                           uint8_t digest_expected[20]) {
  SHA1_CTX ctx = {0};
  SHA1Init(&ctx);

  SHA1Update(&ctx, chunk, chunk_len);

  uint8_t digest_actual[20] = {0};
  SHA1Final(digest_actual, &ctx);

  return !memcmp(digest_actual, digest_expected, 20);
}

int main(int argc, char *argv[]) {
  if (3 != argc) {
    return 1;
  }

  int file_download = open(argv[1], O_RDONLY, 0600);
  if (!file_download) {
    return 1;
  }

  struct stat st_download = {0};
  if (-1 == fstat(file_download, &st_download)) {
    return 1;
  }
  size_t file_download_size = (size_t)st_download.st_size;

  uint8_t *file_download_data = mmap(NULL, file_download_size, PROT_READ,
                                     MAP_FILE | MAP_PRIVATE, file_download, 0);
  if (!file_download_data) {
    return 1;
  }

  int file_torrent = open(argv[2], O_RDONLY, 0600);
  if (!file_torrent) {
    return 1;
  }

  struct stat st_torrent = {0};
  if (-1 == fstat(file_torrent, &st_torrent)) {
    return 1;
  }
  size_t file_torrent_size = (size_t)st_torrent.st_size;

  uint8_t *file_torrent_data = mmap(NULL, file_torrent_size, PROT_READ,
                                    MAP_FILE | MAP_PRIVATE, file_torrent, 0);
  if (!file_torrent_data) {
    return 1;
  }
  // HACK
  uint64_t file_torrent_data_offset = 237;
  file_torrent_data += file_torrent_data_offset;
  file_torrent_size -= file_torrent_data_offset - 1;

  uint64_t piece_length = 262144;
  uint64_t pieces_count = file_download_size / piece_length +
                          ((0 == file_download_size % piece_length) ? 0 : 1);
  for (uint64_t i = 0; i < pieces_count; i++) {
    uint8_t *data = file_download_data + i * piece_length;
    uint64_t piece_length_real = ((i + 1) == pieces_count)
                                     ? (file_download_size - i * piece_length)
                                     : piece_length;
    uint8_t *digest_expected = file_torrent_data + i * 20;

    if (!is_chunk_valid(data, piece_length_real, digest_expected)) {
      return 1;
    }
  }
}
