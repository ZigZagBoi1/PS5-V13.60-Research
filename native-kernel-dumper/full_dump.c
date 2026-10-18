#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <ps5/kernel.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define RECEIVER_IP "10.0.0.231"
#define RECEIVER_PORT 8888
#define DUMP_PATH "/dump"
#define KERNEL_BASE UINT64_C(0xffffffff8a9c0000)
#define SYSENT_RVA UINT64_C(0x00e6e5c0)
#define TEXT_LENGTH SYSENT_RVA
#define DATA_OFFSET UINT64_C(0x01000000)
#define DATA_LENGTH UINT64_C(0x00400000)
#define SYSENT_AREA_OFFSET (SYSENT_RVA - UINT64_C(0x1000))
#define SYSENT_AREA_LENGTH UINT64_C(0x10000)
#define READ_CHUNK 0x4000U
#define READ_DELAY_NS 100000000L
#define PROGRESS_INTERVAL 256U
#define NETWORK_RETRIES 5U

static void pause_between_reads(void) {
  const struct timespec delay = { .tv_sec = 0, .tv_nsec = READ_DELAY_NS };
  while (nanosleep(&delay, NULL) < 0 && errno == EINTR) {}
}

static int send_all(int fd, const void *buffer, size_t length) {
  const unsigned char *p = buffer;
  while (length) {
    ssize_t n = send(fd, p, length, 0);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return -1;
    p += (size_t)n;
    length -= (size_t)n;
  }
  return 0;
}

static int post_chunk(const char *filename, size_t index, size_t total,
                      uint64_t offset, const char *read_status,
                      const void *data, size_t length) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;

  struct sockaddr_in server;
  memset(&server, 0, sizeof(server));
  server.sin_len = sizeof(server);
  server.sin_family = AF_INET;
  server.sin_port = htons(RECEIVER_PORT);
  if (inet_pton(AF_INET, RECEIVER_IP, &server.sin_addr) != 1 ||
      connect(fd, (struct sockaddr *)&server, sizeof(server)) < 0) {
    close(fd);
    return -1;
  }

  char header[640];
  int n = snprintf(header, sizeof(header),
      "POST " DUMP_PATH " HTTP/1.1\r\n"
      "Host: " RECEIVER_IP ":%d\r\n"
      "X-Filename: %s\r\n"
      "X-Chunk: %zu/%zu\r\n"
      "X-Offset: %" PRIu64 "\r\n"
      "X-Read-Status: %s\r\n"
      "Content-Type: application/octet-stream\r\n"
      "Content-Length: %zu\r\n"
      "Connection: close\r\n\r\n",
      RECEIVER_PORT, filename, index, total, offset,
      read_status ? read_status : "n/a", length);
  if (n <= 0 || (size_t)n >= sizeof(header) ||
      send_all(fd, header, (size_t)n) < 0 || send_all(fd, data, length) < 0) {
    close(fd);
    return -1;
  }

  char response[256] = {0};
  ssize_t got;
  do { got = recv(fd, response, sizeof(response) - 1, 0); }
  while (got < 0 && errno == EINTR);
  close(fd);
  if (got <= 0 || strncmp(response, "HTTP/1.", 7) != 0 ||
      (strstr(response, " 200 ") == NULL && strstr(response, " 201 ") == NULL &&
       strstr(response, " 204 ") == NULL)) {
    fprintf(stderr, "receiver rejected %s chunk %zu/%zu: %.100s\n",
        filename, index, total, response);
    return -1;
  }
  return 0;
}

static int post_with_retry(const char *filename, size_t index, size_t total,
                           uint64_t offset, const char *read_status,
                           const void *data, size_t length) {
  for (unsigned attempt = 1; attempt <= NETWORK_RETRIES; ++attempt) {
    if (post_chunk(filename, index, total, offset, read_status, data, length) == 0)
      return 0;
    if (attempt < NETWORK_RETRIES) pause_between_reads();
  }
  fprintf(stderr, "network transfer failed after %u tries: %s chunk %zu/%zu\n",
      NETWORK_RETRIES, filename, index, total);
  return -1;
}

static int send_progress(const char *region, size_t done, size_t total,
                         uint64_t bytes_done, size_t failed) {
  char json[512];
  int n = snprintf(json, sizeof(json),
      "{\"region\":\"%s\",\"chunks_done\":%zu,\"chunks_total\":%zu,"
      "\"bytes_done\":%" PRIu64 ",\"zero_filled_chunks\":%zu}\n",
      region, done, total, bytes_done, failed);
  if (n < 0 || (size_t)n >= sizeof(json)) return -1;
  return post_with_retry("dump_progress.json", 1, 1, 0, "n/a", json, (size_t)n);
}

static int dump_region(uint64_t address, size_t length, const char *filename) {
  unsigned char buffer[READ_CHUNK];
  size_t chunks = (length + READ_CHUNK - 1) / READ_CHUNK;
  unsigned char *failmap = calloc(chunks, 1);
  if (!failmap) {
    perror("failmap allocation");
    return -1;
  }

  size_t failed = 0;
  for (size_t i = 0, offset = 0; offset < length; ++i) {
    size_t count = length - offset;
    if (count > sizeof(buffer)) count = sizeof(buffer);

    const char *read_status = "ok";
    if (kernel_copyout((intptr_t)(address + offset), buffer, count) != 0) {
      memset(buffer, 0, count);
      failmap[i] = 1;
      ++failed;
      read_status = "zero-filled";
    }

    if (post_with_retry(filename, i + 1, chunks, offset, read_status,
                        buffer, count) < 0) {
      free(failmap);
      return -1;
    }

    offset += count;
    if ((i + 1) % PROGRESS_INTERVAL == 0 || i + 1 == chunks) {
      printf("%s: %zu/%zu chunks, %zu zero-filled\n",
          filename, i + 1, chunks, failed);
      fflush(stdout);
      if (send_progress(filename, i + 1, chunks, offset, failed) < 0) {
        free(failmap);
        return -1;
      }
    }
    if (offset < length) pause_between_reads();
  }

  char failmap_name[96];
  int name_len = snprintf(failmap_name, sizeof(failmap_name), "%s.failmap", filename);
  if (name_len < 0 || (size_t)name_len >= sizeof(failmap_name) ||
      post_with_retry(failmap_name, 1, 1, 0, "n/a", failmap, chunks) < 0) {
    free(failmap);
    return -1;
  }
  free(failmap);
  return 0;
}

int main(void) {
  const uint64_t base = KERNEL_BASE;
  const uint64_t sdk_base = (uint64_t)(uintptr_t)KERNEL_ADDRESS_TEXT_BASE;
  if (sdk_base != base) {
    fprintf(stderr, "kernel base mismatch: configured=0x%" PRIx64
        " SDK=0x%" PRIx64 "; refusing to read\n", base, sdk_base);
    return 1;
  }

  const struct {
    const char *name;
    uint64_t address;
    size_t length;
  } regions[] = {
    { "kernel_text.bin", base, (size_t)TEXT_LENGTH },
    { "kernel_data.bin", base + DATA_OFFSET, (size_t)DATA_LENGTH },
    { "sysent_area.bin", base + SYSENT_AREA_OFFSET, (size_t)SYSENT_AREA_LENGTH },
  };

  for (size_t i = 0; i < sizeof(regions) / sizeof(regions[0]); ++i) {
    printf("starting %s at 0x%" PRIx64 " (%zu bytes)\n",
        regions[i].name, regions[i].address, regions[i].length);
    fflush(stdout);
    if (dump_region(regions[i].address, regions[i].length, regions[i].name) < 0) {
      fprintf(stderr, "stopped after transfer failure in %s\n", regions[i].name);
      return 1;
    }
  }

  const char manifest[] =
      "{\"firmware\":\"13.60\",\"kernel_base\":\"0xffffffff8a9c0000\","
      "\"chunk_size\":16384,\"read_delay_ms\":100,"
      "\"regions\":["
      "{\"file\":\"kernel_text.bin\",\"offset\":\"0x0\",\"size\":\"0xe6e5c0\"},"
      "{\"file\":\"kernel_data.bin\",\"offset\":\"0x1000000\",\"size\":\"0x400000\"},"
      "{\"file\":\"sysent_area.bin\",\"offset\":\"0xe6d5c0\",\"size\":\"0x10000\"}],"
      "\"note\":\"Requested ranges are not complete ELF section boundaries; see repository dump README. Per-region .failmap uses 1 for kernel_copyout failure/zero-fill and 0 for success.\"}\n";
  if (post_with_retry("kernel_dump_manifest.json", 1, 1, 0, "n/a",
                      manifest, sizeof(manifest) - 1) < 0) {
    fprintf(stderr, "could not send dump manifest\n");
    return 1;
  }

  puts("requested kernel ranges sent successfully");
  return 0;
}
