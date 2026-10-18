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
#define SYSENT_RVA UINT64_C(0xE6E5C0)
#define SYSENT_COUNT 679U
#define SYSENT_ENTRY_SIZE 48U
#define READ_CHUNK 0x1000U
#define READ_DELAY_NS 100000000L
#define FIRST_SONY_SYSCALL 532U
#define LAST_SONY_SYSCALL 676U
#define HANDLER_SIZE 0x1000U

static uint64_t kernel_base(void) {
  return (uint64_t)(uintptr_t)KERNEL_ADDRESS_TEXT_BASE;
}

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
                      uint64_t offset, const void *data, size_t length) {
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

  char header[512];
  int header_len = snprintf(header, sizeof(header),
      "POST " DUMP_PATH " HTTP/1.1\r\n"
      "Host: " RECEIVER_IP ":%d\r\n"
      "X-Filename: %s\r\n"
      "X-Chunk: %zu/%zu\r\n"
      "X-Offset: %" PRIu64 "\r\n"
      "Content-Type: application/octet-stream\r\n"
      "Content-Length: %zu\r\n"
      "Connection: close\r\n\r\n",
      RECEIVER_PORT, filename, index, total, offset, length);
  if (header_len <= 0 || (size_t)header_len >= sizeof(header) ||
      send_all(fd, header, (size_t)header_len) < 0 ||
      send_all(fd, data, length) < 0) {
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
    fprintf(stderr, "receiver rejected %s chunk %zu: %.100s\n", filename, index, response);
    return -1;
  }
  return 0;
}

static int read_and_post(uint64_t address, const char *filename, size_t total_size,
                         unsigned char *copy_out) {
  unsigned char buffer[READ_CHUNK];
  const size_t total_chunks = (total_size + READ_CHUNK - 1) / READ_CHUNK;
  for (size_t i = 0, offset = 0; offset < total_size; ++i) {
    size_t length = total_size - offset;
    if (length > sizeof(buffer)) length = sizeof(buffer);
    if (kernel_copyout((intptr_t)(address + offset), buffer, length) != 0) {
      fprintf(stderr, "kernel_copyout failed: %s + 0x%zx\n", filename, offset);
      return -1;
    }
    if (copy_out) memcpy(copy_out + offset, buffer, length);
    if (post_chunk(filename, i + 1, total_chunks, offset, buffer, length) < 0) {
      fprintf(stderr, "network send failed: %s chunk %zu/%zu\n", filename, i + 1, total_chunks);
      return -1;
    }
    offset += length;
    printf("%s: %zu/%zu chunks (%zu/%zu bytes)\n",
        filename, i + 1, total_chunks, offset, total_size);
    fflush(stdout);
    if (offset < total_size) pause_between_reads();
  }
  return 0;
}

static int validate_sysent(uint64_t base, unsigned char *sample) {
  uint64_t table = base + SYSENT_RVA;
  if (kernel_copyout((intptr_t)table, sample, READ_CHUNK) != 0) {
    fprintf(stderr, "sysent validation read failed at 0x%" PRIx64 "\n", table);
    return -1;
  }

  unsigned valid = 0;
  for (size_t i = 0; i < 8; ++i) {
    uint64_t handler;
    memcpy(&handler, sample + i * SYSENT_ENTRY_SIZE + 8, sizeof(handler));
    if (handler >= base && handler < (uint64_t)(uintptr_t)KERNEL_ADDRESS_DATA_BASE)
      ++valid;
  }
  if (valid < 6) {
    fprintf(stderr, "sysent sanity check failed: only %u/8 handlers in kernel text range\n", valid);
    return -1;
  }
  return 0;
}

static int dump_handler(uint64_t base, const unsigned char *entry, unsigned syscall_no) {
  uint64_t handler;
  memcpy(&handler, entry + 8, sizeof(handler));
  uint64_t data_base = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DATA_BASE;
  if (handler < base || handler >= data_base) {
    fprintf(stderr, "syscall %u has out-of-range handler 0x%" PRIx64 "; skipping\n",
        syscall_no, handler);
    return 0;
  }

  char filename[64];
  snprintf(filename, sizeof(filename), "syscall_%u_handler.bin", syscall_no);
  return read_and_post(handler, filename, HANDLER_SIZE, NULL);
}

int main(void) {
  const uint64_t base = kernel_base();
  const size_t table_size = SYSENT_COUNT * SYSENT_ENTRY_SIZE;
  unsigned char sample[READ_CHUNK];
  unsigned char *table = malloc(table_size);
  if (!table) {
    perror("malloc sysent");
    return 1;
  }

  printf("PS5 13.60 kernel dumper\nbase=0x%" PRIx64 " sysent=0x%" PRIx64 "\n",
      base, base + SYSENT_RVA);
  if (base < UINT64_C(0xffff800000000000) || validate_sysent(base, sample) < 0) {
    fprintf(stderr, "kernel base/sysent sanity check failed; stopping before dump\n");
    free(table);
    return 1;
  }

  if (read_and_post(base + SYSENT_RVA, "sysent_raw.bin", table_size, table) < 0) {
    fprintf(stderr, "sysent extraction failed\n");
    free(table);
    return 1;
  }

  for (unsigned n = FIRST_SONY_SYSCALL; n <= LAST_SONY_SYSCALL; ++n) {
    const unsigned char *entry = table + (size_t)n * SYSENT_ENTRY_SIZE;
    if (dump_handler(base, entry, n) < 0) {
      fprintf(stderr, "stopping after syscall %u; completed files remain on receiver\n", n);
      free(table);
      return 1;
    }
    if (n < LAST_SONY_SYSCALL) pause_between_reads();
  }

  free(table);
  puts("sysent and Sony handler extraction complete");
  return 0;
}
