/*
 * File-mapped, lock-free transport shared by CXLMemSim server and QEMU.
 * The file is created by setup; neither endpoint creates it implicitly.
 */
#ifndef CXL_FILE_TRANSPORT_H
#define CXL_FILE_TRANSPORT_H

#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CXL_FILE_TRANSPORT_MAGIC 0x43584c46494c4531ULL /* CX LFILE1 */
#define CXL_FILE_TRANSPORT_VERSION 1U
#define CXL_FILE_MAX_CLIENTS 8U
#define CXL_FILE_RING_SIZE 256U

/* These payloads intentionally use only fixed-width C types. */
typedef struct {
    uint8_t op_type;
    uint8_t reserved0[7];
    uint64_t addr, size, timestamp, value, expected, resp_thread_id;
    uint32_t snp_type, metavalue, bisnp_resp_type;
    uint8_t data[64];
} cxl_file_request_t;

typedef struct {
    uint8_t op_type, status;
    uint8_t reserved0[6];
    uint64_t latency_ns, old_value, req_thread_id, addr;
    uint32_t bisnp_req_type;
    uint8_t data[64];
} cxl_file_response_t;

typedef struct {
    uint32_t head; /* written only by producer */
    uint32_t tail; /* written only by consumer */
    uint32_t wake_word;
    uint32_t reserved0;
    cxl_file_request_t entries[CXL_FILE_RING_SIZE];
} cxl_file_request_ring_t;

typedef struct {
    uint32_t head;
    uint32_t tail;
    uint32_t wake_word;
    uint32_t reserved0;
    cxl_file_response_t entries[CXL_FILE_RING_SIZE];
} cxl_file_response_ring_t;

typedef struct {
    uint64_t magic;
    uint32_t version;
    uint32_t server_ready;
    uint32_t client_active[CXL_FILE_MAX_CLIENTS];
    cxl_file_request_ring_t requests[CXL_FILE_MAX_CLIENTS];
    cxl_file_response_ring_t responses[CXL_FILE_MAX_CLIENTS];
} cxl_file_transport_layout_t;

typedef struct {
    int fd;
    size_t size;
    cxl_file_transport_layout_t *layout;
    uint32_t client_id;
} cxl_file_transport_t;

static inline size_t cxl_file_transport_size(void) { return sizeof(cxl_file_transport_layout_t); }
static inline int cxl_file_futex_wait(uint32_t *word, uint32_t expected) {
    return (int)syscall(SYS_futex, word, FUTEX_WAIT, expected, NULL, NULL, 0);
}
static inline void cxl_file_futex_wake(uint32_t *word) { (void)syscall(SYS_futex, word, FUTEX_WAKE, 1, NULL, NULL, 0); }
static inline bool cxl_file_transport_open(cxl_file_transport_t *transport, const char *path, bool server,
                                           uint32_t client_id) {
    struct stat st;
    memset(transport, 0, sizeof(*transport));
    transport->fd = open(path, O_RDWR | (server ? 0 : O_CLOEXEC));
    if (transport->fd < 0 || fstat(transport->fd, &st) != 0 ||
        (!server && (size_t)st.st_size != cxl_file_transport_size()) ||
        (server && (size_t)st.st_size != cxl_file_transport_size() &&
         ftruncate(transport->fd, cxl_file_transport_size()) != 0)) {
        if (transport->fd >= 0)
            close(transport->fd);
        transport->fd = -1;
        return false;
    }
    transport->size = cxl_file_transport_size();
    transport->layout = (cxl_file_transport_layout_t *)mmap(NULL, transport->size, PROT_READ | PROT_WRITE, MAP_SHARED,
                                                            transport->fd, 0);
    if (transport->layout == MAP_FAILED) {
        close(transport->fd);
        transport->fd = -1;
        transport->layout = NULL;
        return false;
    }
    transport->client_id = client_id;
    return true;
}
static inline void cxl_file_transport_close(cxl_file_transport_t *transport) {
    if (transport->layout)
        munmap(transport->layout, transport->size);
    if (transport->fd >= 0)
        close(transport->fd);
    memset(transport, 0, sizeof(*transport));
    transport->fd = -1;
}
static inline void cxl_file_transport_initialize(cxl_file_transport_t *transport) {
    memset(transport->layout, 0, transport->size);
    transport->layout->magic = CXL_FILE_TRANSPORT_MAGIC;
    transport->layout->version = CXL_FILE_TRANSPORT_VERSION;
    __atomic_store_n(&transport->layout->server_ready, 1, __ATOMIC_RELEASE);
}
static inline bool cxl_file_transport_ready(const cxl_file_transport_t *transport) {
    return transport->layout && transport->layout->magic == CXL_FILE_TRANSPORT_MAGIC &&
           transport->layout->version == CXL_FILE_TRANSPORT_VERSION &&
           __atomic_load_n(&transport->layout->server_ready, __ATOMIC_ACQUIRE);
}
static inline bool cxl_file_request_push(cxl_file_transport_t *t, const cxl_file_request_t *request) {
    cxl_file_request_ring_t *r = &t->layout->requests[t->client_id];
    uint32_t head = __atomic_load_n(&r->head, __ATOMIC_RELAXED);
    if (head - __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE) == CXL_FILE_RING_SIZE)
        return false;
    r->entries[head % CXL_FILE_RING_SIZE] = *request;
    __atomic_store_n(&r->head, head + 1, __ATOMIC_RELEASE);
    __atomic_add_fetch(&r->wake_word, 1, __ATOMIC_RELEASE);
    cxl_file_futex_wake(&r->wake_word);
    return true;
}
static inline bool cxl_file_request_pop(cxl_file_transport_t *t, uint32_t client_id, cxl_file_request_t *request) {
    cxl_file_request_ring_t *r = &t->layout->requests[client_id];
    uint32_t tail = __atomic_load_n(&r->tail, __ATOMIC_RELAXED);
    if (tail == __atomic_load_n(&r->head, __ATOMIC_ACQUIRE))
        return false;
    *request = r->entries[tail % CXL_FILE_RING_SIZE];
    __atomic_store_n(&r->tail, tail + 1, __ATOMIC_RELEASE);
    return true;
}
static inline bool cxl_file_response_push(cxl_file_transport_t *t, uint32_t client_id,
                                          const cxl_file_response_t *response) {
    cxl_file_response_ring_t *r = &t->layout->responses[client_id];
    uint32_t head = __atomic_load_n(&r->head, __ATOMIC_RELAXED);
    if (head - __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE) == CXL_FILE_RING_SIZE)
        return false;
    r->entries[head % CXL_FILE_RING_SIZE] = *response;
    __atomic_store_n(&r->head, head + 1, __ATOMIC_RELEASE);
    __atomic_add_fetch(&r->wake_word, 1, __ATOMIC_RELEASE);
    cxl_file_futex_wake(&r->wake_word);
    return true;
}
static inline bool cxl_file_response_pop(cxl_file_transport_t *t, cxl_file_response_t *response) {
    cxl_file_response_ring_t *r = &t->layout->responses[t->client_id];
    uint32_t tail = __atomic_load_n(&r->tail, __ATOMIC_RELAXED);
    if (tail == __atomic_load_n(&r->head, __ATOMIC_ACQUIRE))
        return false;
    *response = r->entries[tail % CXL_FILE_RING_SIZE];
    __atomic_store_n(&r->tail, tail + 1, __ATOMIC_RELEASE);
    return true;
}
#endif
