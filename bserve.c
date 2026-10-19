

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#include "bhttp_protocol.h"

static int read_exact(int fd, void *buf, size_t n)
{
    size_t done = 0;
    while (done < n) {
        ssize_t r = read(fd, (char *)buf + done, n - done);
        if (r <= 0) return -1;
        done += (size_t)r;
    }
    return 0;
}

static int write_exact(int fd, const void *buf, size_t n)
{
    size_t done = 0;
    while (done < n) {
        ssize_t w = write(fd, (const char *)buf + done, n - done);
        if (w <= 0) return -1;
        done += (size_t)w;
    }
    return 0;
}


static void hexdump(const char *label, const uint8_t *buf, size_t len)
{
    fprintf(stderr, "=== %s (%zu bytes) ===\n", label, len);
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) fprintf(stderr, "  %04zx  ", i);
        fprintf(stderr, "%02x ", buf[i]);
        if ((i + 1) % 8  == 0 && (i + 1) % 16 != 0) fprintf(stderr, " ");
        if ((i + 1) % 16 == 0 || i + 1 == len) {
            size_t line_start = (i / 16) * 16;
            size_t pad = 16 - (i % 16 + 1);
            for (size_t p = 0; p < pad; p++) fprintf(stderr, "   ");
            if (pad >= 8) fprintf(stderr, " ");
            fprintf(stderr, " |");
            for (size_t j = line_start; j <= i; j++) {
                unsigned char c = buf[j];
                fprintf(stderr, "%c", (c >= 0x20 && c < 0x7F) ? c : '.');
            }
            fprintf(stderr, "|\n");
        }
    }
    fprintf(stderr, "\n");
}


static int send_headers_frame(int fd, uint32_t stream_id,
                               uint16_t status, uint8_t flags)
{
    uint8_t payload[3];
    put_u16(payload, status);
    payload[2] = 0; 

    uint8_t hdr[FRAME_HEADER_SIZE];
    encode_frame_hdr(hdr, sizeof(payload), FRAME_HEADERS, flags, stream_id);

    uint8_t out[FRAME_HEADER_SIZE + sizeof(payload)];
    memcpy(out, hdr, FRAME_HEADER_SIZE);
    memcpy(out + FRAME_HEADER_SIZE, payload, sizeof(payload));

    hexdump("TX HEADERS", out, sizeof(out));
    return write_exact(fd, out, sizeof(out));
}

static int send_headers_200(int fd, uint32_t stream_id,
                              off_t file_size, const char *mime)
{
    
    uint8_t payload[512];
    size_t  pos = 0;

    put_u16(payload + pos, 200); pos += 2;
    payload[pos++] = 2; 
    char cl_val[32];
    int cl_len = snprintf(cl_val, sizeof(cl_val), "%lld", (long long)file_size);
    payload[pos++] = HDR_CONTENT_LENGTH;
    put_u16(payload + pos, (uint16_t)cl_len); pos += 2;
    memcpy(payload + pos, cl_val, cl_len); pos += cl_len;

    size_t mt_len = strlen(mime);
    payload[pos++] = HDR_CONTENT_TYPE;
    put_u16(payload + pos, (uint16_t)mt_len); pos += 2;
    memcpy(payload + pos, mime, mt_len); pos += mt_len;

    uint8_t hdr[FRAME_HEADER_SIZE];
    encode_frame_hdr(hdr, (uint32_t)pos, FRAME_HEADERS,
                     FLAG_END_HEADERS, stream_id);

    uint8_t out[FRAME_HEADER_SIZE + 512];
    memcpy(out, hdr, FRAME_HEADER_SIZE);
    memcpy(out + FRAME_HEADER_SIZE, payload, pos);

    hexdump("TX HEADERS(200)", out, FRAME_HEADER_SIZE + pos);
    return write_exact(fd, out, FRAME_HEADER_SIZE + pos);
}

static int send_data_frame(int fd, uint32_t stream_id,
                            const uint8_t *data, size_t len, int last)
{
    uint8_t hdr[FRAME_HEADER_SIZE];
    encode_frame_hdr(hdr, (uint32_t)len, FRAME_DATA,
                     last ? FLAG_END_STREAM : 0, stream_id);

    if (write_exact(fd, hdr, FRAME_HEADER_SIZE) != 0) return -1;
    if (len > 0 && write_exact(fd, data, len) != 0) return -1;

    uint8_t preview[FRAME_HEADER_SIZE + 64];
    memcpy(preview, hdr, FRAME_HEADER_SIZE);
    size_t plen = len > 64 ? 64 : len;
    if (data) memcpy(preview + FRAME_HEADER_SIZE, data, plen);
    hexdump("TX DATA", preview, FRAME_HEADER_SIZE + plen);
    if (len > 64) fprintf(stderr, "  ... (%zu more bytes elided)\n\n", len - 64);

    return 0;
}


static const char *guess_mime(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    if (strcmp(dot, ".html") == 0 || strcmp(dot, ".htm") == 0)
        return "text/html";
    if (strcmp(dot, ".css")  == 0) return "text/css";
    if (strcmp(dot, ".js")   == 0) return "application/javascript";
    if (strcmp(dot, ".json") == 0) return "application/json";
    if (strcmp(dot, ".png")  == 0) return "image/png";
    if (strcmp(dot, ".jpg")  == 0 || strcmp(dot, ".jpeg") == 0)
        return "image/jpeg";
    if (strcmp(dot, ".txt")  == 0) return "text/plain";
    return "application/octet-stream";
}

static void handle_request(int client_fd, uint32_t stream_id,
                             const uint8_t *payload, uint32_t plen,
                             const char *root)
{
    const uint8_t *p   = payload;
    uint32_t       rem = plen;

    if (rem < 1) goto bad_request;
    uint8_t method = *p++; rem--;
    (void)method; 
    if (rem < 2) goto bad_request;
    uint16_t path_len = get_u16(p); p += 2; rem -= 2;
    if (rem < path_len) goto bad_request;

    char path_buf[4096];
    if (path_len == 0 || path_len >= sizeof(path_buf) - 1) goto bad_request;
    memcpy(path_buf, p, path_len);
    path_buf[path_len] = '\0';
    p += path_len; rem -= path_len;

    if (rem < 1) goto bad_request;
    uint8_t hdr_count = *p++; rem--;
    bhttp_header_t hdrs[32] = {0};
    if (hdr_count > 32) goto bad_request;
    int consumed = parse_headers(p, rem, hdr_count, hdrs);
    if (consumed < 0) {
        for (int i = 0; i < hdr_count; i++) {
            free(hdrs[i].name); free(hdrs[i].value);
        }
        goto bad_request;
    }
    for (int i = 0; i < hdr_count; i++) {
        fprintf(stderr, "  hdr[%d]: %s: %s\n", i, hdrs[i].name, hdrs[i].value);
        free(hdrs[i].name); free(hdrs[i].value);
    }

    if (strstr(path_buf, "..")) {
        fprintf(stderr, "[server] path traversal blocked: %s\n", path_buf);
        send_headers_frame(client_fd, stream_id, 400, FLAG_END_HEADERS | FLAG_END_STREAM);
        return;
    }

    char fs_path[8192];
    const char *rel = path_buf[0] == '/' ? path_buf + 1 : path_buf;
    snprintf(fs_path, sizeof(fs_path), "%s/%s", root, rel);

    fprintf(stderr, "[server] GET %s → %s\n", path_buf, fs_path);

    struct stat st;
    if (stat(fs_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "[server] 404 not found\n");
        send_headers_frame(client_fd, stream_id, 404,
                           FLAG_END_HEADERS | FLAG_END_STREAM);
        return;
    }

    int file_fd = open(fs_path, O_RDONLY);
    if (file_fd < 0) {
        send_headers_frame(client_fd, stream_id, 500,
                           FLAG_END_HEADERS | FLAG_END_STREAM);
        return;
    }

    const char *mime = guess_mime(fs_path);
    send_headers_200(client_fd, stream_id, st.st_size, mime);

    uint8_t chunk[65536];
    off_t   remaining = st.st_size;
    while (remaining > 0) {
        size_t to_read = remaining > (off_t)sizeof(chunk)
                         ? sizeof(chunk) : (size_t)remaining;
        ssize_t nr = read(file_fd, chunk, to_read);
        if (nr <= 0) break;
        remaining -= nr;
        int last = (remaining == 0) ? 1 : 0;
        if (send_data_frame(client_fd, stream_id, chunk, nr, last) != 0) break;
    }

    close(file_fd);
    return;

bad_request:
    fprintf(stderr, "[server] 400 malformed request\n");
    send_headers_frame(client_fd, stream_id, 400,
                       FLAG_END_HEADERS | FLAG_END_STREAM);
}


static void handle_connection(int client_fd, const char *root)
{
    fprintf(stderr, "[server] connection established\n");

    for (;;) {
        uint8_t hdr_buf[FRAME_HEADER_SIZE];
        if (read_exact(client_fd, hdr_buf, FRAME_HEADER_SIZE) != 0) {
            fprintf(stderr, "[server] connection closed / read error\n");
            break;
        }

        bhttp_frame_hdr_t hdr;
        decode_frame_hdr(hdr_buf, &hdr);

        fprintf(stderr, "[server] RX frame: type=0x%02x flags=0x%02x "
                "stream=%u length=%u\n",
                hdr.type, hdr.flags, hdr.stream_id, hdr.length);

        uint8_t *payload = NULL;
        if (hdr.length > 0) {
            if (hdr.length > 16 * 1024 * 1024) { /* 16 MiB sanity cap */
                fprintf(stderr, "[server] frame too large, dropping connection\n");
                break;
            }
            payload = malloc(hdr.length);
            if (!payload) { perror("malloc"); break; }
            if (read_exact(client_fd, payload, hdr.length) != 0) {
                free(payload);
                fprintf(stderr, "[server] read error while reading payload\n");
                break;
            }
        }

        uint8_t *full = malloc(FRAME_HEADER_SIZE + hdr.length);
        if (full) {
            memcpy(full, hdr_buf, FRAME_HEADER_SIZE);
            if (payload) memcpy(full + FRAME_HEADER_SIZE, payload, hdr.length);
            hexdump("RX frame", full, FRAME_HEADER_SIZE + hdr.length);
            free(full);
        }

        switch (hdr.type) {
        case FRAME_REQUEST:
            handle_request(client_fd, hdr.stream_id,
                           payload, hdr.length, root);
            break;

        default:
            fprintf(stderr, "[server] unknown frame type 0x%02x — skipping %u bytes\n",
                    hdr.type, hdr.length);
            break;
        }

        free(payload);
    }

    close(client_fd);
    fprintf(stderr, "[server] connection closed\n");
}


int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <root_dir> <port>\n", argv[0]);
        return 1;
    }

    const char *root = argv[1];
    int         port = atoi(argv[2]);

    signal(SIGPIPE, SIG_IGN);

    int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons((uint16_t)port),
        .sin_addr.s_addr = INADDR_ANY,
    };

    if (bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind"); return 1;
    }
    if (listen(srv_fd, 8) != 0) {
        perror("listen"); return 1;
    }

    fprintf(stderr, "[server] bserve listening on port %d, root=%s\n", port, root);

    for (;;) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int client_fd = accept(srv_fd, (struct sockaddr *)&cli_addr, &cli_len);
        if (client_fd < 0) { perror("accept"); continue; }

        fprintf(stderr, "[server] accepted connection from %s:%d\n",
                inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));

        handle_connection(client_fd, root);
    }

    close(srv_fd);
    return 0;
}
