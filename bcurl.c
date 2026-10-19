

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "bhttp_protocol.h"


static int verbose = 0;   
static int sock_fd = -1;  


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
    if (!verbose) return;
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

static int tcp_connect(const char *host, int port)
{
    struct addrinfo hints = {
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
    };
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo *res;
    int err = getaddrinfo(host, port_str, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "[bcurl] getaddrinfo: %s\n", gai_strerror(err));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        fprintf(stderr, "[bcurl] could not connect to %s:%d\n", host, port);
    } else {
        fprintf(stderr, "[bcurl] connected to %s:%d\n", host, port);
    }
    return fd;
}


static uint8_t *build_request_frame(const char *path, uint32_t stream_id,
                                     const char *host, size_t *out_len)
{
    
    const char *ua    = "bcurl/1.0";
    const char *accept = "* /*";

    size_t path_len  = strlen(path);
    size_t host_len  = strlen(host);
    size_t ua_len    = strlen(ua);
    size_t acc_len   = strlen(accept);

    
    size_t payload_sz =
        1 +                        
        2 + path_len +             
        1 +                        
        1 + 2 + host_len +         
        1 + 2 + ua_len +           
        1 + 2 + acc_len;           

    size_t total = FRAME_HEADER_SIZE + payload_sz;
    uint8_t *buf = malloc(total);
    if (!buf) { perror("malloc"); return NULL; }

    uint8_t *p = buf + FRAME_HEADER_SIZE;

    *p++ = METHOD_GET;

    put_u16(p, (uint16_t)path_len); p += 2;
    memcpy(p, path, path_len);      p += path_len;


    *p++ = 3;


    *p++ = HDR_HOST;
    put_u16(p, (uint16_t)host_len); p += 2;
    memcpy(p, host, host_len);      p += host_len;

    
    *p++ = HDR_USER_AGENT;
    put_u16(p, (uint16_t)ua_len);   p += 2;
    memcpy(p, ua, ua_len);          p += ua_len;

    *p++ = HDR_ACCEPT;
    put_u16(p, (uint16_t)acc_len);  p += 2;
    memcpy(p, accept, acc_len);     p += acc_len;

    encode_frame_hdr(buf, (uint32_t)payload_sz,
                     FRAME_REQUEST, FLAG_END_HEADERS, stream_id);

    *out_len = total;
    return buf;
}

static int read_response(int fd, uint32_t stream_id)
{
    int status_code = -1;
    int got_end_stream = 0;

    while (!got_end_stream) {
        uint8_t hdr_buf[FRAME_HEADER_SIZE];
        if (read_exact(fd, hdr_buf, FRAME_HEADER_SIZE) != 0) {
            fprintf(stderr, "[bcurl] connection closed reading frame header\n");
            return -1;
        }

        bhttp_frame_hdr_t hdr;
        decode_frame_hdr(hdr_buf, &hdr);

        uint8_t *payload = NULL;
        if (hdr.length > 0) {
            if (hdr.length > 16 * 1024 * 1024) {
                fprintf(stderr, "[bcurl] frame too large\n");
                return -1;
            }
            payload = malloc(hdr.length);
            if (!payload) { perror("malloc"); return -1; }
            if (read_exact(fd, payload, hdr.length) != 0) {
                free(payload);
                fprintf(stderr, "[bcurl] connection closed reading payload\n");
                return -1;
            }
        }

        if (verbose) {
            uint8_t *full = malloc(FRAME_HEADER_SIZE + hdr.length);
            if (full) {
                memcpy(full, hdr_buf, FRAME_HEADER_SIZE);
                if (payload) memcpy(full + FRAME_HEADER_SIZE, payload, hdr.length);
                hexdump("RX frame", full, FRAME_HEADER_SIZE + hdr.length);
                free(full);
            }
        }

        switch (hdr.type) {
        case FRAME_HEADERS: {
            if (hdr.stream_id != stream_id) {
                fprintf(stderr, "[bcurl] unexpected stream id %u\n", hdr.stream_id);
                free(payload); return -1;
            }
            if (hdr.length < 3) {
                fprintf(stderr, "[bcurl] HEADERS payload too short\n");
                free(payload); return -1;
            }
            status_code = (int)get_u16(payload);
            uint8_t hdr_count = payload[2];
            fprintf(stderr, "[bcurl] status %d, %d headers\n",
                    status_code, hdr_count);

            if (hdr_count > 0 && hdr.length > 3) {
                bhttp_header_t hdrs[32] = {0};
                int n = hdr_count > 32 ? 32 : hdr_count;
                int consumed = parse_headers(payload + 3, hdr.length - 3,
                                              n, hdrs);
                if (consumed > 0) {
                    for (int i = 0; i < n; i++) {
                        fprintf(stderr, "  %s: %s\n",
                                hdrs[i].name, hdrs[i].value);
                        free(hdrs[i].name);
                        free(hdrs[i].value);
                    }
                }
            }

            if (hdr.flags & FLAG_END_STREAM) got_end_stream = 1;
            break;
        }

        case FRAME_DATA: {
            if (hdr.stream_id != stream_id) {
                fprintf(stderr, "[bcurl] unexpected stream id %u\n", hdr.stream_id);
                free(payload); return -1;
            }
            if (payload && hdr.length > 0) {
                fwrite(payload, 1, hdr.length, stdout);
                fflush(stdout);
            }
            if (hdr.flags & FLAG_END_STREAM) got_end_stream = 1;
            break;
        }

        default:
            fprintf(stderr, "[bcurl] skipping unknown frame type 0x%02x "
                    "(%u bytes)\n", hdr.type, hdr.length);
            break;
        }

        free(payload);
    }

    return status_code;
}


static int parse_url(char *url_buf, char **host_out,
                     int *port_out, char **path_out)
{
    char *colon = strchr(url_buf, ':');
    char *slash = strchr(url_buf, '/');

    if (colon && (!slash || colon < slash)) {
        *colon = '\0';
        *host_out = url_buf;
        *port_out = atoi(colon + 1);
        *path_out = slash ? slash : "/";
    } else if (slash) {
        *slash = '\0';
        *host_out = url_buf;
        *port_out = 9000; 
        *slash = '/';
        *path_out = slash;
    } else {
        *host_out = url_buf;
        *port_out = 9000;
        *path_out = "/";
    }
    return 0;
}


int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [-v] <host:port/path>\n", argv[0]);
        return 1;
    }

    int arg_start = 1;
    if (strcmp(argv[1], "-v") == 0) {
        verbose = 1;
        arg_start = 2;
    }

    if (arg_start >= argc) {
        fprintf(stderr, "Usage: %s [-v] <host:port/path>\n", argv[0]);
        return 1;
    }

    char url_buf[2048];
    strncpy(url_buf, argv[arg_start], sizeof(url_buf) - 1);
    url_buf[sizeof(url_buf) - 1] = '\0';

    char *host; int port; char *path;
    if (parse_url(url_buf, &host, &port, &path) != 0) {
        fprintf(stderr, "[bcurl] invalid URL\n");
        return 1;
    }

    fprintf(stderr, "[bcurl] GET %s from %s:%d\n", path, host, port);

    sock_fd = tcp_connect(host, port);
    if (sock_fd < 0) return 1;

    uint32_t stream_id = 1;

    size_t   frame_len;
    uint8_t *frame = build_request_frame(path, stream_id, host, &frame_len);
    if (!frame) { close(sock_fd); return 1; }

    if (verbose) hexdump("TX REQUEST", frame, frame_len);

    if (write_exact(sock_fd, frame, frame_len) != 0) {
        fprintf(stderr, "[bcurl] send error\n");
        free(frame); close(sock_fd); return 1;
    }
    free(frame);

    int status = read_response(sock_fd, stream_id);
    close(sock_fd);

    if (status < 0) {
        fprintf(stderr, "[bcurl] error reading response\n");
        return 1;
    }

    fprintf(stderr, "[bcurl] done, status %d\n", status);

    return (status >= 400) ? 1 : 0;
}
