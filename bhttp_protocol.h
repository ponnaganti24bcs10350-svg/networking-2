#ifndef BHTTP_PROTOCOL_H
#define BHTTP_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

#define FRAME_REQUEST   0x01
#define FRAME_HEADERS   0x02
#define FRAME_DATA      0x03

#define FLAG_END_STREAM  0x01
#define FLAG_END_HEADERS 0x04

#define METHOD_GET 0x01

#define FRAME_HEADER_SIZE 9

#define HDR_HOST            0x00
#define HDR_USER_AGENT      0x01
#define HDR_ACCEPT          0x02
#define HDR_CONTENT_TYPE    0x03
#define HDR_CONTENT_LENGTH  0x04
#define HDR_AUTHORIZATION   0x05
#define HDR_CACHE_CONTROL   0x06
#define HDR_ACCEPT_ENCODING 0x07
#define HDR_CONNECTION      0x08
#define HDR_REFERER         0x09
#define HDR_LITERAL         0xFF

static const char *bhttp_static_names[] = {
    "host", "user-agent", "accept", "content-type", "content-length",
    "authorization", "cache-control", "accept-encoding", "connection", "referer"
};

#define STATIC_HDR_COUNT 10

typedef struct {
    uint32_t length;
    uint8_t type;
    uint8_t flags;
    uint32_t stream_id;
} bhttp_frame_hdr_t;

typedef struct {
    char *name;
    char *value;
    int name_is_literal;
} bhttp_header_t;

typedef struct {
    uint8_t method;
    char *path;
    uint16_t path_len;
    uint8_t hdr_count;
    bhttp_header_t headers[32];
} bhttp_request_t;

static inline void put_u24(uint8_t *buf, uint32_t v)
{
    buf[0] = (v >> 16) & 0xFF;
    buf[1] = (v >> 8) & 0xFF;
    buf[2] = v & 0xFF;
}

static inline uint32_t get_u24(const uint8_t *buf)
{
    return ((uint32_t)buf[0] << 16) |
           ((uint32_t)buf[1] << 8) |
           (uint32_t)buf[2];
}

static inline void put_u32(uint8_t *buf, uint32_t v)
{
    buf[0] = (v >> 24) & 0xFF;
    buf[1] = (v >> 16) & 0xFF;
    buf[2] = (v >> 8) & 0xFF;
    buf[3] = v & 0xFF;
}

static inline uint32_t get_u32(const uint8_t *buf)
{
    return ((uint32_t)buf[0] << 24) |
           ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) |
           (uint32_t)buf[3];
}

static inline void put_u16(uint8_t *buf, uint16_t v)
{
    buf[0] = (v >> 8) & 0xFF;
    buf[1] = v & 0xFF;
}

static inline uint16_t get_u16(const uint8_t *buf)
{
    return (uint16_t)(((uint16_t)buf[0] << 8) | buf[1]);
}

static inline void encode_frame_hdr(uint8_t *buf,
                                    uint32_t payload_len,
                                    uint8_t type,
                                    uint8_t flags,
                                    uint32_t stream_id)
{
    put_u24(buf, payload_len);
    buf[3] = type;
    buf[4] = flags;
    put_u32(buf + 5, stream_id & 0x7FFFFFFF);
}

static inline void decode_frame_hdr(const uint8_t *buf,
                                    bhttp_frame_hdr_t *hdr)
{
    hdr->length = get_u24(buf);
    hdr->type = buf[3];
    hdr->flags = buf[4];
    hdr->stream_id = get_u32(buf + 5) & 0x7FFFFFFF;
}

static int parse_headers(const uint8_t *p,
                         size_t avail,
                         uint8_t count,
                         bhttp_header_t *hdrs)
{
    const uint8_t *start = p;

    for (int i = 0; i < (int)count; i++) {
        if (avail < 1)
            return -1;

        uint8_t idx = *p++;
        avail--;

        if (idx == HDR_LITERAL) {
            if (avail < 2)
                return -1;

            uint16_t nlen = get_u16(p);
            p += 2;
            avail -= 2;

            if (avail < nlen)
                return -1;

            hdrs[i].name = strndup((const char *)p, nlen);
            hdrs[i].name_is_literal = 1;

            p += nlen;
            avail -= nlen;
        } else if (idx < STATIC_HDR_COUNT) {
            hdrs[i].name = strdup(bhttp_static_names[idx]);
            hdrs[i].name_is_literal = 0;
        } else {
            return -1;
        }

        if (avail < 2) {
            free(hdrs[i].name);
            return -1;
        }

        uint16_t vlen = get_u16(p);
        p += 2;
        avail -= 2;

        if (avail < vlen) {
            free(hdrs[i].name);
            return -1;
        }

        hdrs[i].value = strndup((const char *)p, vlen);

        p += vlen;
        avail -= vlen;
    }

    return (int)(p - start);
}

#endif
