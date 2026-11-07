#ifndef HUMA_COMPACT_H
#define HUMA_COMPACT_H
#include <stddef.h>
#include <stdint.h>

/* A handle has one serial owner. Requests are bounded UTF-8 JSON. No signing key
 * is accepted: the caller signs the returned domain-separated checkpoint bytes.
 * Reply strings belong to this library, including replies returned on error. */
typedef struct HumaCompactCapture HumaCompactCapture;
HumaCompactCapture *huma_compact_create(const uint8_t *data, size_t length, char **reply);
char *huma_compact_call(HumaCompactCapture *capture, const uint8_t *data, size_t length);
void huma_compact_response_free(char *reply);
void huma_compact_destroy(HumaCompactCapture *capture);
#endif
