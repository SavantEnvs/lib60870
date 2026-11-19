/*
 * ASDU decoder: CS101_ASDU_createFromBuffer + CS101_ASDU_getElement (public, iec60870_common.h),
 * which reaches every information-object decoder (*_getFromBuffer in cs101_information_objects.c,
 * CP16/24/56Time2a, BCR). Same path a CS101/CS104 station takes for every received ASDU.
 * Input: byte 0 selects the application-layer sizes (COT/CA/IOA); the rest is the ASDU.
 */
#include <stdlib.h>
#include <string.h>
#include "iec60870_common.h"
#include "cs101_information_objects.h"
#include "fuzz_input.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1)
        return 0;
    struct sCS101_AppLayerParameters params;
    fuzz_apply_al_params(&params, data[0]);
    params.maxSizeOfASDU = 254;

    size_t len = size - 1;
    if (len > 255)   /* an ASDU never exceeds 255 bytes (one-byte FT1.2/APCI length) */
        return -1;
    /* exact-size heap copy so ASan sees any over-read past the ASDU */
    uint8_t* buf = malloc(len ? len : 1);
    if (!buf)
        return 0;
    memcpy(buf, data + 1, len);

    CS101_ASDU asdu = CS101_ASDU_createFromBuffer(&params, buf, (int)len);
    if (asdu) {
        fuzz_walk_asdu(asdu);
        CS101_ASDU_destroy(asdu);
    }
    free(buf);
    return 0;
}
