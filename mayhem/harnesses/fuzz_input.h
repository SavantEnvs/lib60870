/* Shared fuzz-input state for the lib60870 harnesses (mayhem layer, not upstream code). */
#ifndef FUZZ_INPUT_H
#define FUZZ_INPUT_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "iec60870_common.h"

/* Bytes the fake peer delivers through the HAL (socket or serial), reset per input. */
extern const uint8_t* fuzz_peer_data;
extern size_t fuzz_peer_size;
extern size_t fuzz_peer_pos;

static inline void fuzz_peer_set(const uint8_t* d, size_t n) { fuzz_peer_data = d; fuzz_peer_size = n; fuzz_peer_pos = 0; }
static inline bool fuzz_peer_drained(void) { return fuzz_peer_pos >= fuzz_peer_size; }

/* Virtual clock behind the time HAL (fuzz_hal_time.c): reset per input, advanced per tick. */
void fuzz_clock_reset(void);
void fuzz_clock_advance(uint32_t ms);

/* Application-layer sizes from one config byte: COT 1/2, CA 1/2, IOA 1..3 (the ranges the
 * library documents in struct sCS101_AppLayerParameters). */
static inline void fuzz_apply_al_params(CS101_AppLayerParameters p, uint8_t cfg)
{
    p->sizeOfTypeId = 1;
    p->sizeOfVSQ = 1;
    p->sizeOfCOT = (cfg & 1) ? 2 : 1;
    p->sizeOfCA = (cfg & 2) ? 2 : 1;
    p->sizeOfIOA = 1 + ((cfg >> 2) % 3);
    p->originatorAddress = 0;
}

/* Walk every information object of an ASDU through the public decoders. */
static inline void fuzz_walk_asdu(CS101_ASDU asdu)
{
    volatile int sink = 0;
    sink += CS101_ASDU_getTypeID(asdu);
    sink += CS101_ASDU_getCOT(asdu);
    sink += CS101_ASDU_getCA(asdu);
    sink += CS101_ASDU_getOA(asdu);
    sink += CS101_ASDU_isTest(asdu) + CS101_ASDU_isNegative(asdu) + CS101_ASDU_isSequence(asdu);
    int n = CS101_ASDU_getNumberOfElements(asdu);
    for (int i = 0; i < n; i++) {
        InformationObject io = CS101_ASDU_getElement(asdu, i);
        if (io) {
            sink += InformationObject_getObjectAddress(io);
            sink += InformationObject_getType(io);
            InformationObject_destroy(io);
        }
    }
    (void)sink;
}
#endif
