/*
 * Virtual-clock implementation of lib60870's time HAL (src/hal/inc/hal_time.h), replacing
 * src/hal/time/unix/time.c in the fuzz builds. The HAL is the library's documented porting layer.
 * Every timer in the stacks (CS101 link-layer ack/repeat/link-state timeouts, CS104 t1/t2/t3, the
 * file-server transfer timeout) reads this clock, so it is a pure function of the input: each
 * harness resets it per input (fuzz_clock_reset) and advances it by a fixed step per tick
 * (fuzz_clock_advance). Timeout paths therefore fire at the same tick on every host.
 */
#include "hal_time.h"
#include "fuzz_input.h"

/* 2023-11-14T22:13:20Z; any fixed, plausible wall-clock start works */
#define FUZZ_CLOCK_START_MS 1700000000000ULL

static uint64_t fuzz_clock_ms = FUZZ_CLOCK_START_MS;

void fuzz_clock_reset(void) { fuzz_clock_ms = FUZZ_CLOCK_START_MS; }
void fuzz_clock_advance(uint32_t ms) { fuzz_clock_ms += ms; }

msSinceEpoch Hal_getTimeInMs(void) { return fuzz_clock_ms; }
nsSinceEpoch Hal_getTimeInNs(void) { return fuzz_clock_ms * 1000000ULL; }
/* the stacks never set the clock; refuse, as a HAL without the privilege does */
bool Hal_setTimeInNs(nsSinceEpoch nsTime) { (void)nsTime; return false; }
msSinceEpoch Hal_getMonotonicTimeInMs(void) { return fuzz_clock_ms; }
nsSinceEpoch Hal_getMonotonicTimeInNs(void) { return fuzz_clock_ms * 1000000ULL; }
