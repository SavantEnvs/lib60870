/*
 * CS 101 master (controlling station) over FT 1.2 serial: CS101_Master_create + CS101_Master_run,
 * the slave's line bytes coming from the fuzz input through the in-memory serial HAL
 * (fuzz_hal_serial.c). Reaches link_layer.c (primary unbalanced + per-slave connection state
 * machines, or the balanced state machines from the master side), serial_transceiver_ft_1_2.c
 * and the cs101_master.c ASDU receive path (every received ASDU is walked).
 * Built twice: -DFUZZ_BALANCED=0 (unbalanced) and -DFUZZ_BALANCED=1 (balanced).
 * Input: byte 0 = application-layer sizes + link-address length; the rest is the serial line.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "cs101_master.h"
#include "hal_serial.h"
#include "fuzz_input.h"

#ifndef FUZZ_BALANCED
#error "define FUZZ_BALANCED to 0 or 1"
#endif

static bool asduReceived(void* p, int address, CS101_ASDU asdu)
{
    (void)p; (void)address;
    fuzz_walk_asdu(asdu);
    return true;
}

/* cs101_master.c printf()s every link-layer state change; keep stdout quiet (libFuzzer reports
 * on stderr) so the fuzzer is not throttled by terminal output. */
int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    (void)argc; (void)argv;
    if (!freopen("/dev/null", "w", stdout)) { /* keep running with stdout as is */ }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1)
        return 0;
    uint8_t cfg = data[0];

    SerialPort port = SerialPort_create("fuzz", 9600, 8, 'E', 1);
    CS101_Master master = CS101_Master_create(port, NULL, NULL,
        FUZZ_BALANCED ? IEC60870_LINK_LAYER_BALANCED : IEC60870_LINK_LAYER_UNBALANCED);
    if (!master) {
        SerialPort_destroy(port);
        return 0;
    }
    fuzz_apply_al_params(CS101_Master_getAppLayerParameters(master), cfg);
    LinkLayerParameters ll = CS101_Master_getLinkLayerParameters(master);
    ll->addressLength = FUZZ_BALANCED ? ((cfg >> 4) % 3) : 1 + ((cfg >> 4) & 1);
    ll->useSingleCharACK = (cfg >> 6) & 1;
    CS101_Master_setASDUReceivedHandler(master, asduReceived, NULL);

#if FUZZ_BALANCED
    CS101_Master_setOwnAddress(master, 2);
    CS101_Master_useSlaveAddress(master, 1);
    CS101_Master_setDIR(master, (cfg >> 7) & 1);
#else
    CS101_Master_addSlave(master, 1);
    CS101_Master_addSlave(master, 2);
#endif

    fuzz_peer_set(data + 1, size - 1);
    fuzz_clock_reset();
    size_t limit = size + 8;
    for (size_t i = 0; i < limit && !(fuzz_peer_drained() && i > size); i++) {
#if !FUZZ_BALANCED
        CS101_Master_pollSingleSlave(master, 1 + (i & 1));
#endif
        CS101_Master_run(master);
        fuzz_clock_advance(50);   /* 50 ms per run: ack 200 ms, repeat 1 s, link state 5 s */
        switch (i % 8) {
        case 2:
            CS101_Master_useSlaveAddress(master, 1);
            CS101_Master_sendInterrogationCommand(master, CS101_COT_ACTIVATION, 1, IEC60870_QOI_STATION);
            break;
        case 5:
            CS101_Master_useSlaveAddress(master, 1);
            CS101_Master_sendReadCommand(master, 1, 102);
            break;
        default:
            break;
        }
    }
    for (int i = 0; i < 4; i++) {
        fuzz_clock_advance(2000);   /* line quiet: let the pending timeouts fire */
        CS101_Master_run(master);
    }

    CS101_Master_destroy(master);
    SerialPort_destroy(port);
    return 0;
}
