/*
 * CS 104 client (controlling station): CS104_Connection_create + startThreadless +
 * CS104_Connection_run, the server's bytes coming from the fuzz input through the in-memory
 * socket HAL (fuzz_hal_socket.c). Reaches checkMessage (APCI parsing, STARTDT/STOPDT/TESTFR
 * con/act, S/I frames, sequence-number checks), the receive-buffer state machine and the
 * ASDU dispatch (every received ASDU is walked by the handler).
 * Input: byte 0 = application-layer sizes; the rest is the TCP byte stream from the server.
 */
#include <stdlib.h>
#include <string.h>
#include "cs104_connection.h"
#include "fuzz_input.h"

void fuzz_socket_reset(int acceptOne);

static bool asduReceived(void* p, int address, CS101_ASDU asdu)
{
    (void)p; (void)address;
    fuzz_walk_asdu(asdu);
    return true;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1)
        return 0;
    CS104_Connection con = CS104_Connection_create("127.0.0.1", 2404);
    if (!con)
        return 0;
    fuzz_apply_al_params(CS104_Connection_getAppLayerParameters(con), data[0]);
    CS104_Connection_setASDUReceivedHandler(con, asduReceived, NULL);

    fuzz_peer_set(data + 1, size - 1);
    fuzz_socket_reset(0);
    fuzz_clock_reset();
    if (CS104_Connection_startThreadless(con)) {
        CS104_Connection_sendStartDT(con);
        size_t limit = 2 * size + 16;
        for (size_t i = 0; i < limit; i++) {
            if (!CS104_Connection_run(con, 0))
                break;
            fuzz_clock_advance(1000);   /* 1 s per tick: t2/t1/t3 (10/15/20 s) fire mid-stream */
            switch (i % 8) {
            case 1: CS104_Connection_sendInterrogationCommand(con, CS101_COT_ACTIVATION, 1, IEC60870_QOI_STATION); break;
            case 3: CS104_Connection_sendTestCommand(con, 1); break;
            case 5: CS104_Connection_sendReadCommand(con, 1, 102); break;
            default: break;
            }
        }
        CS104_Connection_stopThreadless(con);
    }
    CS104_Connection_destroy(con);
    return 0;
}
