/*
 * CS 104 server (controlled station): CS104_Slave_create + startThreadless + tick, with one
 * client connection whose received bytes are the fuzz input (in-memory socket HAL,
 * fuzz_hal_socket.c). Reaches handleMessage (APCI U/S/I frames, sequence numbers, t1-t3
 * bookkeeping), handleASDU (every command type), the message queues and the connection
 * teardown paths, plus the file-service plugin for F_* ASDUs.
 * Input: byte 0 = server mode + application-layer sizes; the rest is the TCP byte stream.
 * A fresh slave is created per input, so nothing carries over between inputs.
 */
#include <stdlib.h>
#include <string.h>
#include "cs104_slave.h"
#include "cs101_file_service.h"
#include "fuzz_input.h"

void fuzz_socket_reset(int acceptOne);
void fuzz_add_file_service(CS101_AppLayerParameters al, CS101_FileServer* out);

static bool interrogationHandler(void* p, IMasterConnection c, CS101_ASDU asdu, uint8_t qoi)
{
    (void)p;
    if (qoi == IEC60870_QOI_STATION) {
        CS101_AppLayerParameters al = IMasterConnection_getApplicationLayerParameters(c);
        IMasterConnection_sendACT_CON(c, asdu, false);
        CS101_ASDU r = CS101_ASDU_create(al, false, CS101_COT_INTERROGATED_BY_STATION, 0, 1, false, false);
        InformationObject io = (InformationObject)MeasuredValueScaled_create(NULL, 100, -1, IEC60870_QUALITY_GOOD);
        CS101_ASDU_addInformationObject(r, io);
        InformationObject_destroy(io);
        IMasterConnection_sendASDU(c, r);
        CS101_ASDU_destroy(r);
        IMasterConnection_sendACT_TERM(c, asdu);
    } else {
        IMasterConnection_sendACT_CON(c, asdu, true);
    }
    return true;
}
static bool counterInterrogationHandler(void* p, IMasterConnection c, CS101_ASDU asdu, uint8_t qcc)
{ (void)p; (void)qcc; IMasterConnection_sendACT_CON(c, asdu, false); IMasterConnection_sendACT_TERM(c, asdu); return true; }
static bool readHandler(void* p, IMasterConnection c, CS101_ASDU asdu, int ioa)
{ (void)p; (void)c; (void)asdu; return ioa & 1; }
static bool clockSyncHandler(void* p, IMasterConnection c, CS101_ASDU asdu, CP56Time2a t)
{ (void)p; (void)c; (void)asdu; return CP56Time2a_getYear(t) & 1; }
static bool resetProcessHandler(void* p, IMasterConnection c, CS101_ASDU asdu, uint8_t qrp)
{ (void)p; IMasterConnection_sendACT_CON(c, asdu, qrp != 1); return true; }
static bool delayAcquisitionHandler(void* p, IMasterConnection c, CS101_ASDU asdu, CP16Time2a t)
{ (void)p; (void)t; IMasterConnection_sendACT_CON(c, asdu, false); return true; }
static bool asduHandler(void* p, IMasterConnection c, CS101_ASDU asdu)
{
    (void)p;
    fuzz_walk_asdu(asdu);
    if (CS101_ASDU_getTypeID(asdu) == C_SC_NA_1) {
        CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
        IMasterConnection_sendASDU(c, asdu);
        return true;
    }
    return false;
}
static bool connectionRequestHandler(void* p, const char* ip) { (void)p; (void)ip; return true; }

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1)
        return 0;
    uint8_t cfg = data[0];

    CS104_Slave slave = CS104_Slave_create(16, 16);
    if (!slave)
        return 0;
    CS104_Slave_setLocalAddress(slave, "127.0.0.1");
    CS104_Slave_setLocalPort(slave, 2404);
    CS101_AppLayerParameters al = CS104_Slave_getAppLayerParameters(slave);
    fuzz_apply_al_params(al, cfg);
    static const CS104_ServerMode modes[3] = {
        CS104_MODE_SINGLE_REDUNDANCY_GROUP, CS104_MODE_CONNECTION_IS_REDUNDANCY_GROUP,
        CS104_MODE_MULTIPLE_REDUNDANCY_GROUPS };
    CS104_Slave_setServerMode(slave, modes[(cfg >> 4) % 3]);

    CS104_Slave_setConnectionRequestHandler(slave, connectionRequestHandler, NULL);
    CS104_Slave_setInterrogationHandler(slave, interrogationHandler, NULL);
    CS104_Slave_setCounterInterrogationHandler(slave, counterInterrogationHandler, NULL);
    CS104_Slave_setReadHandler(slave, readHandler, NULL);
    CS104_Slave_setClockSyncHandler(slave, clockSyncHandler, NULL);
    CS104_Slave_setResetProcessHandler(slave, resetProcessHandler, NULL);
    CS104_Slave_setDelayAcquisitionHandler(slave, delayAcquisitionHandler, NULL);
    CS104_Slave_setASDUHandler(slave, asduHandler, NULL);

    CS101_FileServer fs = NULL;
    fuzz_add_file_service(al, &fs);
    CS104_Slave_addPlugin(slave, CS101_FileServer_getSlavePlugin(fs));

    if (modes[(cfg >> 4) % 3] == CS104_MODE_MULTIPLE_REDUNDANCY_GROUPS) {
        /* a group with no allowed-client list is the catch-all group (cs104_slave.h) */
        CS104_Slave_addRedundancyGroup(slave, CS104_RedundancyGroup_create("fuzz"));
    }

    fuzz_peer_set(data + 1, size - 1);
    fuzz_socket_reset(1);
    fuzz_clock_reset();
    CS104_Slave_startThreadless(slave);
    if (CS104_Slave_isRunning(slave)) {
        /* the message queues exist only once the server is started */
        /* queued spontaneous data, so the I-frame send/ack window is exercised */
        for (int i = 0; i < 3; i++) {
            CS101_ASDU a = CS101_ASDU_create(al, false, CS101_COT_SPONTANEOUS, 0, 1, false, false);
            InformationObject io = (InformationObject)SinglePointInformation_create(NULL, 200 + i, i & 1, IEC60870_QUALITY_GOOD);
            CS101_ASDU_addInformationObject(a, io);
            InformationObject_destroy(io);
            CS104_Slave_enqueueASDU(slave, a);
            CS101_ASDU_destroy(a);
        }
        /* every tick reads at most one APDU; the connection closes once the stream ends */
        size_t limit = 2 * size + 16;
        for (size_t i = 0; i < limit; i++) {
            CS104_Slave_tick(slave);
            fuzz_clock_advance(1000);   /* 1 s per tick: t2/t1/t3 (10/15/20 s) fire mid-stream */
            if (i > 0 && fuzz_peer_drained() && CS104_Slave_getOpenConnections(slave) == 0)
                break;
        }
        CS104_Slave_stopThreadless(slave);
    }
    CS104_Slave_destroy(slave);
    CS101_FileServer_destroy(fs);
    return 0;
}
