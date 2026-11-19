/*
 * CS 101 slave (controlled station) over FT 1.2 serial: CS101_Slave_create + CS101_Slave_run, the
 * line bytes coming from the fuzz input through the in-memory serial HAL (fuzz_hal_serial.c).
 * Reaches serial_transceiver_ft_1_2.c (framing, checksum), link_layer.c (secondary unbalanced,
 * or the balanced primary+secondary state machines), cs101_slave.c handleASDU, the class 1/2
 * queues and the file-service plugin.
 * Built twice: -DFUZZ_BALANCED=0 (unbalanced) and -DFUZZ_BALANCED=1 (balanced).
 * Input: byte 0 = application-layer sizes + link-address length; the rest is the serial line.
 * A fresh slave is created per input.
 */
#include <stdlib.h>
#include <string.h>
#include "cs101_slave.h"
#include "cs101_file_service.h"
#include "hal_serial.h"
#include "fuzz_input.h"

#ifndef FUZZ_BALANCED
#error "define FUZZ_BALANCED to 0 or 1"
#endif

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
static void resetCUHandler(void* p) { CS101_Slave_flushQueues((CS101_Slave)p); }

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1)
        return 0;
    uint8_t cfg = data[0];

    SerialPort port = SerialPort_create("fuzz", 9600, 8, 'E', 1);
    CS101_Slave slave = CS101_Slave_create(port, NULL, NULL,
        FUZZ_BALANCED ? IEC60870_LINK_LAYER_BALANCED : IEC60870_LINK_LAYER_UNBALANCED);
    if (!slave) {
        SerialPort_destroy(port);
        return 0;
    }
    CS101_AppLayerParameters al = CS101_Slave_getAppLayerParameters(slave);
    fuzz_apply_al_params(al, cfg);
    LinkLayerParameters ll = CS101_Slave_getLinkLayerParameters(slave);
    /* address length 1 or 2; balanced mode also allows 0 (link_layer_parameters.h) */
    ll->addressLength = FUZZ_BALANCED ? ((cfg >> 4) % 3) : 1 + ((cfg >> 4) & 1);
    ll->useSingleCharACK = (cfg >> 6) & 1;
    CS101_Slave_setLinkLayerAddress(slave, 1);
    CS101_Slave_setLinkLayerAddressOtherStation(slave, 2);
    CS101_Slave_setDIR(slave, (cfg >> 7) & 1);

    CS101_Slave_setInterrogationHandler(slave, interrogationHandler, NULL);
    CS101_Slave_setCounterInterrogationHandler(slave, counterInterrogationHandler, NULL);
    CS101_Slave_setReadHandler(slave, readHandler, NULL);
    CS101_Slave_setClockSyncHandler(slave, clockSyncHandler, NULL);
    CS101_Slave_setResetProcessHandler(slave, resetProcessHandler, NULL);
    CS101_Slave_setDelayAcquisitionHandler(slave, delayAcquisitionHandler, NULL);
    CS101_Slave_setASDUHandler(slave, asduHandler, NULL);
    CS101_Slave_setResetCUHandler(slave, resetCUHandler, slave);

    CS101_FileServer fs = NULL;
    fuzz_add_file_service(al, &fs);
    CS101_Slave_addPlugin(slave, CS101_FileServer_getSlavePlugin(fs));

    /* class 1 and class 2 user data, so the primary side and the polling replies have data */
    for (int i = 0; i < 2; i++) {
        CS101_ASDU a = CS101_ASDU_create(al, false, CS101_COT_SPONTANEOUS, 0, 1, false, false);
        InformationObject io = (InformationObject)SinglePointInformation_create(NULL, 200 + i, i & 1, IEC60870_QUALITY_GOOD);
        CS101_ASDU_addInformationObject(a, io);
        InformationObject_destroy(io);
        if (i) CS101_Slave_enqueueUserDataClass2(slave, a); else CS101_Slave_enqueueUserDataClass1(slave, a);
        CS101_ASDU_destroy(a);
    }

    fuzz_peer_set(data + 1, size - 1);
    fuzz_clock_reset();
    /* each run handles at most one frame; a few extra runs let the state machines react */
    size_t limit = size + 8;
    /* 50 ms per run: ack (200 ms) / repeat (1 s) timeouts fire mid-stream; then 2 s steps so
     * the pending timeouts (incl. the file server's 3 s) fire once the line goes quiet */
    for (size_t i = 0; i < limit && !(fuzz_peer_drained() && i > size); i++) {
        CS101_Slave_run(slave);
        fuzz_clock_advance(50);
    }
    for (int i = 0; i < 4; i++) {
        fuzz_clock_advance(2000);
        CS101_Slave_run(slave);
    }

    CS101_Slave_destroy(slave);
    CS101_FileServer_destroy(fs);
    SerialPort_destroy(port);
    return 0;
}
