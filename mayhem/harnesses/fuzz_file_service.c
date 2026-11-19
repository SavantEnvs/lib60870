/*
 * File service (src/file-service/file_server.c): the slave plugin from
 * CS101_FileServer_getSlavePlugin, driven through its public plugin interface
 * (struct sCS101_SlavePlugin: handleAsdu + runTask) exactly as cs101_slave.c / cs104_slave.c
 * call it for each received ASDU. Reaches F_FR/F_SR/F_SC/F_LS/F_AF/F_SG/F_DR handling and the
 * file send/receive state machines without the link layer in front.
 * Input: byte 0 = application-layer sizes; then records [len][len bytes of ASDU].
 */
#include <stdlib.h>
#include <string.h>
#include "cs101_file_service.h"
#include "fuzz_input.h"

void fuzz_add_file_service(CS101_AppLayerParameters al, CS101_FileServer* out);

static struct sCS101_AppLayerParameters g_al;

static bool c_isReady(IMasterConnection self) { (void)self; return true; }
static bool c_sendASDU(IMasterConnection self, CS101_ASDU asdu) { (void)self; fuzz_walk_asdu(asdu); return true; }
static bool c_sendASDUEx(IMasterConnection self, CS101_ASDU asdu, bool b) { (void)b; return c_sendASDU(self, asdu); }
static bool c_sendACT_CON(IMasterConnection self, CS101_ASDU asdu, bool neg) { (void)self; (void)asdu; (void)neg; return true; }
static bool c_sendACT_TERM(IMasterConnection self, CS101_ASDU asdu) { (void)self; (void)asdu; return true; }
static void c_close(IMasterConnection self) { (void)self; }
static int c_getPeerAddress(IMasterConnection self, char* buf, int n) { (void)self; if (n > 0) buf[0] = 0; return 0; }
static CS101_AppLayerParameters c_getAL(IMasterConnection self) { (void)self; return &g_al; }

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1)
        return 0;
    fuzz_apply_al_params(&g_al, data[0]);
    g_al.maxSizeOfASDU = 249;

    struct sIPeerConnection conn = {
        c_isReady, c_sendASDU, c_sendASDUEx, c_sendACT_CON, c_sendACT_TERM,
        c_close, c_getPeerAddress, c_getAL, NULL };

    CS101_FileServer fs = NULL;
    fuzz_add_file_service(&g_al, &fs);
    CS101_SlavePlugin plugin = CS101_FileServer_getSlavePlugin(fs);

    fuzz_clock_reset();
    size_t pos = 1;
    while (pos < size) {
        size_t len = data[pos++];
        if (len > size - pos)
            len = size - pos;
        uint8_t* buf = malloc(len ? len : 1);   /* exact size: ASan sees over-reads */
        if (!buf)
            break;
        memcpy(buf, data + pos, len);
        pos += len;
        CS101_ASDU asdu = CS101_ASDU_createFromBuffer(&g_al, buf, (int)len);
        if (asdu) {
            plugin->handleAsdu(plugin->parameter, &conn, asdu);
            CS101_ASDU_destroy(asdu);
        }
        free(buf);
        if (plugin->runTask)
            plugin->runTask(plugin->parameter, &conn);
        fuzz_clock_advance(500);   /* 500 ms per ASDU; the transfer timeout is 3 s */
    }
    for (int i = 0; i < 4 && plugin->runTask; i++) {
        fuzz_clock_advance(2000);   /* peer quiet: the transfer timeout fires */
        plugin->runTask(plugin->parameter, &conn);
    }

    CS101_FileServer_destroy(fs);
    return 0;
}
