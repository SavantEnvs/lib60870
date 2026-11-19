/*
 * In-memory file provider/receiver for the file-service plugin (cs101_file_service.h), shared by
 * the slave harnesses. One provided file (CA 1, IOA 30000, two sections) and an upload receiver
 * for CA 1 / IOA 30001 that only counts bytes. No filesystem access.
 */
#include <string.h>
#include "cs101_file_service.h"
#include "fuzz_input.h"

static uint8_t section[2][400];
static struct sCS101_IFileProvider provider;
static struct sCS101_FilesAvailable avail;
static struct sCS101_IFileReceiver receiver;
static size_t received_bytes;

static uint64_t getFileDate(CS101_IFileProvider self) { (void)self; return 0; }
static int getFileSize(CS101_IFileProvider self) { (void)self; return 800; }
static int getSectionSize(CS101_IFileProvider self, int n) { (void)self; return (n == 0 || n == 1) ? 400 : 0; }
static bool getSegmentData(CS101_IFileProvider self, int n, int offset, int size, uint8_t* data)
{
    (void)self;
    if (n < 0 || n > 1 || offset < 0 || size < 0 || offset + size > 400)
        return false;
    memcpy(data, section[n] + offset, size);
    return true;
}
static void transferComplete(CS101_IFileProvider self, bool ok) { (void)self; (void)ok; }

static CS101_IFileProvider getNextFile(void* p, CS101_IFileProvider after) { (void)p; return after ? NULL : &provider; }
static CS101_IFileProvider getFile(void* p, int ca, int ioa, uint16_t nof, int* err)
{
    (void)p; (void)nof;
    if (ca == provider.ca && ioa == provider.ioa) return &provider;
    *err = 1;
    return NULL;
}
static void rcvFinished(CS101_IFileReceiver self, CS101_FileErrorCode r) { (void)self; (void)r; }
static void rcvSegment(CS101_IFileReceiver self, uint8_t sec, int offset, int size, uint8_t* data)
{
    (void)self; (void)sec; (void)offset;
    volatile uint8_t x = 0;
    for (int i = 0; i < size; i++) x ^= data[i];   /* touch every received byte */
    received_bytes += size;
}
static CS101_IFileReceiver fileReady(void* p, int ca, int ioa, uint16_t nof, int len, int* err)
{
    (void)p; (void)nof; (void)len;
    if (ca == 1 && ioa == 30001) { *err = 0; return &receiver; }
    *err = 1;
    return NULL;
}

void fuzz_add_file_service(CS101_AppLayerParameters al, CS101_FileServer* out)
{
    for (int i = 0; i < 400; i++) { section[0][i] = (uint8_t)i; section[1][i] = (uint8_t)(i + 1); }
    memset(&provider, 0, sizeof provider);
    provider.ca = 1; provider.ioa = 30000; provider.nof = CS101_NOF_TRANSPARENT_FILE;
    provider.getFileDate = getFileDate; provider.getFileSize = getFileSize;
    provider.getSectionSize = getSectionSize; provider.getSegmentData = getSegmentData;
    provider.transferComplete = transferComplete;
    avail.getFile = getFile; avail.getNextFile = getNextFile; avail.parameter = NULL;
    memset(&receiver, 0, sizeof receiver);
    receiver.finished = rcvFinished; receiver.segmentReceived = rcvSegment;
    received_bytes = 0;

    CS101_FileServer fs = CS101_FileServer_create(al);
    CS101_FileServer_setFilesAvailableIfc(fs, &avail);
    CS101_FileServer_setFileReadyHandler(fs, fileReady, NULL);
    *out = fs;
}
