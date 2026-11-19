/*
 * In-memory implementation of lib60870's serial-port HAL (src/hal/inc/hal_serial.h), replacing
 * src/hal/serial/linux/serial_port_linux.c in the CS101 fuzz builds. The HAL is the library's
 * documented porting layer: the bytes the remote station sends on the line are the fuzz input
 * (fuzz_peer_*); readByte returns them one at a time and -1 ("no byte before the timeout") once
 * they are drained; everything the stack writes is discarded. discardInBuffer drops nothing:
 * the rest of the input models bytes that arrive after the discard.
 */
#include <stdlib.h>
#include <string.h>
#include "hal_serial.h"
#include "fuzz_input.h"

struct sSerialPort { int baudRate; int timeout; SerialPortError lastError; };

SerialPort SerialPort_create(const char* interfaceName, int baudRate, uint8_t dataBits, char parity, uint8_t stopBits)
{
    (void)interfaceName; (void)dataBits; (void)parity; (void)stopBits;
    SerialPort self = calloc(1, sizeof(struct sSerialPort));
    if (self) self->baudRate = baudRate;
    return self;
}
void SerialPort_destroy(SerialPort self) { free(self); }
bool SerialPort_open(SerialPort self) { (void)self; return true; }
void SerialPort_close(SerialPort self) { (void)self; }
int SerialPort_getBaudRate(SerialPort self) { return self->baudRate; }
void SerialPort_setTimeout(SerialPort self, int timeout) { self->timeout = timeout; }
void SerialPort_discardInBuffer(SerialPort self) { (void)self; }
int SerialPort_readByte(SerialPort self)
{
    (void)self;
    if (fuzz_peer_drained()) return -1;
    return fuzz_peer_data[fuzz_peer_pos++];
}
int SerialPort_write(SerialPort self, uint8_t* buffer, int startPos, int numberOfBytes)
{ (void)self; (void)buffer; (void)startPos; return numberOfBytes; }
SerialPortError SerialPort_getLastError(SerialPort self) { return self->lastError; }
