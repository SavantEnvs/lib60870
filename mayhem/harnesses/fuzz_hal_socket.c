/*
 * In-memory implementation of lib60870's socket HAL (src/hal/inc/hal_socket.h), replacing
 * src/hal/socket/linux/socket_linux.c in the fuzz builds. The HAL is the library's documented
 * porting layer: a TCP peer is modeled as one connection whose received bytes are the fuzz input
 * (fuzz_peer_*); everything the stack sends is discarded. After the input is drained a read
 * reports the peer closed (-1), as a real socket does. No network (time is the virtual clock
 * of fuzz_hal_time.c), no global state
 * survives an input except what the harness resets via fuzz_peer_set()/fuzz_socket_reset().
 */
#include <stdlib.h>
#include <string.h>
#include "hal_socket.h"
#include "fuzz_input.h"


struct sSocket { int kind; };          /* 1 = server, 2 = connection */
struct sServerSocket { int kind; };
struct sHandleSet { int count; };
struct sUdpSocket { int kind; };

static int fuzz_accept_pending;

void fuzz_socket_reset(int acceptOne) { fuzz_accept_pending = acceptOne; }

HandleSet Handleset_new(void) { return (HandleSet)calloc(1, sizeof(struct sHandleSet)); }
void Handleset_reset(HandleSet self) { if (self) self->count = 0; }
void Handleset_addSocket(HandleSet self, const Socket sock) { if (self && sock) self->count++; }
void Handleset_removeSocket(HandleSet self, const Socket sock) { if (self && sock && self->count) self->count--; }
/* The fake peer is always readable: either data or the end-of-stream (-1) is pending. */
int Handleset_waitReady(HandleSet self, unsigned int timeoutMs) { (void)timeoutMs; return (self && self->count) ? 1 : 0; }
void Handleset_destroy(HandleSet self) { free(self); }

ServerSocket TcpServerSocket_create(const char* address, int port)
{ (void)address; (void)port; ServerSocket s = calloc(1, sizeof(struct sServerSocket)); if (s) s->kind = 1; return s; }
UdpSocket UdpSocket_create(void) { return NULL; }
UdpSocket UdpSocket_createIpV6(void) { return NULL; }
bool UdpSocket_addGroupMembership(UdpSocket self, const char* a) { (void)self; (void)a; return false; }
bool UdpSocket_setMulticastTtl(UdpSocket self, int ttl) { (void)self; (void)ttl; return false; }
bool UdpSocket_bind(UdpSocket self, const char* a, int p) { (void)self; (void)a; (void)p; return false; }
bool UdpSocket_sendTo(UdpSocket self, const char* a, int p, uint8_t* m, int n) { (void)self; (void)a; (void)p; (void)m; (void)n; return false; }
int UdpSocket_receiveFrom(UdpSocket self, char* a, int s, uint8_t* m, int n) { (void)self; (void)a; (void)s; (void)m; (void)n; return -1; }
void ServerSocket_listen(ServerSocket self) { (void)self; }

static Socket new_conn(void) { Socket s = calloc(1, sizeof(struct sSocket)); if (s) s->kind = 2; return s; }

Socket ServerSocket_accept(ServerSocket self)
{
    (void)self;
    if (!fuzz_accept_pending) return NULL;
    fuzz_accept_pending = 0;
    return new_conn();
}
void Socket_activateTcpKeepAlive(Socket self, int a, int b, int c) { (void)self; (void)a; (void)b; (void)c; }
void ServerSocket_setBacklog(ServerSocket self, int backlog) { (void)self; (void)backlog; }
void ServerSocket_destroy(ServerSocket self) { free(self); }
Socket TcpSocket_create(void) { return new_conn(); }
void Socket_setConnectTimeout(Socket self, uint32_t t) { (void)self; (void)t; }
bool Socket_bind(Socket self, const char* a, int p) { (void)self; (void)a; (void)p; return true; }
bool Socket_connect(Socket self, const char* a, int p) { (void)self; (void)a; (void)p; return true; }
bool Socket_connectAsync(Socket self, const char* a, int p) { (void)self; (void)a; (void)p; return true; }
SocketState Socket_checkAsyncConnectState(Socket self) { (void)self; return SOCKET_STATE_CONNECTED; }

int Socket_read(Socket self, uint8_t* buf, int size)
{
    if (!self || size <= 0) return 0;
    if (fuzz_peer_drained()) return -1;
    size_t n = fuzz_peer_size - fuzz_peer_pos;
    if (n > (size_t)size) n = (size_t)size;
    memcpy(buf, fuzz_peer_data + fuzz_peer_pos, n);
    fuzz_peer_pos += n;
    return (int)n;
}
int Socket_write(Socket self, uint8_t* buf, int size) { (void)self; (void)buf; return size; }

static char* dup_addr(void) { char* s = malloc(32); if (s) strcpy(s, "127.0.0.1:2404"); return s; }
char* Socket_getLocalAddress(Socket self) { (void)self; return dup_addr(); }
char* Socket_getPeerAddress(Socket self) { (void)self; return dup_addr(); }
char* Socket_getPeerAddressStatic(Socket self, char* peerAddressString)
{ (void)self; strcpy(peerAddressString, "127.0.0.1:2404"); return peerAddressString; }
void Socket_destroy(Socket self) { free(self); }
