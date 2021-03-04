/*
 * Wslay - The WebSocket Library
 *
 * Copyright (c) 2011, 2012 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
// WebSocket Test Client for Autobahn client test
// $ g++ -Wall -O2 -g -o testclient testclient.cc -L../lib/.libs -I../lib/includes -lwslay -lnettle
// $ export LD_LIBRARY_PATH=../lib/.libs
// $ ./a.out localhost 9001


/*
 * https://tls.mbed.org/kb/how-to/mbedtls-tutorial
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>

#include <cassert>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
#include <string>
#include <set>
#include <iomanip>
#include <fstream>

#include <nettle/base64.h>
#include <nettle/sha.h>
#include <wslay/wslay.h>
// mbedtls
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

struct tls_context{
  // net related.
  mbedtls_net_context socket;
  // tls library related.
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctrDrbg;
  mbedtls_ssl_config sslConfig;
  mbedtls_ssl_context sslCtx;
  mbedtls_x509_crt cacert;
};

#define CHK_STATUS(ret) do{ \
                          if(ret != 0){ \
                            printf("%s(%d)error: %x\n", __func__, __LINE__, ret); \
                          } \
                        }while(0);

/**
 * @brief
 * 
 * @param[in]
 * 
 * @return
*/
int tlsSession_init(struct tls_context** ppTlsConext, const char* cacertPath){

  //mbedtls_platform_set_calloc_free(my_calloc, vPortFree);
  struct tls_context* pTlsContext = (struct tls_context*)malloc(sizeof(struct tls_context));
  // the initialization of entropy and ctrdrbg.
  // mbedtls_net_init( &pTlsContext->socket );
  mbedtls_entropy_init(&pTlsContext->entropy);
  mbedtls_ctr_drbg_init(&pTlsContext->ctrDrbg);
  CHK_STATUS(mbedtls_ctr_drbg_seed(&pTlsContext->ctrDrbg, mbedtls_entropy_func, &pTlsContext->entropy, NULL, 0));
  // the initializatino of x509 certificate.
  mbedtls_x509_crt_init(&pTlsContext->cacert);
  CHK_STATUS(mbedtls_x509_crt_parse_file(&pTlsContext->cacert, cacertPath));
  // the initialization of ssl context.
  mbedtls_ssl_config_init(&pTlsContext->sslConfig);
  mbedtls_ssl_init(&pTlsContext->sslCtx);
  mbedtls_net_init(&pTlsContext->socket);
  *ppTlsConext = pTlsContext;
  return 0;
}

static void tlsSession_debug( void *ctx, int level, const char *file, int line, const char *str ){ 
  ((void) level);
  fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
  fflush( (FILE *) ctx ); 
}

int tlsSession_connect(struct tls_context* pTlsContext, const char *host, const char *port){

  mbedtls_net_context* pTlsSocket = &(pTlsContext->socket);
  CHK_STATUS(mbedtls_net_connect(pTlsSocket, host, port, MBEDTLS_NET_PROTO_TCP));
  CHK_STATUS(mbedtls_ssl_config_defaults(&pTlsContext->sslConfig, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT));
  mbedtls_ssl_conf_ca_chain(&pTlsContext->sslConfig, &pTlsContext->cacert, NULL);
  //#YC_TBD, need to confirm this is necessary.
  /**
    #define MBEDTLS_SSL_VERIFY_NONE                 0
    #define MBEDTLS_SSL_VERIFY_OPTIONAL             1
    #define MBEDTLS_SSL_VERIFY_REQUIRED             2
  */
  // #YC_TBD, 
  mbedtls_ssl_conf_authmode(&pTlsContext->sslConfig, MBEDTLS_SSL_VERIFY_REQUIRED);
  //mbedtls_ssl_conf_authmode(&pTlsContext->sslConfig, MBEDTLS_SSL_VERIFY_NONE);
  // rng
  mbedtls_ssl_conf_rng(&pTlsContext->sslConfig, mbedtls_ctr_drbg_random, &pTlsContext->ctrDrbg);
  //mbedtls_ssl_conf_dbg( &conf, tlsSession_debug, stdout );
  CHK_STATUS(mbedtls_ssl_setup(&pTlsContext->sslCtx, &pTlsContext->sslConfig));
  //mbedtls_ssl_set_mtu(&pTlsContext->sslCtx, DEFAULT_MTU_SIZE);
  //mbedtls_ssl_set_bio(&pTlsContext->sslCtx, pTlsContext, (mbedtls_ssl_send_t*)tlsSessionSendCallback, (mbedtls_ssl_recv_t*)tlsSessionReceiveCallback, NULL);
  mbedtls_ssl_set_bio(&pTlsContext->sslCtx, &pTlsContext->socket, mbedtls_net_send, mbedtls_net_recv, NULL);

  CHK_STATUS(mbedtls_ssl_handshake(&pTlsContext->sslCtx));
  //sslCtx.state == MBEDTLS_SSL_HANDSHAKE_OVER
  //CHK(sslRet == MBEDTLS_ERR_SSL_WANT_READ || sslRet == MBEDTLS_ERR_SSL_WANT_WRITE, STATUS_TLS_SSL_HANDSHAKE_FAILED);
  //LOG_MBEDTLS_ERROR("mbedtls_ssl_handshake", sslRet);
  return 0;

}

/**
 * @brief when socket connection is ready, we have to dispatch the data from the sock connection to the corresponding handler.
 *        Note:: If mbedtls_ssl_read() or mbedtls_ssl_write() returns an error, the connection must be closed.
 * 
 * @param[in] pTlsContext
 * @param[in] pBuf the address of this buffer.
 * @param[in] bufLen the maximum length of this data buffer.
 * @param[in] pReadLen the length of the data inside this buffer.
 * 
 * @return
*/
int tlsSession_recv(struct tls_context* pTlsContext, uint8_t* pBuf, uint32_t bufLen){
	int ret;

	ret = mbedtls_ssl_read(&pTlsContext->sslCtx, (unsigned char*)pBuf, bufLen);
	if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE
			|| ret == MBEDTLS_ERR_NET_RECV_FAILED)
		ret = 0;
	return ret;
}

/**
 * @brief 
 * 
 * @param[in]
 * 
 * @return
*/
int tlsSession_send(struct tls_context* pTlsContext, const uint8_t* buf, uint32_t bufLen){
  //mbedtls_ssl_write
  int ret;
  ret = mbedtls_ssl_write(&pTlsContext->sslCtx, (unsigned char const*)buf, bufLen);
	if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
		ret = 0;

	return ret;
}


int tlsSession_close(struct tls_context* pTlsContext){
  mbedtls_ssl_close_notify(&pTlsContext->sslCtx);
  mbedtls_net_free( &pTlsContext->socket );
  mbedtls_ssl_free( &pTlsContext->sslCtx );
  mbedtls_ssl_config_free( &pTlsContext->sslConfig );
  mbedtls_ctr_drbg_free( &pTlsContext->ctrDrbg );
  mbedtls_entropy_free( &pTlsContext->entropy );
  return 0;
}


int connect_to(const char *host, const char *service) {
  struct addrinfo hints;
  int fd = -1;
  int r;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo *res;
  r = getaddrinfo(host, service, &hints, &res);
  if (r != 0) {
    std::cerr << "getaddrinfo: " << gai_strerror(r) << std::endl;
    return -1;
  }
  for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1) {
      continue;
    }
    while ((r = connect(fd, rp->ai_addr, rp->ai_addrlen)) == -1 &&
           errno == EINTR)
      ;
    if (r == 0) {
      break;
    }
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}

int make_non_block(int fd) {
  int flags, r;
  while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR)
    ;
  if (flags == -1) {
    return -1;
  }
  while ((r = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR)
    ;
  if (r == -1) {
    return -1;
  }
  return 0;
}

std::string sha1(const std::string &src) {
  sha1_ctx ctx;
  sha1_init(&ctx);
  sha1_update(&ctx, src.size(), reinterpret_cast<const uint8_t *>(src.c_str()));
  uint8_t temp[SHA1_DIGEST_SIZE];
  sha1_digest(&ctx, SHA1_DIGEST_SIZE, temp);
  std::string res(&temp[0], &temp[SHA1_DIGEST_SIZE]);
  return res;
}

std::string base64(const std::string &src) {
  base64_encode_ctx ctx;
  base64_encode_init(&ctx);
  int dstlen = BASE64_ENCODE_RAW_LENGTH(src.size());
  char *dst = new char[dstlen];
  base64_encode_raw(dst, src.size(),
                    reinterpret_cast<const uint8_t *>(src.c_str()));
  std::string res(&dst[0], &dst[dstlen]);
  delete[] dst;
  return res;
}

std::string create_acceptkey(const std::string &clientkey) {
  std::string s = clientkey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  return base64(sha1(s));
}

class WebSocketClient {
public:
  WebSocketClient(int fd, struct wslay_event_callbacks *callbacks,
                  const std::string &body, struct tls_context* tlsContext)
      : fd_(fd), body_(body), body_off_(0), dev_urand_("/dev/urandom"), counter(0), tls(NULL){
    wslay_event_context_client_init(&ctx_, callbacks, this);
    tls = tlsContext;
  }
  ~WebSocketClient() {
    wslay_event_context_free(ctx_);
    shutdown(fd_, SHUT_WR);
    close(fd_);
  }
  int on_read_event() { return wslay_event_recv(ctx_); }
  int on_write_event() { return wslay_event_send(ctx_); }
  ssize_t send_data(const uint8_t *data, size_t len, int flags) {
    ssize_t r;
    int sflags = 0;
#ifdef MSG_MORE
    if (flags & WSLAY_MSG_MORE) {
      sflags |= MSG_MORE;
    }
#endif // MSG_MORE
    //while ((r = send(fd_, data, len, sflags)) == -1 && errno == EINTR)
    
    while ((r = tlsSession_send(tls, data, len)) == -1 && errno == EINTR)
      ;
    return r;
  }

  ssize_t feed_body(uint8_t *data, size_t len) {
    if (body_off_ < body_.size()) {
      size_t wlen = std::min(len, body_.size() - body_off_);
      memcpy(data, body_.c_str(), wlen);
      body_off_ += wlen;
      return wlen;
    } else {
      return 0;
    }
  }
  ssize_t recv_data(uint8_t *data, size_t len, int flags) {
    ssize_t r;
    //while ((r = recv(fd_, data, len, 0)) == -1 && errno == EINTR)
    while ((r = tlsSession_recv(tls, data, len)) == -1 && errno == EINTR)
      ;
    return r;
  }
  bool want_read() { return wslay_event_want_read(ctx_); }
  bool want_write() { return wslay_event_want_write(ctx_); }
  int fd() const { return fd_; }
  void get_random(uint8_t *buf, size_t len) {
    dev_urand_.read((char *)buf, len);
  }
  void set_callbacks(const struct wslay_event_callbacks *callbacks) {
    wslay_event_config_set_callbacks(ctx_, callbacks);
  }
  void test_echo(void){
    char echoBuf[128];
    #define ECHO_STRING "echo"
    sprintf(echoBuf, "%s:%d", "echo", counter);
    struct wslay_event_msg msgarg = {1, (uint8_t*)echoBuf, strlen(echoBuf)+1};
    printf("send msg, opcode:%d, str:%s, length:%d\n", msgarg.opcode, msgarg.msg, msgarg.msg_length);
    wslay_event_queue_msg(ctx_, &msgarg);
    counter++;
  }
  struct tls_context* get_tls(void){
    return tls;
  }
private:
  int fd_;
  wslay_event_context_ptr ctx_;
  std::string body_;
  size_t body_off_;
  std::fstream dev_urand_;
  int counter;
  struct tls_context* tls;
};

ssize_t send_callback(wslay_event_context_ptr ctx, const uint8_t *data,
                      size_t len, int flags, void *user_data) {
  WebSocketClient *ws = (WebSocketClient *)user_data;
  ssize_t r = ws->send_data(data, len, flags);
  if (r == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
    } else {
      wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
    }
  }
  return r;
}

ssize_t recv_callback(wslay_event_context_ptr ctx, uint8_t *data, size_t len,
                      int flags, void *user_data) {
  WebSocketClient *ws = (WebSocketClient *)user_data;
  ssize_t r = ws->recv_data(data, len, flags);
  if (r == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
    } else {
      wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
    }
  } else if (r == 0) {
    wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
    r = -1;
  }
  return r;
}

ssize_t feed_body_callback(wslay_event_context_ptr ctx, uint8_t *data,
                           size_t len, int flags, void *user_data) {
  WebSocketClient *ws = (WebSocketClient *)user_data;
  return ws->feed_body(data, len);
}

int genmask_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len,
                     void *user_data) {
  WebSocketClient *ws = (WebSocketClient *)user_data;
  ws->get_random(buf, len);
  return 0;
}

void on_msg_recv_callback(wslay_event_context_ptr ctx,
                          const struct wslay_event_on_msg_recv_arg *arg,
                          void *user_data) {
  if (!wslay_is_ctrl_frame(arg->opcode)) {
    struct wslay_event_msg msgarg = {arg->opcode, arg->msg, arg->msg_length};
    wslay_event_queue_msg(ctx, &msgarg);
  }
}

std::string casecntjson;

void get_casecnt_on_msg_recv_callback(
    wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg *arg,
    void *user_data) {
  if (arg->opcode == WSLAY_TEXT_FRAME) {
    //casecntjson.assign(arg->msg, arg->msg + arg->msg_length);
    printf("received: %s\n", arg->msg);
  }
}

int send_http_handshake(int fd, const std::string &reqheader) {
  size_t off = 0;
  while (off < reqheader.size()) {
    ssize_t r;
    size_t len = reqheader.size() - off;
    while ((r = write(fd, reqheader.c_str() + off, len)) == -1 &&
           errno == EINTR)
      ;
    if (r == -1) {
      perror("write");
      return -1;
    }
    off += r;
  }
  return 0;
}

int recv_http_handshake(int fd, std::string &resheader) {
  char buf[4096];
  while (1) {
    ssize_t r;
    while ((r = read(fd, buf, sizeof(buf))) == -1 && errno == EINTR)
      ;
    if (r <= 0) {
      return -1;
    }
    resheader.append(buf, buf + r);
    if (resheader.find("\r\n\r\n") != std::string::npos) {
      break;
    }
    if (resheader.size() > 8192) {
      std::cerr << "Too big response header" << std::endl;
      return -1;
    }
  }
  return 0;
}

std::string get_random16() {
  char buf[16];
  std::fstream f("/dev/urandom");
  f.read(buf, 16);
  return std::string(buf, buf + 16);
}
/** send the req key and  verify the res key is the same as the req key.*/
int http_handshake(int fd, const char *host, const char *service,
                   const char *path, std::string &body) {
  char buf[4096];
  std::string client_key = base64(get_random16());
  snprintf(buf, sizeof(buf),
           "GET %s HTTP/1.1\r\n"
           "Host: %s:%s\r\n"
           "Upgrade: websocket\r\n"
           "Connection: Upgrade\r\n"
           "Sec-WebSocket-Key: %s\r\n"
           "Sec-WebSocket-Version: 13\r\n"
           "\r\n",
           path, host, service, client_key.c_str());
  std::string reqheader = buf;
  if (send_http_handshake(fd, reqheader) == -1) {
    return -1;
  }
  std::string resheader;
  if (recv_http_handshake(fd, resheader) == -1) {
    return -1;
  }
  std::string::size_type keyhdstart;
  if ((keyhdstart = resheader.find("Sec-WebSocket-Accept: ")) ==
      std::string::npos) {
    std::cerr << "http_upgrade: missing required headers" << std::endl;
    return -1;
  }
  keyhdstart += 22;
  std::string::size_type keyhdend = resheader.find("\r\n", keyhdstart);
  std::string accept_key = resheader.substr(keyhdstart, keyhdend - keyhdstart);
  if (accept_key == create_acceptkey(client_key)) {
    body = resheader.substr(resheader.find("\r\n\r\n") + 4);
    return 0;
  } else {
    return -1;
  }
}

int send_https_handshake(struct tls_context* pTlsContext, const std::string &reqheader) {
  size_t off = 0;
  while (off < reqheader.size()) {
    ssize_t r;
    size_t len = reqheader.size() - off;

    //while ((r = write(fd, reqheader.c_str() + off, len)) == -1 &&
    while ((r = tlsSession_send(pTlsContext, (const uint8_t*)reqheader.c_str() + off, len)) == -1 &&
           errno == EINTR)
      ;
    if (r == -1) {
      perror("write");
      return -1;
    }
    off += r;
  }
  return 0;
}

int recv_https_handshake(struct tls_context* pTlsContext, std::string &resheader) {
  char buf[4096];
  while (1) {
    ssize_t r;

    //while ((r = read(fd, buf, sizeof(buf))) == -1 && errno == EINTR)
    while ((r = tlsSession_recv(pTlsContext, (uint8_t*)buf, sizeof(buf))) == -1 && errno == EINTR)
      ;
    if (r <= 0) {
      return -1;
    }
    resheader.append(buf, buf + r);
    if (resheader.find("\r\n\r\n") != std::string::npos) {
      break;
    }
    if (resheader.size() > 8192) {
      std::cerr << "Too big response header" << std::endl;
      return -1;
    }
  }
  return 0;
}



/** send the req key and  verify the res key is the same as the req key.*/
int https_handshake(struct tls_context* pTlsContext, const char *host, const char *service,
                   const char *path, std::string &body) {
  char buf[4096];
  std::string client_key = base64(get_random16());
  snprintf(buf, sizeof(buf),
           "GET %s HTTP/1.1\r\n"
           "Host: %s:%s\r\n"
           "Upgrade: websocket\r\n"
           "Connection: Upgrade\r\n"
           "Sec-WebSocket-Key: %s\r\n"
           "Sec-WebSocket-Version: 13\r\n"
           "\r\n",
           path, host, service, client_key.c_str());
  std::string reqheader = buf;
  if (send_https_handshake(pTlsContext, reqheader) == -1) {
    return -1;
  }
  std::string resheader;
  if (recv_https_handshake(pTlsContext, resheader) == -1) {
    return -1;
  }
  std::string::size_type keyhdstart;
  if ((keyhdstart = resheader.find("Sec-WebSocket-Accept: ")) ==
      std::string::npos) {
    std::cerr << "http_upgrade: missing required headers" << std::endl;
    return -1;
  }
  keyhdstart += 22;
  std::string::size_type keyhdend = resheader.find("\r\n", keyhdstart);
  std::string accept_key = resheader.substr(keyhdstart, keyhdend - keyhdstart);
  if (accept_key == create_acceptkey(client_key)) {
    body = resheader.substr(resheader.find("\r\n\r\n") + 4);
    return 0;
  } else {
    return -1;
  }
}


void ctl_epollev(int epollfd, int op, WebSocketClient &ws) {
  epoll_event ev;
  memset(&ev, 0, sizeof(ev));
  if (ws.want_read()) {
    ev.events |= EPOLLIN;
  }
  if (ws.want_write()) {
    ev.events |= EPOLLOUT;
  }
  if (epoll_ctl(epollfd, op, ws.fd(), &ev) == -1) {
    perror("epoll_ctl");
    exit(EXIT_FAILURE);
  }
}

/**
 * @brief
 * 
 * @param[in]
 * 
 * @return
*/
int communicate(const char *host, const char *service, const char *path,
                const struct wslay_event_callbacks *callbacks, const char* cacertPath) {

  struct wslay_event_callbacks cb = *callbacks;
  cb.recv_callback = feed_body_callback;
  struct tls_context* pTlsContext = NULL;
  tlsSession_init(&pTlsContext, cacertPath);
  tlsSession_connect(pTlsContext, host, service);
  
  std::cerr << "tls done" << std::endl;

  int fd = pTlsContext->socket.fd;//connect_to(host, service);

  if (fd == -1) {
    std::cerr << "Could not connect to the host" << std::endl;
    return -1;
  }
  std::string body;
  if (https_handshake(pTlsContext, host, service, path, body) == -1) {
    std::cerr << "Failed handshake" << std::endl;
    close(fd);
    return -1;
  }
  std::cerr << "handshake done" << std::endl;
  // set the socket option.
  make_non_block(fd);
  int val = 1;
  if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val)) ==
      -1) {
    perror("setsockopt: TCP_NODELAY");
    return -1;
  }
  // 
  WebSocketClient ws(fd, &cb, body, pTlsContext);
  if (ws.on_read_event() == -1) {
    return -1;
  }
  cb.recv_callback = callbacks->recv_callback;
  ws.set_callbacks(&cb);
  int epollfd = epoll_create(1);
  if (epollfd == -1) {
    perror("epoll_create");
    return -1;
  }
  ctl_epollev(epollfd, EPOLL_CTL_ADD, ws);
  static const size_t MAX_EVENTS = 1;
  epoll_event events[MAX_EVENTS];
  bool ok = true;
  
  
  std::cerr << "polling start" << std::endl;
  while (ws.want_read() || ws.want_write()) {
    int nfds = epoll_wait(epollfd, events, MAX_EVENTS, 1000);
    //std::cerr << "wait" << std::endl;
    //printf("nfds:%x\n", nfds);
    if (nfds == -1) {
      perror("epoll_wait");
      return -1;

    }else if (nfds == 0){
      std::cerr << "echo start" << std::endl;
      ws.test_echo();
    }
    for (int n = 0; n < nfds; ++n) {
      if (((events[n].events & EPOLLIN) && ws.on_read_event() != 0) ||
          ((events[n].events & EPOLLOUT) && ws.on_write_event() != 0)) {
        ok = false;
        break;
      }
    }
    if (!ok) {
      break;
    }
    ctl_epollev(epollfd, EPOLL_CTL_MOD, ws);
  }
  return ok ? 0 : -1;
}
/**
 * @brief get the count of test cases.
*/
int get_casecnt(const char *host, const char *service, char* cacerPath) {
  struct wslay_event_callbacks callbacks = {
      recv_callback,
      send_callback,
      genmask_callback,
      NULL, /* on_frame_recv_start_callback */
      NULL, /* on_frame_recv_callback */
      NULL, /* on_frame_recv_end_callback */
      get_casecnt_on_msg_recv_callback};
  if (communicate(host, service, "/getCaseCount", &callbacks, cacerPath) == -1) {
    return -1;
  }
  errno = 0;
  int casecnt = strtol(casecntjson.c_str(), 0, 10);
  if (errno == ERANGE) {
    return -1;
  } else {
    return casecnt;
  }
}

int run_testcase(const char *host, const char *service, int casenum) {
  struct wslay_event_callbacks callbacks = {
      recv_callback,
      send_callback,
      genmask_callback,
      NULL, /* on_frame_recv_start_callback */
      NULL, /* on_frame_recv_callback */
      NULL, /* on_frame_recv_end_callback */
      on_msg_recv_callback};
  char buf[1024];
  snprintf(buf, sizeof(buf), "/runCase?case=%d&agent=wslay", casenum);
  return communicate(host, service, buf, &callbacks, NULL);
}
int update_reports(const char *host, const char *service) {
  struct wslay_event_callbacks callbacks = {
      recv_callback, send_callback, genmask_callback,
      NULL, /* on_frame_recv_start_callback */
      NULL, /* on_frame_recv_callback */
      NULL, /* on_frame_recv_end_callback */
      NULL, /* on_msg_recv_callback */
  };
  return communicate(host, service, "/updateReports?&agent=wslay", &callbacks, NULL);
}

int main(int argc, char **argv) {
  if (argc < 3) {
    std::cerr << "Usage: " << argv[0] << " HOST SERV" << std::endl;
    exit(EXIT_FAILURE);
  }
  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, 0);
  const char *host = argv[1];
  const char *service = argv[2];
  printf("ip:%s, port:%s, cert:%s\n", argv[1], argv[2], argv[3]);
  int casecnt = get_casecnt(host, service, argv[3]);
  if (casecnt == -1) {
    std::cerr << "Failed to get case count." << std::endl;
    exit(EXIT_FAILURE);
  }
  for (int i = 1; i <= casecnt; ++i) {
    std::cout << "Running test case " << i << std::endl;
    if (run_testcase(host, service, i) == -1) {
      std::cout << "Detected error during test" << std::endl;
    }
  }
  if (update_reports(host, service) == -1) {
    std::cerr << "Failed to update reports." << std::endl;
    exit(EXIT_FAILURE);
  }
}
