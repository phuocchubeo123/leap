#pragma once

#include <algorithm>
#include <cstdint>
#include <vector>

#include <coproto/coproto.h>
#include <cryptoTools/Common/Defines.h>

namespace LEAP {

// coproto frames carry a 32-bit length, so one message must stay below 4 GiB
// (the 2^18 client-set OT correction message is exactly 4 GiB and arrives as a
// "badCoprotoMessageHeader"). Large buffers are sent as consecutive 1 GiB
// messages; the receiver splits its (equally sized) buffer the same way, so
// both sides only need to agree on the total byte count. Same scheme as the
// Pool benchmark (ot-pq-oprf). Payload is unchanged.
constexpr size_t kMaxMsgBytes = size_t(1) << 30;

template <typename Sock>
inline void send_chunked(Sock &sock, const uint8_t *data, size_t bytes) {
  for (size_t off = 0; off < bytes; off += kMaxMsgBytes) {
    osuCrypto::span<const uint8_t> part(data + off,
                                        std::min(kMaxMsgBytes, bytes - off));
    coproto::sync_wait(sock.send(part));
  }
}

template <typename Sock>
inline void recv_chunked(Sock &sock, uint8_t *data, size_t bytes) {
  for (size_t off = 0; off < bytes; off += kMaxMsgBytes) {
    osuCrypto::span<uint8_t> part(data + off,
                                  std::min(kMaxMsgBytes, bytes - off));
    coproto::sync_wait(sock.recv(part));
  }
}

template <typename Sock, typename T>
inline void send_chunked(Sock &sock, osuCrypto::span<T> buf) {
  send_chunked(sock, (const uint8_t *)buf.data(), buf.size() * sizeof(T));
}

template <typename Sock, typename T>
inline void recv_chunked(Sock &sock, osuCrypto::span<T> buf) {
  recv_chunked(sock, (uint8_t *)buf.data(), buf.size() * sizeof(T));
}

template <typename Sock, typename T>
inline void send_chunked(Sock &sock, std::vector<T> &buf) {
  send_chunked(sock, (const uint8_t *)buf.data(), buf.size() * sizeof(T));
}

template <typename Sock, typename T>
inline void recv_chunked(Sock &sock, std::vector<T> &buf) {
  recv_chunked(sock, (uint8_t *)buf.data(), buf.size() * sizeof(T));
}

} // namespace LEAP
