/*
 * Leap OPRF benchmark, split into two processes so that client and server can
 * run on different machines.
 *
 * Usage:
 *   server machine:  oprf-ref server 0.0.0.0     <port> [reps]
 *   client machine:  oprf-ref client <server-ip> <port> [reps]
 *   single machine:  oprf-ref local  127.0.0.1   <port> [reps]   (both roles,
 *                    two threads, like the original binary)
 *
 * `server`/`client` may also be given as `0`/`1` (as in test-psi).
 *
 * Networking: the libOTe/coproto AsioSocket (TCP, TCP_NODELAY) that the
 * original code already used. The server listens, the client connects, and a
 * single connection is reused for all repetitions. Before each repetition the
 * parties run a 1-byte barrier (not counted, not timed) so that both machines
 * start timing at the same protocol point. Byte counts come from the coproto
 * socket counters and therefore include coproto's 8-byte per-message header.
 *
 * The protocol code itself (base OT, OT extension, subset-sum, OLE, rounding,
 * BCH) is unchanged from the original single-process version.
 */
#include <coproto/Socket/AsioSocket.h>
#include <cryptoTools/Common/Matrix.h>
#include <cstring>
#include <leap/oprf/BCH.h>
#include <leap/oprf/PRF.h>
#include <leap/oprf/Subset128.h>
#include <leap/oprf/ntt-falcon.h>
#include <libOTe/Base/MasnyRindalKyber.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h>
#include <unistd.h>

#include <iostream>
#include <numeric>
#include <string>
#include <thread>

#define LEAP_MICRO_BENCHMARKS

using namespace osuCrypto;
using namespace LEAP;

// N (=128) comes from leap/oprf/params.h
#define HASHLEN N

static const size_t numBaseOTs = 128;

////////////////////////////////////////////////////
////////////////// Networking helpers //////////////
////////////////////////////////////////////////////

// 1-byte ping-pong so that both parties start the measured section together.
// Executed outside of every timed/counted region.
static void barrier(cp::Socket &sock, bool isServer) {
  uint8_t token = 0;
  if (isServer) {
    coproto::sync_wait(sock.recv(token));
    coproto::sync_wait(sock.send(token));
  } else {
    coproto::sync_wait(sock.send(token));
    coproto::sync_wait(sock.recv(token));
  }
  coproto::sync_wait(sock.flush());
}

struct ClientStats {
  double overall_ms = 0;   // base OT + online, wall clock
  double baseot_ms = 0;    // base OT + OT extension, wall clock
  double online_us = 0;    // subset-sum -> digest, wall clock (incl. network)
  size_t sent = 0, recv = 0;               // whole evaluation
  size_t online_sent = 0, online_recv = 0; // online part only
  uint64_t prf_out = 0;
};

////////////////////////////////////////////////////
////////////////// Client //////////////////////////
////////////////////////////////////////////////////
static ClientStats run_client(cp::Socket &client_socket) {
  ClientStats st;
  PRNG prng(sysRandomSeed());
  SHAKE256 shake256;
  Timer time;
  osuCrypto::block input =
      osuCrypto::toBlock((const uint8_t *)"ffffffff88888888");

  ////////////////////////////////////////////////////
  ////////////////// Base OT    //////////////////////
  ////////////////////////////////////////////////////
  auto base_start = client_socket.bytesSent();
  auto base_start_recv = client_socket.bytesReceived();
  auto cc_bot = time.setTimePoint("bot");
  osuCrypto::BitVector ot_choices_;
  std::vector<osuCrypto::block> ots_;

  std::vector<std::array<block, 2>> baseOTs;
  baseOTs.resize(numBaseOTs);
  osuCrypto::span<std::array<block, 2>> baseOTsSpan(baseOTs.data(),
                                                    baseOTs.size());

  // base OT
  MasnyRindalKyber ot;
  coproto::sync_wait(ot.send(baseOTsSpan, prng, client_socket));

  // OT extension
  IknpOtExtReceiver OTeRecv;
  OTeRecv.setBaseOts(baseOTsSpan);
  ot_choices_.resize(N * 19);
  ot_choices_.randomize(prng);
  ots_.resize(ot_choices_.size());
  osuCrypto::span<osuCrypto::block> otSpan(ots_.data(), ots_.size());
  coproto::sync_wait(OTeRecv.receive(ot_choices_, otSpan, prng, client_socket));

  // generate blinding polynomials for subset-sum step
  std::vector<Subset128> ot_res;
  for (size_t j = 0; j < N; ++j) {
    Subset128 res(ots_[j], &shake256);
    ot_res.push_back(res);
  }

  std::array<uint16_t, N * LOG_Q> ole_int{0};
  for (size_t j = 0; j < N * LOG_Q; ++j) {
    // generate OLE elements
    shake256.Reset(2);
    shake256.Update((uint8_t *)&ots_[N + j], 128 / 8);
    shake256.Final((uint8_t *)&ole_int[j]);
    ole_int[j] = ole_int[j] & 0x1ff;
    while (ole_int[j] >= SPRING_Q) {
      // rejection sampling to get OLE input in [0, SPRING_Q]
      shake256.Final((uint8_t *)&ole_int[j]);
      ole_int[j] = ole_int[j] & 0x1ff;
    }
  }

  auto base_end = client_socket.bytesSent();
  auto base_end_recv = client_socket.bytesReceived();

  ////////////////////////////////////////////////////
  ////////////////// Subset-Sum    ///////////////////
  ////////////////////////////////////////////////////

  auto cc_subsum_prep = time.setTimePoint("subsum-prep");
  Subset128 aggregated;
  std::vector<uint8_t> received(128 * N);
  auto recvSpan = osuCrypto::span<uint8_t>((uint8_t *)received.data(), 128 * N);
  BitVector server_bv;
  server_bv.copy(ot_choices_, 0, N);
  osuCrypto::BitVector bv;
  bv.assign(input);
  server_bv = server_bv ^ bv;
  auto serverBvSpan =
      osuCrypto::span<uint8_t>(server_bv.data(), server_bv.sizeBytes());

#ifdef LEAP_MICRO_BENCHMARKS
  auto cc_subsum_wait = time.setTimePoint("subsum-wait");
#endif
  coproto::sync_wait(client_socket.send(serverBvSpan));
  coproto::sync_wait(client_socket.recv(recvSpan));
#ifdef LEAP_MICRO_BENCHMARKS
  auto cc_subsum = time.setTimePoint("subsum");
#endif
  uint8_t *r_ptr = received.data();
  for (size_t j = 0; j < N; ++j) {
    Subset128 r(r_ptr);
    if (bv[j]) {
      aggregated = aggregated + (ot_res[j] ^ r);
    } else {
      aggregated = aggregated + ot_res[j];
    }
    r_ptr += N;
  }

  auto cc_end = client_socket.bytesSent();

  ////////////////////////////////////////////////////
  //////////////// Client OLE  ///////////////////////
  ////////////////////////////////////////////////////
  auto cc_ole_prep = time.setTimePoint("ole-prep");
  // lift to subset product for OLE
  std::array<uint16_t, N> ole_in;
  aggregated.get_int_from_subsetsum(ole_in.data());

  // allocate 16*8*N bits for the correction vector
  std::array<uint16_t, N> y;
  size_t idx = 0;
  BitVector ole_corr(N * LOG_Q);
  for (uint16_t j : ole_in) {
    for (size_t k = 0; k < LOG_Q; ++k) {
      ole_corr[idx] = (j & (1 << k)) >> k;
      ++idx;
    }
  }
  // Inititialize BitVector with length bits pointed to by data.
  BitVector ole_choices;
  // get bitvector at correct offset
  ole_choices.copy(ot_choices_, N, N * LOG_Q);
  // XOR with choice bits
  ole_choices = ole_corr ^ ole_choices;
  auto oleSpan =
      osuCrypto::span<uint8_t>(ole_choices.data(), ole_choices.sizeBytes());
  // use uint32_t to avoid overflows
  std::vector<uint32_t> ole_enc(1152);

#ifdef LEAP_MICRO_BENCHMARKS
  auto cc_ole_wait = time.setTimePoint("ole-wait");
#endif
  coproto::sync_wait(client_socket.send(oleSpan));
  coproto::sync_wait(client_socket.recv(ole_enc));
#ifdef LEAP_MICRO_BENCHMARKS
  auto cc_ole = time.setTimePoint("ole");
#endif

  idx = 0;
  for (uint16_t &j : y) {
    uint32_t result = 0;
    for (size_t k = 0; k < LOG_Q; ++k) {
      if (ole_corr[idx]) {
        result =
            result + (((uint32_t)ole_int[idx] << k) ^ (uint32_t)ole_enc[idx]);
      } else {
        result = result + ((uint32_t)ole_int[idx] << k);
      }
      ++idx;
    }
    j = result % SPRING_Q;
  }

  auto ole_end = client_socket.bytesSent();
  auto cc_ntt = time.setTimePoint("ntt");
  intt(y.data());

  ////////////////////////////////////////////////////
  ////////////////// Client Rounding  ////////////////
  ////////////////////////////////////////////////////

  auto cc_rounding_prep = time.setTimePoint("round-prep");

  std::vector<block> recvMsgs(N);
  BitVector rounding_corr(1152);
  idx = 0;
  for (uint16_t j : y) {
    for (int64_t k = 8; k >= 0; --k) {
      rounding_corr[idx] = (j & (1 << k)) >> k;
      ++idx;
    }
  }

  // Inititialize BitVector with length bits pointed to by data.
  BitVector rounding_choices;
  // get bitvector at correct offset
  rounding_choices.copy(ot_choices_, N * 10, 1152);
  // XOR with choice bits
  rounding_choices = rounding_corr ^ rounding_choices;
  auto roundSpan = osuCrypto::span<uint8_t>(rounding_choices.data(),
                                            rounding_choices.sizeBytes());
  std::array<uint64_t, 2> biased{0};
  std::array<uint64_t, 2 * SPRING_Q> enc_bits{0};
  uint64_t mask;
#ifdef LEAP_MICRO_BENCHMARKS
  auto cc_rounding_wait = time.setTimePoint("round-wait");
#endif
  coproto::sync_wait(client_socket.send(roundSpan));
  coproto::sync_wait(client_socket.recv(enc_bits));
  coproto::sync_wait(client_socket.recv(mask));
#ifdef LEAP_MICRO_BENCHMARKS
  auto cc_round = time.setTimePoint("round");
#endif

  for (size_t j = 0; j < 64; ++j) {
    // note: the compiler may claim this variable is initialized and unused,
    // this is not the case as the loop below will always be executed
    uint8_t kee = 0;
    for (size_t l = 0; l < LOG_Q; ++l) {
      uint8_t *extract = (uint8_t *)&ots_[N * 10 + j * LOG_Q + l];
      kee ^= (extract[0] & 1);
    }
    biased[0] ^= (((enc_bits[y[j] * 2] >> j) & 1) ^ (uint64_t)kee) << j;
  }
  for (size_t j = 64; j < N; ++j) {
    // note: the compiler may claim this variable is initialized and unused,
    // this is not the case as the loop below will always be executed
    uint8_t kee = 0;
    for (size_t l = 0; l < LOG_Q; ++l) {
      uint8_t *extract = (uint8_t *)&ots_[N * 10 + j * LOG_Q + l];
      kee ^= (extract[0] & 1);
    }
    biased[1] |= (((enc_bits[y[j] * 2 + 1] >> (j - 64)) & 1) ^ (uint64_t)kee)
                 << (j - 64);
  }

  auto rounding_end = client_socket.bytesSent();
  auto cc_bch = time.setTimePoint("bch");
  uint64_t prf_out = mask ^ BCH128to64(biased.data());
  auto bch_end = client_socket.bytesSent();
  auto bch_end_recv = client_socket.bytesReceived();
  auto digest = LEAP::compute_digest(shake256, prf_out);
  auto postEnd = time.setTimePoint("dig-end");
  printf("[OPRF] Result: %ld\n", prf_out);
  printf("[OPRF] Digest: %ld\n", digest);

  /*
   * End of functional code, only benchmarks
   */

  auto overall =
      std::chrono::duration_cast<std::chrono::milliseconds>(postEnd - cc_bot)
          .count();
  auto b_t = std::chrono::duration_cast<std::chrono::milliseconds>(
                 cc_subsum_prep - cc_bot)
                 .count();
  auto sub_all_t = std::chrono::duration_cast<std::chrono::microseconds>(
                       cc_ole_prep - cc_subsum_prep)
                       .count();
  auto ole_all_t = std::chrono::duration_cast<std::chrono::microseconds>(
                       cc_rounding_prep - cc_ole_prep)
                       .count();
  auto ntt_t = std::chrono::duration_cast<std::chrono::microseconds>(
                   cc_rounding_prep - cc_ntt)
                   .count();
  auto rounding_t = std::chrono::duration_cast<std::chrono::microseconds>(
                        cc_bch - cc_rounding_prep)
                        .count();
  auto bch_t =
      std::chrono::duration_cast<std::chrono::microseconds>(postEnd - cc_bch)
          .count();
  auto online_t = std::chrono::duration_cast<std::chrono::microseconds>(
                      postEnd - cc_subsum_prep)
                      .count();
#ifdef LEAP_MICRO_BENCHMARKS
  auto subsum_prep_t = std::chrono::duration_cast<std::chrono::microseconds>(
                           cc_subsum_wait - cc_subsum_prep)
                           .count();
  auto subsum_wait_t = std::chrono::duration_cast<std::chrono::microseconds>(
                           cc_subsum - cc_subsum_wait)
                           .count();
  auto subsum_t = std::chrono::duration_cast<std::chrono::microseconds>(
                      cc_ole_prep - cc_subsum)
                      .count();
  auto ole_prep_t = std::chrono::duration_cast<std::chrono::microseconds>(
                        cc_ole_wait - cc_ole_prep)
                        .count();
  auto ole_wait_t = std::chrono::duration_cast<std::chrono::microseconds>(
                        cc_ole - cc_ole_wait)
                        .count();
  auto ole_t =
      std::chrono::duration_cast<std::chrono::microseconds>(cc_ntt - cc_ole)
          .count();
  auto rounding_all_t =
      std::chrono::duration_cast<std::chrono::microseconds>(cc_bch - cc_round)
          .count();
  auto rounding_prep_t = std::chrono::duration_cast<std::chrono::microseconds>(
                             cc_rounding_wait - cc_rounding_prep)
                             .count();
  auto rounding_wait_t = std::chrono::duration_cast<std::chrono::microseconds>(
                             cc_round - cc_rounding_wait)
                             .count();
#endif

  std::cout << "[Client] overall " << overall << " ms, baseOT " << b_t
            << " ms, Subset-Sum " << sub_all_t << " us, OLE " << ole_all_t
            << " us, NTT " << ntt_t << " us, rounding " << rounding_t
            << " us, BCH + postprocessing " << bch_t << " us" << std::endl;
#ifdef LEAP_MICRO_BENCHMARKS
  std::cout << "[Client] Microbenchmarks: \n\t Subsum:  " << subsum_prep_t
            << " us preparation, " << subsum_wait_t
            << " us waiting for server answer, " << subsum_t
            << " us computation\n\t OLE: " << ole_prep_t << " us preparation, "
            << ole_wait_t << " us waiting for server answer, " << ole_t
            << " us computation\n\t Rounding: " << rounding_prep_t
            << " us preparation, " << rounding_wait_t
            << " us waiting for server answer, " << rounding_all_t
            << " us computation" << std::endl;
#endif
  std::cout << "[Client] overall " << (bch_end - base_start) / 1024.0
            << " kiB, BaseOT " << (base_end - base_start) / 1024.0
            << " kiB,  online " << (bch_end - base_end)
            << " bytes,  Subset-Sum " << cc_end - base_end
            << " bytes,  OLE comms " << ole_end - cc_end
            << " bytes, Rounding Comms " << rounding_end - ole_end
            << " bytes,  BCH Comms " << bch_end - rounding_end << " bytes"
            << std::endl;
  std::cout << "[Client] online latency (subset-sum..digest, incl. network) "
            << online_t << " us; online traffic: sent "
            << (bch_end - base_end) << " B, received "
            << (bch_end_recv - base_end_recv) << " B; whole evaluation: sent "
            << (bch_end - base_start) << " B, received "
            << (bch_end_recv - base_start_recv) << " B" << std::endl;

  st.overall_ms = overall;
  st.baseot_ms = b_t;
  st.online_us = online_t;
  st.sent = bch_end - base_start;
  st.recv = bch_end_recv - base_start_recv;
  st.online_sent = bch_end - base_end;
  st.online_recv = bch_end_recv - base_end_recv;
  st.prf_out = prf_out;
  return st;
}

////////////////////////////////////////////////////
////////////////// Server //////////////////////////
////////////////////////////////////////////////////
static void run_server(cp::Socket &server_socket,
                       const std::vector<Subset128> &private_keys,
                       long prf_t) {
  Timer time;
  PRNG prng(sysRandomSeed());
  SHAKE256 shake256;

  ////////////////////////////////////////////////////
  ////////////////// Base OT    //////////////////////
  ////////////////////////////////////////////////////
  auto base_start = server_socket.bytesSent();
  auto base_start_recv = server_socket.bytesReceived();
  auto server_bot = time.setTimePoint("bot");
  std::vector<block> baseOTs;
  BitVector baseChoices(numBaseOTs);
  baseChoices.randomize(prng);
  baseOTs.resize(numBaseOTs);
  std::vector<std::array<osuCrypto::block, 2>> ots_;
  osuCrypto::span<block> baseOTsSpan(baseOTs.data(), baseOTs.size());

  MasnyRindalKyber ot;
  coproto::sync_wait(ot.receive(baseChoices, baseOTsSpan, prng, server_socket));

  osuCrypto::IknpOtExtSender otExtSender;
  otExtSender.setBaseOts(baseOTsSpan, baseChoices);

  // one for subset-sum, one for each gilboa coefficient bit, one for each
  // rounding
  ots_.resize(N * 19);
  osuCrypto::span<std::array<osuCrypto::block, 2>> otSpan(ots_.data(),
                                                          ots_.size());
  coproto::sync_wait(otExtSender.send(otSpan, prng, server_socket));

  std::vector<Subset128> r_0;
  std::vector<Subset128> r_1;
  for (size_t j = 0; j < N; ++j) {
    Subset128 r0(ots_[j][0], &shake256);
    Subset128 r1(ots_[j][1], &shake256);
    r_0.push_back(r0);
    r_1.push_back(r1);
  }

  std::array<uint16_t, N * LOG_Q> ole_r0;
  std::array<uint16_t, N * LOG_Q> ole_r1;
  for (size_t j = 0; j < N * LOG_Q; ++j) {
    // rejection sampling routine
    shake256.Reset(2);
    shake256.Update((uint8_t *)&ots_[N + j][0], 128 / 8);
    shake256.Final((uint8_t *)&ole_r0[j]);
    ole_r0[j] = ole_r0[j] & 0x1ff;
    while (ole_r0[j] >= SPRING_Q) {
      shake256.Final((uint8_t *)&ole_r0[j]);
      ole_r0[j] = ole_r0[j] & 0x1ff;
    }

    shake256.Reset(2);
    shake256.Update((uint8_t *)&ots_[N + j][1], 128 / 8);
    shake256.Final((uint8_t *)&ole_r1[j]);
    ole_r1[j] = ole_r1[j] & 0x1ff;
    while (ole_r1[j] >= SPRING_Q) {
      shake256.Final((uint8_t *)&ole_r1[j]);
      ole_r1[j] = ole_r1[j] & 0x1ff;
    }
  }

  auto base_end = server_socket.bytesSent();
  auto base_end_recv = server_socket.bytesReceived();

  ////////////////////////////////////////////////////
  ////////////////// Subset Sum //////////////////////
  ////////////////////////////////////////////////////
  // vectors of server_choices for PSI
  auto server_subsum_prep = time.setTimePoint("subsum-prep");
  osuCrypto::BitVector subsum_choices(N);
  auto serverSpan = osuCrypto::span<uint8_t>(subsum_choices.data(),
                                             subsum_choices.sizeBytes());

#ifdef LEAP_MICRO_BENCHMARKS
  auto server_subsum_wait = time.setTimePoint("subsum-wait");
#endif
  coproto::sync_wait(server_socket.recv(serverSpan));
#ifdef LEAP_MICRO_BENCHMARKS
  auto server_subsum = time.setTimePoint("subset-sum");
#endif

  Subset128 s_prime = private_keys[0];
  std::vector<uint8_t> send_poly(128 * N);
  for (size_t j = 0; j < N; ++j) {
    Subset128 randomness;
    if (subsum_choices[j]) {
      s_prime = s_prime - r_1[j];
      randomness = r_0[j] ^ (r_1[j] + private_keys[j + 1]);
    } else {
      s_prime = s_prime - r_0[j];
      randomness = r_1[j] ^ (r_0[j] + private_keys[j + 1]);
    }
    memcpy(send_poly.data() + j * N, (uint8_t *)randomness.dlog.data(), N);
  }
  auto polySpan = osuCrypto::span<uint8_t>((uint8_t *)send_poly.data(), 128 * N);
#ifdef LEAP_MICRO_BENCHMARKS
  auto server_subsum_wait_two = time.setTimePoint("subsum-wait-2");
#endif
  coproto::sync_wait(server_socket.send(polySpan));
  auto server_end = server_socket.bytesSent();

  //////////////////////////////////////////////////
  //////////////// OLE    //////////////////////////
  //////////////////////////////////////////////////
  auto server_ole_prep = time.setTimePoint("ole-prep");

  std::array<uint16_t, N> ole_in;
  s_prime.get_int_from_subsetsum(ole_in.data());
  std::array<uint16_t, N> blinder;
  // use uint32_t to avoid overflows
  std::array<uint32_t, 1152> ole_enc;
  BitVector ole_corr(1152);

  auto oleSpan = osuCrypto::span<uint8_t>(ole_corr.data(), ole_corr.sizeBytes());
#ifdef LEAP_MICRO_BENCHMARKS
  auto server_ole_wait = time.setTimePoint("ole-wait");
#endif
  coproto::sync_wait(server_socket.recv(oleSpan));
#ifdef LEAP_MICRO_BENCHMARKS
  auto server_ole = time.setTimePoint("ole");
#endif
  for (size_t j = 0; j < N; ++j) {
    uint64_t blinding_factor = 0;
    for (size_t k = 0; k < LOG_Q; k++) {
      // check if correction bit was set
      if (ole_corr[j * LOG_Q + k]) {
        // update blinding factor with r1 << k
        blinding_factor += (ole_r1[j * LOG_Q + k] << k);
        // encrypt OLE result with ole_r1 and XOR it with r0
        ole_enc[j * LOG_Q + k] =
            ((uint32_t)ole_r0[j * LOG_Q + k] << k) ^
            (((uint32_t)ole_in[j] + (uint32_t)ole_r1[j * LOG_Q + k]) << k);
      } else {
        // update blinding factor with r1 << k
        blinding_factor += (ole_r0[j * LOG_Q + k] << k);
        ole_enc[j * LOG_Q + k] =
            ((uint32_t)ole_r1[j * LOG_Q + k] << k) ^
            (((uint32_t)ole_in[j] + (uint32_t)ole_r0[j * LOG_Q + k]) << k);
      }
    }
    blinder[j] = blinding_factor % SPRING_Q;
  }
#ifdef LEAP_MICRO_BENCHMARKS
  auto server_ole_wait_two = time.setTimePoint("ole-wait-2");
#endif
  coproto::sync_wait(server_socket.send(ole_enc));
  auto ole_end = server_socket.bytesSent();

  auto server_ntt = time.setTimePoint("ntt");

  intt(blinder.data());

  ////////////////////////////////////////////////////
  ////////////////// Rounding    /////////////////////
  ////////////////////////////////////////////////////
  auto server_rounding_prep = time.setTimePoint("round-prep");
  BitVector rounding_corr(1152);
  auto roundSpan =
      osuCrypto::span<uint8_t>(rounding_corr.data(), rounding_corr.sizeBytes());
#ifdef LEAP_MICRO_BENCHMARKS
  auto server_rounding_wait = time.setTimePoint("round-wait");
#endif
  coproto::sync_wait(server_socket.recv(roundSpan));
#ifdef LEAP_MICRO_BENCHMARKS
  auto server_rounding = time.setTimePoint("round");
#endif

  // 128 poly coefficients, for each we have SPRING_Q options:
  // (128*SPRING_Q)/64=SPRING_Q*2
  std::array<uint64_t, SPRING_Q * 2> enc_bits{0};

  std::array<uint64_t, 2> mask{0};
  for (uint64_t &j : mask) {
    j = prng.get<uint64_t>();
  }

  /*
   * XOR rounding result with OT keys
   * encrypt meserverages s.t. enc_i=m_i^(e(1^{i_j})
   */
  for (int32_t k = 0; k < SPRING_Q; k++) {
    for (size_t j = 0; j < 64; ++j) {
      uint16_t r0 = 0;
      uint16_t r1 = 0;
      for (size_t l = 0; l < LOG_Q; ++l) {
        uint8_t *extract = (uint8_t *)&ots_[N * 10 + j * LOG_Q + l][0];
        r0 |= (extract[0] & 1) << l;
        extract = (uint8_t *)&ots_[N * 10 + j * LOG_Q + l][1];
        r1 |= (extract[0] & 1) << l;
      }
      uint8_t bit = 0;
      // compute assumed rounding value
      int32_t to_round = (int32_t)(k - (int32_t)blinder[j]);
      while (to_round < 0) {
        to_round += SPRING_Q;
      }
      while (to_round >= SPRING_Q) {
        to_round -= SPRING_Q;
      }
      if ((to_round > 63) && (to_round < 193)) {
        bit ^= 1;
      }
      // encrypt result bit with OT taking corrections into account
      for (size_t l = 0; l < LOG_Q; ++l) {
        if (rounding_corr[j * LOG_Q + l]) {
          // correction bit set, switch how encryption works
          if ((k >> (LOG_Q - l - 1)) & 1) {
            bit ^= ((r0 >> l) & 1);
          } else {
            bit ^= ((r1 >> l) & 1);
          }
        } else {
          // correct bit was already requested
          if ((k >> (LOG_Q - l - 1)) & 1) {
            bit ^= ((r1 >> l) & 1);
          } else {
            bit ^= ((r0 >> l) & 1);
          }
        }
      }
      enc_bits[2 * k] |= ((uint64_t)bit << j);
    }
    enc_bits[2 * k] ^= mask[0];
    for (size_t j = 64; j < N; ++j) {
      uint16_t r0 = 0;
      uint16_t r1 = 0;
      for (size_t l = 0; l < LOG_Q; ++l) {
        uint8_t *extract = (uint8_t *)&ots_[N * 10 + j * LOG_Q + l][0];
        r0 |= (extract[0] & 1) << l;
        extract = (uint8_t *)&ots_[N * 10 + j * LOG_Q + l][1];
        r1 |= (extract[0] & 1) << l;
      }
      uint8_t bit = 0;
      // compute assumed rounding value
      int32_t to_round = (int32_t)(k - (int32_t)blinder[j]);
      while (to_round < 0) {
        to_round += SPRING_Q;
      }
      while (to_round >= SPRING_Q) {
        to_round -= SPRING_Q;
      }
      if ((to_round > 63) && (to_round < 193))
        // round up if centered
        bit ^= 1;
      for (size_t l = 0; l < LOG_Q; ++l) {
        if (rounding_corr[j * LOG_Q + l]) {
          // switch
          if ((k >> (LOG_Q - l - 1)) & 1) {
            bit ^= ((r0 >> l) & 1);
          } else {
            bit ^= ((r1 >> l) & 1);
          }
        } else {
          if ((k >> (LOG_Q - l - 1)) & 1) {
            bit ^= ((r1 >> l) & 1);
          } else {
            bit ^= ((r0 >> l) & 1);
          }
        }
      }
      enc_bits[2 * k + 1] |= ((uint64_t)bit << (j - 64));
    }
    enc_bits[2 * k + 1] ^= mask[1];
  }

#ifdef LEAP_MICRO_BENCHMARKS
  auto server_rounding_wait_two = time.setTimePoint("round-end");
#endif
  coproto::sync_wait(server_socket.send(enc_bits));
  auto rounding_end = server_socket.bytesSent();

  auto server_bch = time.setTimePoint("bch");
  uint64_t bch_mask = BCH128to64(mask.data());
  coproto::sync_wait(server_socket.send(bch_mask));
  auto server_fin = time.setTimePoint("end");
  auto bch_end = server_socket.bytesSent();
  auto bch_end_recv = server_socket.bytesReceived();

  /*
   * End of functional code, only benchmarks
   */

  auto overall = std::chrono::duration_cast<std::chrono::milliseconds>(
                     server_fin - server_bot)
                     .count();
  auto b_t = std::chrono::duration_cast<std::chrono::milliseconds>(
                 server_subsum_prep - server_bot)
                 .count();
  auto sub_all_t = std::chrono::duration_cast<std::chrono::microseconds>(
                       server_ole_prep - server_subsum_prep)
                       .count();
  auto ole_all_t = std::chrono::duration_cast<std::chrono::microseconds>(
                       server_rounding_prep - server_ole_prep)
                       .count();
  auto rounding_all_t = std::chrono::duration_cast<std::chrono::microseconds>(
                            server_bch - server_rounding_prep)
                            .count();
  auto bch_t = std::chrono::duration_cast<std::chrono::microseconds>(
                   server_fin - server_bch)
                   .count();
  auto ntt_t = std::chrono::duration_cast<std::chrono::microseconds>(
                   server_rounding_prep - server_ntt)
                   .count();

#ifdef LEAP_MICRO_BENCHMARKS
  auto subsum_prep_t = std::chrono::duration_cast<std::chrono::microseconds>(
                           server_subsum_wait - server_subsum_prep)
                           .count();
  auto subsum_wait_t = std::chrono::duration_cast<std::chrono::microseconds>(
                           server_subsum - server_subsum_wait +
                           server_ole_prep - server_subsum_wait_two)
                           .count();
  auto subsum_t = std::chrono::duration_cast<std::chrono::microseconds>(
                      server_subsum_wait_two - server_subsum)
                      .count();

  auto ole_prep_t = std::chrono::duration_cast<std::chrono::microseconds>(
                        server_ole_wait - server_ole_prep)
                        .count();
  auto ole_wait_t = std::chrono::duration_cast<std::chrono::microseconds>(
                        server_ole - server_ole_wait + server_rounding_prep -
                        server_ole_wait_two)
                        .count();
  auto ole_t = std::chrono::duration_cast<std::chrono::microseconds>(
                   server_ole_wait_two - server_ole)
                   .count();

  auto rounding_prep_t = std::chrono::duration_cast<std::chrono::microseconds>(
                             server_rounding_wait - server_rounding_prep)
                             .count();
  auto rounding_t = std::chrono::duration_cast<std::chrono::microseconds>(
                        server_rounding_wait_two - server_rounding)
                        .count();
  auto rounding_wait_t = std::chrono::duration_cast<std::chrono::microseconds>(
                             server_rounding - server_rounding_wait +
                             server_bch - server_rounding_wait_two)
                             .count();
#endif

  std::cout << "[Server] overall " << overall << " ms, PRF " << prf_t
            << " ms, baseOT " << b_t << " ms, Subset - Sum " << sub_all_t
            << " us, OLE " << ole_all_t << " us, NTT " << ntt_t
            << " us, rounding " << rounding_all_t << " us, BCH " << bch_t
            << " us" << std::endl;
#ifdef LEAP_MICRO_BENCHMARKS
  std::cout << "[Server] Microbenchmarks: \n\t Subsum:  " << subsum_prep_t
            << "us preparation, " << subsum_wait_t
            << " us waiting for client answer, " << subsum_t
            << " us computation\n\t OLE: " << ole_prep_t << "us preparation, "
            << ole_wait_t << " us waiting for client answer, " << ole_t
            << " us computation\n\t Rounding: " << rounding_prep_t
            << "us preparation, " << rounding_wait_t
            << " us waiting for client answer, " << rounding_t
            << " us computation" << std::endl;
#endif
  std::cout << "[Server] overall " << (bch_end - base_start) / 1024.0
            << " kiB, BaseOT " << (base_end - base_start) / 1024.0
            << " kiB,  online " << (bch_end - base_end)
            << " bytes,  Subset-Sum " << server_end - base_end
            << " bytes,  OLE comms " << ole_end - server_end
            << " bytes, Rounding Comms " << rounding_end - ole_end
            << " bytes, BCH Comms " << bch_end - rounding_end << " bytes"
            << std::endl;
  std::cout << "[Server] online traffic: sent " << (bch_end - base_end)
            << " B, received " << (bch_end_recv - base_end_recv)
            << " B; whole evaluation: sent " << (bch_end - base_start)
            << " B, received " << (bch_end_recv - base_start_recv) << " B"
            << std::endl;
}

////////////////////////////////////////////////////
////////////////// Drivers /////////////////////////
////////////////////////////////////////////////////

// Runs `reps` evaluations as the client. Returns the number of evaluations
// whose output did not match the server's plaintext PRF (sanity check).
static int client_main(cp::Socket &sock, size_t reps) {
  std::vector<ClientStats> stats;
  int failures = 0;
  for (size_t rep = 0; rep < reps; ++rep) {
    barrier(sock, false);
    std::cout << "\n===== [Client] evaluation " << rep + 1 << "/" << reps
              << " =====" << std::endl;
    stats.push_back(run_client(sock));

    // Correctness check, outside of all measurements: the server sends the
    // plaintext PRF value of the fixed test input.
    uint64_t expected = 0;
    coproto::sync_wait(sock.recv(expected));
    bool ok = (expected == stats.back().prf_out);
    failures += !ok;
    std::cout << "[Client] correctness check: "
              << (ok ? "OK" : "MISMATCH") << " (server PRF " << expected
              << ")" << std::endl;
  }

  auto avg = [&](auto f) {
    double s = 0;
    for (auto &x : stats)
      s += f(x);
    return s / stats.size();
  };
  std::cout << "\n===== [Client] summary over " << reps
            << " evaluation(s) =====\n"
            << "  avg overall (base OT + online): "
            << avg([](auto &x) { return x.overall_ms; }) << " ms\n"
            << "  avg base OT + OT ext:           "
            << avg([](auto &x) { return x.baseot_ms; }) << " ms\n"
            << "  avg online latency:             "
            << avg([](auto &x) { return x.online_us; }) << " us\n"
            << "  per evaluation traffic: client sent "
            << stats.back().sent << " B, received " << stats.back().recv
            << " B (online part: sent " << stats.back().online_sent
            << " B, received " << stats.back().online_recv << " B)\n"
            << "  correctness failures: " << failures << std::endl;
  return failures;
}

static void server_main(cp::Socket &sock, size_t reps,
                        const std::vector<Subset128> &private_keys,
                        uint64_t expected_prf, long prf_t) {
  for (size_t rep = 0; rep < reps; ++rep) {
    barrier(sock, true);
    std::cout << "\n===== [Server] evaluation " << rep + 1 << "/" << reps
              << " =====" << std::endl;
    run_server(sock, private_keys, prf_t);
    // correctness check message, outside of all measurements
    coproto::sync_wait(sock.send(expected_prf));
  }
  coproto::sync_wait(sock.flush());
}

static void usage(const char *prog) {
  std::cout << "usage: " << prog << " {server|client|local} {ip} {port} [reps]\n"
            << "  server: listen on ip:port (e.g. 0.0.0.0)\n"
            << "  client: connect to the server at ip:port\n"
            << "  local : run both roles in one process (two threads)\n"
            << "  `0`/`1` are accepted for server/client.\n"
            << "  reps  : number of OPRF evaluations (default 1)" << std::endl;
}

int main(int argc, char **argv) {
  if (argc < 4) {
    usage(argv[0]);
    return -1;
  }
  std::string role = argv[1];
  if (role == "0")
    role = "server";
  if (role == "1")
    role = "client";
  if (role != "server" && role != "client" && role != "local") {
    usage(argv[0]);
    return -1;
  }
  std::string ip = std::string(argv[2]) + ":" + argv[3];
  size_t reps = argc > 4 ? std::stoul(argv[4]) : 1;
  if (reps == 0) {
    usage(argv[0]);
    return -1;
  }

  if (role == "client") {
    cp::Socket sock = coproto::asioConnect(ip, false);
    int failures = client_main(sock, reps);
    coproto::sync_wait(sock.flush());
    return failures ? 1 : 0;
  }

  // Key generation and plaintext PRF (server side, not part of the protocol
  // measurements).
  PRNG prng(sysRandomSeed());
  std::vector<Subset128> private_keys;

  ////////////////////////////////////////////////////
  ////////////////// Setup    ////////////////////////
  ////////////////////////////////////////////////////
  auto time_start = std::chrono::high_resolution_clock::now();
  for (size_t i = 0; i < HASHLEN + 1; ++i) {
    Subset128 rand;
    rand.rand_poly(&prng);
    private_keys.push_back(rand);
  }
  auto time_end = std::chrono::high_resolution_clock::now();
  std::chrono::microseconds time_keygen_micro =
      std::chrono::duration_cast<std::chrono::microseconds>(time_end -
                                                            time_start);

  std::cout << "SPRING KeyGen Time: " << time_keygen_micro.count()
            << " microseconds" << std::endl;

  osuCrypto::block sanity =
      osuCrypto::toBlock((const uint8_t *)"ffffffff88888888");
  auto time0 = std::chrono::high_resolution_clock::now();
  uint64_t prf_out = LEAP::prf(sanity, private_keys);
  auto time4 = std::chrono::high_resolution_clock::now();
  printf("[PRF] %ld\n", prf_out);
  long prf_t =
      std::chrono::duration_cast<std::chrono::milliseconds>(time4 - time0)
          .count();

  if (role == "server") {
    std::cout << "[Server] listening on " << ip << std::endl;
    cp::Socket sock = coproto::asioConnect(ip, true);
    server_main(sock, reps, private_keys, prf_out, prf_t);
    return 0;
  }

  // local: both roles in one process, as in the original benchmark
  int failures = 0;
  auto clientThread = std::thread([&]() {
    cp::Socket sock = coproto::asioConnect(ip, false);
    failures = client_main(sock, reps);
    coproto::sync_wait(sock.flush());
  });
  {
    cp::Socket sock = coproto::asioConnect(ip, true);
    server_main(sock, reps, private_keys, prf_out, prf_t);
  }
  clientThread.join();
  return failures ? 1 : 0;
}
