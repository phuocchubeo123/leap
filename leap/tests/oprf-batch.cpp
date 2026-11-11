/*
 * Batched Leap OPRF benchmark (two processes / two machines).
 *
 * Uses the authors' batched OPRF implementation from the PSI code
 * (SpringNRPSIServer / SpringNRPSIClient):
 *   - Setup():  server key generation + PSI cuckoo filter of a one-element
 *               server set (not measured).
 *   - Base(B):  offline phase: base OT + OT extension for B evaluations and
 *               derivation of all OT-based correlations.
 *   - Online(): online phase for the whole batch of B inputs: subset-sum, OLE
 *               and rounding, each one batched round trip.
 *
 * Usage:
 *   oprf-batch server 0.0.0.0     <port> <log2(B)>
 *   oprf-batch client <server-ip> <port> <log2(B)>
 *
 * For each phase both parties first run a 1-byte barrier (not measured), then
 * report wall-clock time, process CPU time (CLOCK_PROCESS_CPUTIME_ID, all
 * threads) and bytes sent/received on the coproto socket (incl. coproto's
 * 8-byte per-message header), as a machine-readable RESULT line.
 *
 * Correctness (after the measured phases, testing only): the client sends its
 * inputs to the server, which returns the plaintext PRF values; the client
 * compares them with all of its OPRF outputs. (The PSI's own cuckoo-filter
 * membership test is not used: it gives false negatives for server sets with
 * more than one element, independently of the OPRF.)
 */
#include <coproto/Socket/AsioSocket.h>
#include <ctime>
#include <iostream>
#include <leap/psi/SpringNRPSIClient.h>
#include <leap/psi/SpringNRPSIServer.h>
#include <string>

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

static double cpu_ms() {
  timespec ts;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
  return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

struct Meter {
  cp::Socket &sock;
  std::chrono::steady_clock::time_point wall0;
  double cpu0;
  size_t sent0, recv0;
  explicit Meter(cp::Socket &s)
      : sock(s), wall0(std::chrono::steady_clock::now()), cpu0(cpu_ms()),
        sent0(s.bytesSent()), recv0(s.bytesReceived()) {}
  void report(const char *role, const char *phase, size_t batch) {
    double wall = std::chrono::duration<double, std::milli>(
                      std::chrono::steady_clock::now() - wall0)
                      .count();
    double cpu = cpu_ms() - cpu0;
    std::cout << "RESULT protocol=leap role=" << role << " phase=" << phase
              << " batch=" << batch << " wall_ms=" << wall
              << " cpu_ms=" << cpu << " sent=" << sock.bytesSent() - sent0
              << " recv=" << sock.bytesReceived() - recv0 << std::endl;
  }
};

int main(int argc, char **argv) {
  if (argc < 5) {
    std::cout << "usage: " << argv[0]
              << " {server|client} {ip} {port} {log2(batch)}" << std::endl;
    return -1;
  }
  std::string role = argv[1];
  std::string ip = std::string(argv[2]) + ":" + argv[3];
  int exp = std::stoi(argv[4]);
  if (exp < 0 || exp > 24 || (role != "server" && role != "client")) {
    std::cout << "bad arguments" << std::endl;
    return -1;
  }
  size_t batch = 1ULL << exp;
  const block sanity = toBlock((const uint8_t *)"ffffffff88888888");

  if (role == "server") {
    cp::AsioSocket sock = coproto::asioConnect(ip, true);
    LEAP::SpringNRPSIServer server(sock, 1);
    // PSI server set (only needed because Setup() builds the PSI filter)
    std::vector<block> elements{sanity};
    server.Setup(elements);

    barrier(sock, true);
    {
      Meter m(sock);
      server.Base();
      m.report("server", "offline", batch);
    }
    barrier(sock, true);
    {
      Meter m(sock);
      server.Online();
      coproto::sync_wait(sock.flush());
      m.report("server", "online", batch);
    }
    // Correctness check, outside of all measurements and for testing only:
    // the client reveals its inputs, the server returns the plaintext PRF.
    std::vector<block> inputs(batch);
    coproto::sync_wait(sock.recv(inputs));
    std::vector<uint64_t> expected(batch);
    for (size_t i = 0; i < batch; i++)
      expected[i] = LEAP::prf(inputs[i], server.keys());
    coproto::sync_wait(sock.send(expected));
    coproto::sync_wait(sock.flush());
    return 0;
  }

  cp::AsioSocket sock = coproto::asioConnect(ip, false);
  LEAP::SpringNRPSIClient client(sock);
  client.Setup();

  std::vector<block> elements;
  elements.push_back(sanity);
  PRNG prng(sysRandomSeed());
  for (size_t i = 1; i < batch; i++)
    elements.push_back(prng.get<block>());

  barrier(sock, false);
  {
    Meter m(sock);
    client.Base(elements.size());
    m.report("client", "offline", batch);
  }
  barrier(sock, false);
  {
    Meter m(sock);
    client.Online(elements);
    m.report("client", "online", batch);
  }
  // Correctness check (not measured): compare all outputs with the server's
  // plaintext PRF on the same inputs.
  coproto::sync_wait(sock.send(elements));
  std::vector<uint64_t> expected(batch);
  coproto::sync_wait(sock.recv(expected));
  size_t wrong = 0;
  for (size_t i = 0; i < batch; i++)
    wrong += (expected[i] != client.last_outputs[i]);
  std::cout << "CORRECTNESS protocol=leap " << (wrong ? "FAIL" : "OK") << " ("
            << batch - wrong << "/" << batch << " outputs correct)" << std::endl;
  return wrong ? 1 : 0;
}
