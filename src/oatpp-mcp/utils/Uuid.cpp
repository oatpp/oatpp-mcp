#include "Uuid.hpp"

#include <cstdio>
#include <mutex>
#include <random>

namespace oatpp { namespace mcp { namespace utils {

namespace {

/**
 * Process-wide entropy source.
 *
 * Allocated once and deliberately never destroyed: sessions run on detached threads that can still
 * be calling this during shutdown, after function-local statics would have been torn down, and a
 * mutex destroyed under a thread that is waiting on it is a far worse bug than a few bytes the
 * loader never gets back.
 */
struct EntropySource {
  std::random_device device;
  std::mutex mutex;
};

EntropySource& entropySource() {
  static EntropySource* source = new EntropySource();
  return *source;
}

/**
 * Fill @p out with @p size bytes from the entropy source.
 *
 * `std::random_device::operator()` is not required to be thread-safe for the same object, so the
 * calls are serialized. One call yields 32 bits and all of them are used.
 */
void fillRandomBytes(unsigned char* out, v_buff_size size) {
  auto& source = entropySource();
  std::lock_guard<std::mutex> lock(source.mutex);
  for(v_buff_size i = 0; i < size; i += 4) {
    auto word = source.device();
    for(v_buff_size j = 0; j < 4 && i + j < size; j++) {
      out[i + j] = static_cast<unsigned char>((word >> (8 * j)) & 0xFF);
    }
  }
}

}

oatpp::String Uuid::generateV4() {

  unsigned char bytes[16];
  fillRandomBytes(bytes, sizeof(bytes));

  /*
   * Six of the 128 bits are fixed by RFC 4122 and are not random: the version nibble and the
   * variant bits. What remains - 122 bits - is what an attacker has to guess.
   */
  bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0F) | 0x40);  // version 4, §4.4
  bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3F) | 0x80);  // variant 10xx, §4.1.1

  auto byte = [&bytes](v_buff_size i) -> v_uint64 {
    return static_cast<v_uint64>(bytes[i]);
  };

  v_uint64 timeLow  = (byte(0) << 24) | (byte(1) << 16) | (byte(2) << 8) | byte(3);
  v_uint64 timeMid  = (byte(4) << 8)  | byte(5);
  v_uint64 timeHi   = (byte(6) << 8)  | byte(7);
  v_uint64 clockSeq = (byte(8) << 8)  | byte(9);
  v_uint64 node     = (byte(10) << 40) | (byte(11) << 32) | (byte(12) << 24)
                    | (byte(13) << 16) | (byte(14) << 8)   | byte(15);

  /*
   * Lowercase, no braces, no urn prefix - the canonical form of RFC 4122 §4.1.2. snprintf is used
   * rather than a stream so that the result does not depend on any locale or on an iostream state
   * somebody else left behind.
   */
  char buffer[37];
  auto written = std::snprintf(
    buffer, sizeof(buffer),
    "%08llx-%04llx-%04llx-%04llx-%012llx",
    static_cast<unsigned long long>(timeLow),
    static_cast<unsigned long long>(timeMid),
    static_cast<unsigned long long>(timeHi),
    static_cast<unsigned long long>(clockSeq),
    static_cast<unsigned long long>(node)
  );

  if(written != 36) {
    /* Not "could not format": every field above is masked to its own width, so a wrong length here
     * means this function was changed and got it wrong. Fail rather than hand out a malformed
     * identifier. */
    throw std::runtime_error(
      "[oatpp::mcp::utils::Uuid::generateV4()]: Error - formatted UUID has an unexpected length."
    );
  }

  return oatpp::String(buffer, 36);
}

}}}
