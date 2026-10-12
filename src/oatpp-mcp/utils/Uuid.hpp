//
// Version-4 (random) UUIDs for identifiers that must not be guessable.
//
// See SECURITY-FINDINGS.md, finding F2.
//

#ifndef oatpp_mcp_utils_Uuid_hpp
#define oatpp_mcp_utils_Uuid_hpp

#include "oatpp/Types.hpp"

namespace oatpp { namespace mcp { namespace utils {

/**
 * Version-4 (random) UUIDs as specified by RFC 4122: 122 bits of randomness (128 minus the 6 bits
 * that encode the version and the variant), rendered in the canonical
 * <code>8-4-4-4-12</code> lowercase form.
 *
 * <h3>Why a type for this</h3>
 *
 * An identifier that is handed out to a client and then accepted as proof of "this session" is a
 * capability. Anything an attacker can predict or reproduce lets them use someone else's session,
 * so the generator has to be a documented, single, tested thing rather than whatever the local
 * scope had to hand.
 *
 * <h3>What this is not</h3>
 *
 * <ul>
 *   <li>not {@link oatpp::utils::Random} - that is <code>std::mt19937</code>, a Mersenne twister
 *       whose internal state is recoverable from a few dozen outputs, which makes it exactly the
 *       wrong tool for an identifier and a fine one for shuffling;</li>
 *   <li>not a UUID v1 - no timestamp, no node identity, nothing about the server leaks into the
 *       value;</li>
 *   <li>not a token - it carries no integrity protection and means nothing to anyone but the
 *       server that issued it.</li>
 * </ul>
 *
 * <h3>Failure</h3>
 *
 * If the platform entropy source cannot be opened, the exception from <code>std::random_device</code>
 * propagates. There is deliberately no fallback to a weaker generator: an identifier that is not
 * random is not merely lower quality, it is the vulnerability this class exists to fix, and failing
 * to create a session is recoverable while failing silently is not.
 */
class Uuid {
public:

  /**
   * Generate a new random (version 4) UUID.
   *
   * Safe to call from several threads at once.
   * @return 36 characters, lowercase, e.g. <code>"f47ac10b-58cc-4372-a567-0e02b2c3d479"</code>.
   * @throws std::exception if the platform entropy source is unavailable.
   */
  static oatpp::String generateV4();

};

}}}

#endif // oatpp_mcp_utils_Uuid_hpp
