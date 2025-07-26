#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


/**
 * The maximum length of the password that can be used to create an HMAC state using the `Self::new_short` method
 */
#define Pbkdf2HmacSha256State_MAX_SHORT_PASSWORD_LEN (64 - 9)

/**
 * API constants for invalid buffer alignments.
 */
#define SCRYPT_OPT_INVALID_BUFFER_ALIGNMENT -3

/**
 * API constants for invalid buffer sizes.
 */
#define SCRYPT_OPT_INVALID_BUFFER_SIZE -2

/**
 * API constants for unsupported parameters.
 */
#define SCRYPT_OPT_UNSUPPORTED_PARAM_SPACE -1

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * C export for scrypt_kdf using a libscrypt-kdf compatible API.
 */
int scrypt_kdf(const uint8_t *password,
               size_t password_len,
               const uint8_t *salt,
               size_t salt_len,
               uint64_t n,
               uint32_t r,
               uint32_t p,
               uint8_t *output,
               size_t output_len);

/**
 * C export for scrypt_kdf using a libscrypt-kdf compatible API except input is taken as a cost factor.
 */
int scrypt_kdf_cf(const uint8_t *password,
                  size_t password_len,
                  const uint8_t *salt,
                  size_t salt_len,
                  uint8_t log2_n,
                  uint32_t r,
                  uint32_t p,
                  uint8_t *output,
                  size_t output_len);

/**
 * C export for scrypt_ro_mix.
 *
 * Parameters:
 * - `front_buffer`: In. Pointer to the buffer to perform the RoMix_front operation on. Can be null.
 * - `back_buffer`: In. Pointer to the buffer to perform the RoMix_back operation on. Can be null. Cannot be an alias of the front buffer.
 * - `salt_output`: Out. Pointer to receive a pointer to the raw salt that corresponds to the back buffer. Can be null.
 * - `r`: In. R value.
 * - `cf`: In. Cost factor.
 * - `minimum_buffer_size`: In. The smaller of the two buffer sizes.
 *
 * Returns:
 * - 0 on success.
 * - `SCRYPT_OPT_INVALID_BUFFER_SIZE` if the parameters are invalid.
 * - `SCRYPT_OPT_INVALID_BUFFER_ALIGNMENT` if the buffers are not 64-byte aligned.
 * - `SCRYPT_OPT_UNSUPPORTED_PARAM_SPACE` if the parameters are unsupported.
 */
int scrypt_ro_mix(uint8_t *front_buffer,
                  uint8_t *back_buffer,
                  const uint8_t **salt_output,
                  uint32_t r,
                  uint8_t cf,
                  size_t minimum_buffer_size);

/**
 * Compute the minimum buffer length in bytes to allocate for [`scrypt_ro_mix`].
 *
 * Returns 0 if the parameters are invalid or unsupported.
 *
 * ```c
 * #include <stdlib.h>
 *
 * extern size_t scrypt_ro_mix_minimum_buffer_len(unsigned int r, unsigned int cf);
 *
 * int main() {
 *     int minimum_buffer_len = scrypt_ro_mix_minimum_buffer_len(1, 1);
 *     printf("Minimum buffer length: %d\n", minimum_buffer_len);
 *     if (!minimum_buffer_len) {
 *         return 1;
 *     }
 *     void* alloc = aligned_alloc(64, minimum_buffer_len);
 *     if (alloc == NULL) {
 *         return 2;
 *     }
 *     scrypt_ro_mix(alloc, alloc, r, cf, minimum_buffer_len);
 *     return 0;
 * }
 * ```
 */
size_t scrypt_ro_mix_minimum_buffer_len(unsigned int r, unsigned int cf);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
