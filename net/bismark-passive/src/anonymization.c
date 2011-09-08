#include "anonymization.h"

#ifndef NDEBUG
#include <assert.h>
#endif
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "constants.h"
#include "util.h"

static uint8_t seed[ANONYMIZATION_SEED_LEN];
static EVP_MD_CTX digest_context;
static char seed_hex_digest[SHA_DIGEST_LENGTH * 2 + 1];
#ifndef NDEBUG
static int initialized = 0;
#endif

static int init_hex_seed_digest() {
  unsigned char seed_digest[SHA_DIGEST_LENGTH];
  if (anonymization_process(seed, ANONYMIZATION_SEED_LEN, seed_digest)) {
    return -1;
  }

  const char* hex_digest = buffer_to_hex(seed_digest, SHA_DIGEST_LENGTH);
  if (!hex_digest) {
    return -1;
  }

  int idx;
  for (idx = 0; idx < SHA_DIGEST_LENGTH; ++idx) {
    if (sprintf(seed_hex_digest + 2 * idx, "%02x", seed_digest[idx]) < 2) {
#ifndef NDEBUG
      perror("Error writing update");
#endif
      return -1;
    }
  }
  seed_hex_digest[SHA_DIGEST_LENGTH * 2] = '\0';
  return 0;
}

int anonymization_init() {
  FILE* handle = fopen(ANONYMIZATION_SEED_FILE, "rb");
  if (!handle) {
    FILE* handle = fopen(ANONYMIZATION_SEED_FILE, "wb");
    if (!handle) {
#ifndef NDEBUG
      perror("Error opening seed file");
#endif
      return -1;
    }
    if (!RAND_bytes(seed, ANONYMIZATION_SEED_LEN)) {
#ifndef NDEBUG
      fprintf(stderr, "Error generating new seed");
#endif
      return -1;
    }
    if (fwrite(seed, 1, ANONYMIZATION_SEED_LEN, handle)
        < ANONYMIZATION_SEED_LEN) {
#ifndef NDEBUG
      perror("Error writing seed file");
#endif
      return -1;
    }
    fclose(handle);
  } else {
    if (fread(seed, 1, ANONYMIZATION_SEED_LEN, handle)
        < ANONYMIZATION_SEED_LEN) {
#ifndef NDEBUG
      perror("Error reading seed file");
#endif
      return -1;
    }
    fclose(handle);
  }

  EVP_MD_CTX_init(&digest_context);

#ifndef NDEBUG
  initialized = 1;
#endif

  if (init_hex_seed_digest()) {
#ifndef NDEBUG
    initialized = 0;
#endif
    return -1;
  }

  return 0;
}

int anonymization_process(const uint8_t* const data,
                          const int len,
                          unsigned char* const digest) {
  assert(initialized);

  if (!EVP_DigestInit_ex(&digest_context, EVP_sha1(), NULL)) {
    return -1;
  }
  if (!EVP_DigestUpdate(&digest_context, seed, ANONYMIZATION_SEED_LEN)) {
    return -1;
  }
  if (!EVP_DigestUpdate(&digest_context, data, len)) {
    return -1;
  }
  if (!EVP_DigestFinal_ex(&digest_context, digest, NULL)) {
    return -1;
  }
  return 0;
}

inline int anonymize_ip(uint32_t address, uint64_t* digest) {
  unsigned char address_digest[ANONYMIZATION_DIGEST_LENGTH];
  if (anonymization_process((unsigned char*)&address,
                            sizeof(address),
                            address_digest)) {
    return -1;
  }
  *digest = *(uint64_t*)address_digest;
  return 0;
}

inline int anonymize_domain(const char* domain, unsigned char* digest) {
  return anonymization_process((unsigned char*)domain, strlen(domain), digest);
}

#define MAC_UPPER_MASK 0xffffff000000
#define MAC_LOWER_MASK 0x000000ffffff

inline int anonymize_mac(uint8_t mac[ETH_ALEN], uint8_t digest[ETH_ALEN]) {
  unsigned char mac_digest[ANONYMIZATION_DIGEST_LENGTH];
  if (anonymization_process(mac, ETH_ALEN, mac_digest)) {
    return -1;
  }
  memcpy(digest, mac_digest, ETH_ALEN);
  memcpy(digest, mac, ETH_ALEN / 2);
  return 0;
}

int anonymization_write_update(gzFile handle) {
  if (!gzprintf(handle, "%s\n\n", seed_hex_digest)) {
#ifndef NDEBUG
    perror("Error writing update");
#endif
    return -1;
  }
  return 0;
}
