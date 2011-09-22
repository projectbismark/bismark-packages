#ifndef _BISMARK_PASSIVE_WHITELIST_H_
#define _BISMARK_PASSIVE_WHITELIST_H_

typedef struct {
  char** domains;
  int size;
} domain_whitelist_t;

int domain_whitelist_init(domain_whitelist_t* whitelist,
                          const char* const filename);

void domain_whitelist_destroy(const domain_whitelist_t* whitelist);

int domain_whitelist_lookup(const domain_whitelist_t* whitelist,
                            const char* const domain);

#endif
