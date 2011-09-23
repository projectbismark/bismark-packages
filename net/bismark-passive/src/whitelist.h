#ifndef _BISMARK_PASSIVE_WHITELIST_H_
#define _BISMARK_PASSIVE_WHITELIST_H_

typedef struct {
  char** domains;
  int size;
} domain_whitelist_t;

/* Initialize an empty whitelist. */
void domain_whitelist_init(domain_whitelist_t* whitelist);

/* Load a whitelist from file contents. You should call this function at most
 * once per whitelist, otherwise old list contents will be leaked. */
int domain_whitelist_load(domain_whitelist_t* whitelist,
                          const char* const contents);

void domain_whitelist_destroy(const domain_whitelist_t* whitelist);

/* Look up a domain name in the whitelist. Return 0 if it matches and -1 if it
 * doesn't. Subdomain matching works as expected; for example, if foo.com is on
 * the whitelist, then both foo.com and www.foo.com will match, but not
 * barfoo.com or oo.com */
int domain_whitelist_lookup(const domain_whitelist_t* whitelist,
                            const char* const domain);

#endif
