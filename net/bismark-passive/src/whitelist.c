#include "whitelist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int domain_whitelist_init(domain_whitelist_t* whitelist,
                          const char* orig_contents) {
  char* contents;

  contents = strdup(orig_contents);
  int num_lines = 0;
  char* ptr = contents;
  while (strtok(ptr, "\n") != NULL) {
    ++num_lines;
    ptr = NULL;
  }
  whitelist->size = num_lines;
  whitelist->domains = calloc(num_lines, sizeof(char*));
  free(contents);

  contents = strdup(orig_contents);
  ptr = contents;
  int idx;
  for (idx = 0; idx < num_lines; ++idx) {
    whitelist->domains[idx] = strdup(strtok(ptr, "\n"));
    if (!whitelist->domains[idx]) {
#ifndef NDEBUG
      perror("Error duplicating whitelist line");
#endif
      free(contents);
      return -1;
    }
    ptr = NULL;
  }
  free(contents);

  return 0;
}

void domain_whitelist_destroy(const domain_whitelist_t* whitelist) {
  int idx;
  for (idx = 0; idx < whitelist->size; ++idx) {
    free(whitelist->domains[idx]);
  }
  free(whitelist->domains);
}

int domain_whitelist_lookup(const domain_whitelist_t* whitelist,
                            const char* const domain) {
  int match_length = strlen(domain);
  int idx;
  for (idx = 0; idx < whitelist->size; ++idx) {
    int current_length = strlen(whitelist->domains[idx]);
    int domain_offset = match_length - current_length;
    if (domain_offset < 0) {
      continue;
    }
    if (strcmp(domain + domain_offset, whitelist->domains[idx]) == 0
        && (domain_offset == 0 || domain[domain_offset - 1] == '.')) {
        return 0;
    }
  }
  return -1;
}
