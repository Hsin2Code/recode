#ifndef REGESITER_H_XXX
#define REGESITER_H_XXX

#include <string>

bool do_regesiter(const std::string &dev_id);

void report_assert();

void *heart_beat_worker(void *args);

#endif
