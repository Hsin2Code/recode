#ifndef PULL_POLICY_XXX
#define PULL_POLICY_XXX

#include <pthread.h>
void *pull_policy_worker(void *args);
extern pthread_t *g_running_file_tid_ptr;
extern int policy_pull_success_times;
extern int policy_pull_falied_times;

#endif

