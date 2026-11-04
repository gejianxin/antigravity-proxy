#ifndef CONFIG_H
#define CONFIG_H

#include "antigravity_proxy.h"

int config_load(app_config_t *cfg);
void config_free(app_config_t *cfg);

#endif /* CONFIG_H */
