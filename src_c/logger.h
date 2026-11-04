#ifndef LOGGER_H
#define LOGGER_H

#include "antigravity_proxy.h"

void logger_init(const char *log_path, int level);
void logger_close(void);
void logger_log(int level, const char *fmt, ...);

#define LOG_DEBUG(fmt, ...) logger_log(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  logger_log(LOG_LEVEL_INFO,  fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  logger_log(LOG_LEVEL_WARN,  fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) logger_log(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)

#endif /* LOGGER_H */
