#include "logger.h"
#include <stdarg.h>
#include <time.h>

static FILE *s_log_fp = NULL;
static int s_log_level = LOG_LEVEL_INFO;
static pthread_mutex_t s_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool s_stderr_echo = false;

void logger_init(const char *log_path, int level) {
    pthread_mutex_lock(&s_log_mutex);
    s_log_level = level;
    if (getenv("ANTIGRAVITY_PROXY_DEBUG") != NULL || level == LOG_LEVEL_DEBUG) {
        s_stderr_echo = true;
    }

    if (log_path && log_path[0] != '\0') {
        if (s_log_fp) {
            fclose(s_log_fp);
        }
        s_log_fp = fopen(log_path, "a");
        if (s_log_fp) {
            setvbuf(s_log_fp, NULL, _IOLBF, 0); // Line buffered
        }
    }
    pthread_mutex_unlock(&s_log_mutex);
}

void logger_close(void) {
    pthread_mutex_lock(&s_log_mutex);
    if (s_log_fp) {
        fclose(s_log_fp);
        s_log_fp = NULL;
    }
    pthread_mutex_unlock(&s_log_mutex);
}

static const char* level_to_str(int level) {
    switch (level) {
        case LOG_LEVEL_DEBUG: return "调试";
        case LOG_LEVEL_INFO:  return "信息";
        case LOG_LEVEL_WARN:  return "警告";
        case LOG_LEVEL_ERROR: return "错误";
        default: return "未知";
    }
}

void logger_log(int level, const char *fmt, ...) {
    if (level < s_log_level) {
        return;
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm_buf;
    localtime_r(&tv.tv_sec, &tm_buf);

    char time_str[64];
    snprintf(time_str, sizeof(time_str), "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
             tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
             tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, tv.tv_usec / 1000);

    pthread_mutex_lock(&s_log_mutex);

    char msg_buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg_buf, sizeof(msg_buf), fmt, args);
    va_end(args);

    if (s_log_fp) {
        fprintf(s_log_fp, "[%s] [%s] [%s:%d] %s\n",
                time_str, level_to_str(level), g_process_name, getpid(), msg_buf);
        fflush(s_log_fp);
    }

    if (s_stderr_echo || s_log_fp == NULL) {
        fprintf(stderr, "[Antigravity-Proxy] [%s] [%s] [%s:%d] %s\n",
                time_str, level_to_str(level), g_process_name, getpid(), msg_buf);
    }

    pthread_mutex_unlock(&s_log_mutex);
}
