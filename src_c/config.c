#include "config.h"
#include "cJSON.h"
#include "logger.h"
#include <libgen.h>

static void set_defaults(app_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));

    cfg->log_level = LOG_LEVEL_INFO;
    cfg->traffic_logging = false;
    cfg->child_injection = true;
    cfg->child_injection_mode = INJECTION_MODE_FILTERED;

    strncpy(cfg->proxy.host, "127.0.0.1", sizeof(cfg->proxy.host) - 1);
    cfg->proxy.port = 7898;
    cfg->proxy.type = PROXY_TYPE_SOCKS5;

    cfg->fake_ip.enabled = true;
    strncpy(cfg->fake_ip.cidr, "198.18.0.0/15", sizeof(cfg->fake_ip.cidr) - 1);

    cfg->timeout.connect_ms = 5000;
    cfg->timeout.send_ms = 5000;
    cfg->timeout.recv_ms = 5000;

    cfg->rules.allowed_ports[0] = 80;
    cfg->rules.allowed_ports[1] = 443;
    cfg->rules.allowed_ports_count = 2;

    strncpy(cfg->rules.dns_mode, "direct", sizeof(cfg->rules.dns_mode) - 1);
    strncpy(cfg->rules.ipv6_mode, "proxy", sizeof(cfg->rules.ipv6_mode) - 1);
    strncpy(cfg->rules.udp_mode, "auto", sizeof(cfg->rules.udp_mode) - 1);
    strncpy(cfg->rules.udp_fallback, "block", sizeof(cfg->rules.udp_fallback) - 1);
    cfg->rules.routing_enabled = true;
    cfg->rules.use_default_private = true;
    strncpy(cfg->rules.default_action, "proxy", sizeof(cfg->rules.default_action) - 1);

    strncpy(cfg->log_file_path, "proxy.log", sizeof(cfg->log_file_path) - 1);
}

static char* find_config_file(app_config_t *cfg) {
    // 1. ANTIGRAVITY_PROXY_CONFIG
    const char *env_cfg = getenv("ANTIGRAVITY_PROXY_CONFIG");
    if (env_cfg && access(env_cfg, R_OK) == 0) {
        strncpy(cfg->config_file_path, env_cfg, sizeof(cfg->config_file_path) - 1);
        return cfg->config_file_path;
    }

    // 2. Current directory ./config.json
    if (access("config.json", R_OK) == 0) {
        strncpy(cfg->config_file_path, "config.json", sizeof(cfg->config_file_path) - 1);
        return cfg->config_file_path;
    }

    // 3. Next to libantigravity_proxy.so
    Dl_info info;
    if (dladdr((void*)config_load, &info) && info.dli_fname) {
        char path_buf[512];
        strncpy(path_buf, info.dli_fname, sizeof(path_buf) - 1);
        path_buf[sizeof(path_buf) - 1] = '\0';
        char *dir = dirname(path_buf);
        char test_path[512];
        snprintf(test_path, sizeof(test_path), "%s/config.json", dir);
        if (access(test_path, R_OK) == 0) {
            strncpy(cfg->config_file_path, test_path, sizeof(cfg->config_file_path) - 1);
            return cfg->config_file_path;
        }
    }

    // 4. ~/.config/antigravity-proxy/config.json
    const char *home = getenv("HOME");
    if (home) {
        char test_path[512];
        snprintf(test_path, sizeof(test_path), "%s/.config/antigravity-proxy/config.json", home);
        if (access(test_path, R_OK) == 0) {
            strncpy(cfg->config_file_path, test_path, sizeof(cfg->config_file_path) - 1);
            return cfg->config_file_path;
        }
    }

    // 5. /etc/antigravity-proxy/config.json
    if (access("/etc/antigravity-proxy/config.json", R_OK) == 0) {
        strncpy(cfg->config_file_path, "/etc/antigravity-proxy/config.json", sizeof(cfg->config_file_path) - 1);
        return cfg->config_file_path;
    }

    return NULL;
}

int config_load(app_config_t *cfg) {
    set_defaults(cfg);

    char *cfg_path = find_config_file(cfg);
    if (!cfg_path) {
        // Fallback default
        return 0;
    }

    FILE *fp = fopen(cfg_path, "rb");
    if (!fp) {
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (sz <= 0 || sz > 1024 * 1024) {
        fclose(fp);
        return 0;
    }

    char *json_data = (char*)malloc(sz + 1);
    if (!json_data) {
        fclose(fp);
        return 0;
    }

    size_t read_bytes = fread(json_data, 1, sz, fp);
    fclose(fp);
    json_data[read_bytes] = '\0';

    cJSON *root = cJSON_Parse(json_data);
    free(json_data);

    if (!root) {
        return 0;
    }

    // log_level
    cJSON *j_level = cJSON_GetObjectItemCaseSensitive(root, "log_level");
    if (cJSON_IsString(j_level) && j_level->valuestring) {
        if (strcasecmp(j_level->valuestring, "debug") == 0) cfg->log_level = LOG_LEVEL_DEBUG;
        else if (strcasecmp(j_level->valuestring, "info") == 0) cfg->log_level = LOG_LEVEL_INFO;
        else if (strcasecmp(j_level->valuestring, "warn") == 0) cfg->log_level = LOG_LEVEL_WARN;
        else if (strcasecmp(j_level->valuestring, "error") == 0) cfg->log_level = LOG_LEVEL_ERROR;
    }

    // traffic_logging
    cJSON *j_traffic = cJSON_GetObjectItemCaseSensitive(root, "traffic_logging");
    if (cJSON_IsBool(j_traffic)) {
        cfg->traffic_logging = cJSON_IsTrue(j_traffic);
    }

    // child_injection & child_injection_mode
    cJSON *j_ci = cJSON_GetObjectItemCaseSensitive(root, "child_injection");
    if (cJSON_IsBool(j_ci)) {
        cfg->child_injection = cJSON_IsTrue(j_ci);
    }
    cJSON *j_cimode = cJSON_GetObjectItemCaseSensitive(root, "child_injection_mode");
    if (cJSON_IsString(j_cimode) && j_cimode->valuestring) {
        if (strcasecmp(j_cimode->valuestring, "inherit") == 0) {
            cfg->child_injection_mode = INJECTION_MODE_INHERIT;
        } else {
            cfg->child_injection_mode = INJECTION_MODE_FILTERED;
        }
    }

    // target_processes
    cJSON *j_targets = cJSON_GetObjectItemCaseSensitive(root, "target_processes");
    if (cJSON_IsArray(j_targets)) {
        int cnt = cJSON_GetArraySize(j_targets);
        if (cnt > 0) {
            cfg->target_processes = (char**)calloc(cnt, sizeof(char*));
            cfg->target_processes_count = 0;
            for (int i = 0; i < cnt; i++) {
                cJSON *item = cJSON_GetArrayItem(j_targets, i);
                if (cJSON_IsString(item) && item->valuestring) {
                    cfg->target_processes[cfg->target_processes_count++] = strdup(item->valuestring);
                }
            }
        }
    }

    // child_injection_exclude
    cJSON *j_exclude = cJSON_GetObjectItemCaseSensitive(root, "child_injection_exclude");
    if (cJSON_IsArray(j_exclude)) {
        int cnt = cJSON_GetArraySize(j_exclude);
        if (cnt > 0) {
            cfg->child_injection_exclude = (char**)calloc(cnt, sizeof(char*));
            cfg->child_injection_exclude_count = 0;
            for (int i = 0; i < cnt; i++) {
                cJSON *item = cJSON_GetArrayItem(j_exclude, i);
                if (cJSON_IsString(item) && item->valuestring) {
                    cfg->child_injection_exclude[cfg->child_injection_exclude_count++] = strdup(item->valuestring);
                }
            }
        }
    }

    // proxy
    cJSON *j_proxy = cJSON_GetObjectItemCaseSensitive(root, "proxy");
    if (cJSON_IsObject(j_proxy)) {
        cJSON *j_host = cJSON_GetObjectItemCaseSensitive(j_proxy, "host");
        if (cJSON_IsString(j_host) && j_host->valuestring) {
            strncpy(cfg->proxy.host, j_host->valuestring, sizeof(cfg->proxy.host) - 1);
        }
        cJSON *j_port = cJSON_GetObjectItemCaseSensitive(j_proxy, "port");
        if (cJSON_IsNumber(j_port)) {
            cfg->proxy.port = (uint16_t)j_port->valueint;
        }
        cJSON *j_type = cJSON_GetObjectItemCaseSensitive(j_proxy, "type");
        if (cJSON_IsString(j_type) && j_type->valuestring) {
            if (strcasecmp(j_type->valuestring, "http") == 0) {
                cfg->proxy.type = PROXY_TYPE_HTTP;
            } else {
                cfg->proxy.type = PROXY_TYPE_SOCKS5;
            }
        }
    }

    // fake_ip
    cJSON *j_fakeip = cJSON_GetObjectItemCaseSensitive(root, "fake_ip");
    if (cJSON_IsObject(j_fakeip)) {
        cJSON *j_f_en = cJSON_GetObjectItemCaseSensitive(j_fakeip, "enabled");
        if (cJSON_IsBool(j_f_en)) {
            cfg->fake_ip.enabled = cJSON_IsTrue(j_f_en);
        }
        cJSON *j_cidr = cJSON_GetObjectItemCaseSensitive(j_fakeip, "cidr");
        if (cJSON_IsString(j_cidr) && j_cidr->valuestring) {
            strncpy(cfg->fake_ip.cidr, j_cidr->valuestring, sizeof(cfg->fake_ip.cidr) - 1);
        }
    }

    // timeout
    cJSON *j_timeout = cJSON_GetObjectItemCaseSensitive(root, "timeout");
    if (cJSON_IsObject(j_timeout)) {
        cJSON *c = cJSON_GetObjectItemCaseSensitive(j_timeout, "connect");
        if (cJSON_IsNumber(c)) cfg->timeout.connect_ms = c->valueint;
        cJSON *s = cJSON_GetObjectItemCaseSensitive(j_timeout, "send");
        if (cJSON_IsNumber(s)) cfg->timeout.send_ms = s->valueint;
        cJSON *r = cJSON_GetObjectItemCaseSensitive(j_timeout, "recv");
        if (cJSON_IsNumber(r)) cfg->timeout.recv_ms = r->valueint;
    }

    // proxy_rules
    cJSON *j_rules = cJSON_GetObjectItemCaseSensitive(root, "proxy_rules");
    if (cJSON_IsObject(j_rules)) {
        cJSON *j_ports = cJSON_GetObjectItemCaseSensitive(j_rules, "allowed_ports");
        if (cJSON_IsArray(j_ports)) {
            cfg->rules.allowed_ports_count = 0;
            int pcnt = cJSON_GetArraySize(j_ports);
            for (int i = 0; i < pcnt && i < 32; i++) {
                cJSON *p = cJSON_GetArrayItem(j_ports, i);
                if (cJSON_IsNumber(p)) {
                    cfg->rules.allowed_ports[cfg->rules.allowed_ports_count++] = p->valueint;
                }
            }
        }
        cJSON *j_routing = cJSON_GetObjectItemCaseSensitive(j_rules, "routing");
        if (cJSON_IsObject(j_routing)) {
            cJSON *j_priv = cJSON_GetObjectItemCaseSensitive(j_routing, "use_default_private");
            if (cJSON_IsBool(j_priv)) {
                cfg->rules.use_default_private = cJSON_IsTrue(j_priv);
            }
        }
    }

    cJSON_Delete(root);
    return 1;
}

void config_free(app_config_t *cfg) {
    if (cfg->target_processes) {
        for (int i = 0; i < cfg->target_processes_count; i++) {
            free(cfg->target_processes[i]);
        }
        free(cfg->target_processes);
        cfg->target_processes = NULL;
        cfg->target_processes_count = 0;
    }
    if (cfg->child_injection_exclude) {
        for (int i = 0; i < cfg->child_injection_exclude_count; i++) {
            free(cfg->child_injection_exclude[i]);
        }
        free(cfg->child_injection_exclude);
        cfg->child_injection_exclude = NULL;
        cfg->child_injection_exclude_count = 0;
    }
}
