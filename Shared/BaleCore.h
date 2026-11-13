#ifndef BALE_CORE_H
#define BALE_CORE_H
#include <stdbool.h>
#include <stdint.h>
#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>

typedef void (*BaleStateCallback)(uint64_t session, int32_t state, uint16_t port, int32_t error_number);

char *bale_request_code(const char *phone);
char *bale_verify_code(const char *transaction, const char *code);
void bale_free_string(char *result);
bool bale_validate_tls_profile(const char *profile);

uint64_t bale_start_socks(const char *token, const char *peer, uint16_t port,
                          bool allow_port_fallback, const char *tls_profile, BaleStateCallback state);
void bale_stop(uint64_t session);

bool flow_validate_profile(const char *profile);
uint64_t flow_start(const char *profile, uint16_t port, bool allow_port_fallback, BaleStateCallback state);
void flow_stop(uint64_t session);

bool cloudflare_validate(const char *profile);
uint64_t cloudflare_start(const char *profile, uint16_t port, bool allow_port_fallback, BaleStateCallback state);
typedef void (*CloudflareScanCallback)(uint64_t scan, const char *json);
uint64_t cloudflare_scan_start(const char *profile, const char *seeds, const char *custom, bool deep, CloudflareScanCallback callback);
void cloudflare_scan_stop(uint64_t scan);
char *cloudflare_targets_check(const char *list);
char *cloudflare_link_for_ip(const char *profile, const char *ip, const char *custom);
void cloudflare_free(char *value);

bool dnstt_validate(const char *profile);
bool dnstt_validate_resolvers(const char *addresses);
char *dnstt_normalize_resolvers(const char *addresses);
char *dnstt_reference_resolvers(const char *addresses);
uint64_t dnstt_start(const char *profile, const char *addresses, uint16_t timeout, uint16_t port,
                     bool allow_port_fallback, BaleStateCallback callback);
uint64_t dnstt_scan_start(const char *profile, const char *addresses, uint16_t timeout, bool deep, CloudflareScanCallback callback);
void dnstt_scan_stop(uint64_t scan);

static inline void bale_system_resolvers(char *buffer, size_t capacity) {
    if (!capacity) return;
    buffer[0] = 0;
    struct __res_state state = {0};
    if (res_ninit(&state) != 0) return;
    union res_sockaddr_union addresses[8];
    int count = res_getservers(&state, addresses, 8);
    for (int i = 0; i < count && i < 8; i++) {
        const struct sockaddr *address = (const struct sockaddr *)&addresses[i];
        if (address->sa_family != AF_INET && address->sa_family != AF_INET6) continue;
        char host[NI_MAXHOST], service[NI_MAXSERV], endpoint[NI_MAXHOST + NI_MAXSERV + 5];
        if (getnameinfo(address, address->sa_len, host, sizeof(host), service, sizeof(service),
                        NI_NUMERICHOST | NI_NUMERICSERV) != 0) continue;
        snprintf(endpoint, sizeof(endpoint), address->sa_family == AF_INET6 ? "[%s]:%s" : "%s:%s", host, service);
        if (buffer[0]) strlcat(buffer, ",", capacity);
        strlcat(buffer, endpoint, capacity);
    }
    res_ndestroy(&state);
}

#endif
