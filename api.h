#ifndef API_H
#define API_H
char *check_abuseIPDB(const char *ip);
char *check_virustotal(const char *ip);
char *check_shodan(const char *ip);
char *check_ipinfo(const char *ip);
char *check_pulsedive(const char *ip);
char *check_alien_vault_otx(const char *ip);
char *check_ipqs(const char *ip);
#endif