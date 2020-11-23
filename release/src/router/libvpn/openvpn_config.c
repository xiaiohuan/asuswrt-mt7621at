#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "openvpn_config.h"
#include "bcmnvram.h"
#include "shared.h"
#include "shutils.h"

extern struct nvram_tuple router_defaults[];

ovpn_sconf_common_t* get_ovpn_sconf_common(ovpn_sconf_common_t* conf)
{
	char buf[32] = {0};
	char *cp;
	int unit;

	if(!conf)
		return NULL;

	memset(conf, 0, sizeof(ovpn_sconf_common_t));

	if( !nvram_match("VPNServer_enable", "1") )
		return conf;

	snprintf(buf, sizeof(buf), nvram_safe_get("vpn_serverx_eas"));
	for( cp = strtok(buf, ","); cp != NULL; cp = strtok(NULL, ",")) {
		unit = atoi(cp);
		if(unit > OVPN_SERVER_MAX || unit <=0)
			continue;
		conf->enable[unit-1] = 1;
	}

	snprintf(buf, sizeof(buf), nvram_safe_get("vpn_serverx_dns"));
	for( cp = strtok(buf, ","); cp != NULL; cp = strtok(NULL, ",")) {
		unit = atoi(cp);
		if(unit > OVPN_SERVER_MAX || unit <=0)
			continue;
		conf->dns[unit-1] = 1;
	}

	return conf;
}

ovpn_cconf_common_t* get_ovpn_cconf_common(ovpn_cconf_common_t* conf)
{
	char buf[32] = {0};
	char *cp;
	int unit;

	if(!conf)
		return NULL;

	memset(conf, 0, sizeof(ovpn_cconf_common_t));

	snprintf(buf, sizeof(buf), nvram_safe_get("vpn_clientx_eas"));
	for( cp = strtok(buf, ","); cp != NULL; cp = strtok(NULL, ",")) {
		unit = atoi(cp);
		if(unit > OVPN_CLIENT_MAX || unit <=0)
			continue;
		conf->enable[unit-1] = 1;
	}

	return conf;
}

ovpn_sconf_t* get_ovpn_sconf(int unit, ovpn_sconf_t* conf)
{
	char prefix[32] = {0};
	char value[4096] = {0};
	char *nvp, *b;
	char *enable, *name, *net, *mask, *push;
	int i = 0;

	if(!conf)
		return NULL;

	memset(conf, 0, sizeof(ovpn_sconf_t));

	conf->enable = nvram_get_int("VPNServer_enable");

	snprintf(prefix, sizeof(prefix), "vpn_server%d_", unit);

// Tunnel options
	snprintf(conf->proto, sizeof(conf->proto), nvram_pf_safe_get(prefix, "proto"));

	conf->port = nvram_pf_get_int(prefix, "port");

	snprintf(conf->if_name, sizeof(conf->if_name), "%s%d", nvram_pf_safe_get(prefix, "if"), OVPN_SERVER_BASE + unit);
	if(!strncmp(conf->if_name, "tun", 3))
		conf->if_type = OVPN_IF_TUN;
	else
		conf->if_type = OVPN_IF_TAP;

	snprintf(conf->local, sizeof(conf->local), nvram_pf_safe_get(prefix, "local"));

	snprintf(conf->remote, sizeof(conf->remote), nvram_pf_safe_get(prefix, "remote"));

	if( strlen(nvram_pf_safe_get(prefix, "verb")) )	//new config, if not apply setting again, length will be 0 
		conf->verb = nvram_pf_get_int(prefix, "verb");
	else	//old config
		conf->verb = nvram_get_int("vpn_loglevel");

	snprintf(conf->comp, sizeof(conf->comp), nvram_pf_safe_get(prefix, "comp"));

	if(nvram_pf_match(prefix, "crypt", "secret"))
		conf->auth_mode = OVPN_AUTH_STATIC;
	else
		conf->auth_mode = OVPN_AUTH_TLS;

	conf->useronly = nvram_pf_get_int(prefix, "igncrt");

//Server mode
	snprintf(conf->network, sizeof(conf->network), nvram_pf_safe_get(prefix, "sn"));

	snprintf(conf->netmask, sizeof(conf->netmask), nvram_pf_safe_get(prefix, "nm"));

	conf->dhcp = nvram_pf_get_int(prefix, "dhcp");

	snprintf(conf->pool_start, sizeof(conf->pool_start), nvram_pf_safe_get(prefix, "r1"));

	snprintf(conf->pool_end, sizeof(conf->pool_end), nvram_pf_safe_get(prefix, "r2"));

	conf->redirect_gateway = nvram_pf_get_int(prefix, "rgw");

	conf->push_lan = nvram_pf_get_int(prefix, "plan");

	conf->push_dns = nvram_pf_get_int(prefix, "pdns");

	conf->ccd = nvram_pf_get_int(prefix, "ccd");

	conf->c2c = nvram_pf_get_int(prefix, "c2c");

	conf->ccd_excl = nvram_pf_get_int(prefix, "ccd_excl");

	snprintf(value, sizeof(value), nvram_pf_safe_get(prefix, "ccd_val"));
	nvp = value;
	while ((b = strsep(&nvp, "<")) != NULL) {
		if ((vstrsep(b, ">", &enable, &name, &net, &mask, &push) != 5))
			continue;
		conf->ccd_info.ccd_val[i].enable = atoi(enable);
		snprintf(conf->ccd_info.ccd_val[i].name, sizeof(conf->ccd_info.ccd_val[i].name), name);
		snprintf(conf->ccd_info.ccd_val[i].network, sizeof(conf->ccd_info.ccd_val[i].network), net);
		snprintf(conf->ccd_info.ccd_val[i].netmask, sizeof(conf->ccd_info.ccd_val[i].netmask), mask);
		conf->ccd_info.ccd_val[i].push = atoi(push);
		conf->ccd_info.count++;
		i++;
	}

//Data Channel Encryption Options:
	conf->direction = nvram_pf_get_int(prefix, "hmac");

	snprintf(conf->digest, sizeof(conf->digest), nvram_pf_safe_get(prefix, "digest"));

	snprintf(conf->cipher, sizeof(conf->cipher), nvram_pf_safe_get(prefix, "cipher"));

//TLS Mode Options:
	conf->reneg = nvram_pf_get_int(prefix, "reneg");

	conf->tls_keysize = nvram_pf_get_int(prefix, "tls_keysize")?2048:1024;

//Router options
	snprintf(conf->firewall, sizeof(conf->firewall), nvram_pf_safe_get(prefix, "firewall"));

	conf->poll = nvram_pf_get_int(prefix, "poll");

	snprintf(conf->lan_ipaddr, sizeof(conf->lan_ipaddr), nvram_safe_get("lan_ipaddr"));

	snprintf(conf->lan_netmask, sizeof(conf->lan_netmask), nvram_safe_get("lan_netmask"));

//Final custom
	snprintf(conf->custom, sizeof(conf->custom), nvram_pf_safe_get(prefix, "custom"));

	return conf;
}

ovpn_cconf_t* get_ovpn_cconf(int unit, ovpn_cconf_t* conf)
{
	char prefix[32] = {0};

	if(!conf)
		return NULL;

	memset(conf, 0, sizeof(ovpn_cconf_t));

	snprintf(prefix, sizeof(prefix), "vpn_client%d_", unit);

	conf->enable = 1;

// Tunnel options
	snprintf(conf->addr, sizeof(conf->addr), nvram_pf_safe_get(prefix, "addr"));

	conf->retry = nvram_pf_get_int(prefix, "retry");

	snprintf(conf->proto, sizeof(conf->proto), nvram_pf_safe_get(prefix, "proto"));

	conf->port = nvram_pf_get_int(prefix, "port");

	snprintf(conf->if_name, sizeof(conf->if_name), "%s%d", nvram_pf_safe_get(prefix, "if"), OVPN_CLIENT_BASE + unit);
	if(!strncmp(conf->if_name, "tun", 3))
		conf->if_type = OVPN_IF_TUN;
	else
		conf->if_type = OVPN_IF_TAP;

	snprintf(conf->local, sizeof(conf->local), nvram_pf_safe_get(prefix, "local"));

	snprintf(conf->remote, sizeof(conf->remote), nvram_pf_safe_get(prefix, "remote"));

	snprintf(conf->netmask, sizeof(conf->netmask), nvram_pf_safe_get(prefix, "nm"));

	conf->redirect_gateway = nvram_pf_get_int(prefix, "rgw");

	snprintf(conf->gateway, sizeof(conf->gateway), nvram_pf_safe_get(prefix, "gw"));

	if( strlen(nvram_pf_safe_get(prefix, "verb")) )	//new config, if not apply setting again, length will be 0 
		conf->verb = nvram_pf_get_int(prefix, "verb");
	else	//old config
		conf->verb = nvram_get_int("vpn_loglevel");

	snprintf(conf->comp, sizeof(conf->comp), nvram_pf_safe_get(prefix, "comp"));

	if(nvram_pf_match(prefix, "crypt", "secret"))
		conf->auth_mode = OVPN_AUTH_STATIC;
	else
		conf->auth_mode = OVPN_AUTH_TLS;

	conf->userauth = nvram_pf_get_int(prefix, "userauth");

	conf->useronly = nvram_pf_get_int(prefix, "useronly");

	snprintf(conf->username, sizeof(conf->username), "%s", nvram_pf_safe_get(prefix, "username"));

	snprintf(conf->password, sizeof(conf->password), "%s", nvram_pf_safe_get(prefix, "password"));

//Data Channel Encryption Options:
	conf->direction = nvram_pf_get_int(prefix, "hmac");

	snprintf(conf->digest, sizeof(conf->digest), nvram_pf_safe_get(prefix, "digest"));

	snprintf(conf->cipher, sizeof(conf->cipher), nvram_pf_safe_get(prefix, "cipher"));

//TLS Mode Options:
	conf->reneg = nvram_pf_get_int(prefix, "reneg");

//Router options
	snprintf(conf->firewall, sizeof(conf->firewall), nvram_pf_safe_get(prefix, "firewall"));

	conf->poll = nvram_pf_get_int(prefix, "poll");

	conf->bridge = nvram_pf_get_int(prefix, "bridge");

	conf->nat = nvram_pf_get_int(prefix, "nat");

	//conf->adns = nvram_pf_get_int(prefix, "adns");
	conf->adns = 1;	//use dns from server directly.

//Final custom
	snprintf(conf->custom, sizeof(conf->custom), nvram_pf_safe_get(prefix, "custom"));

	return conf;
}

static char* _get_ovpn_key_attr(ovpn_key_t type, char* name, size_t len)
{
	switch(type) {
		case OVPN_CLIENT_STATIC:
		case OVPN_SERVER_STATIC:
			snprintf(name, len, "static");
			break;
		case OVPN_CLIENT_CA:
		case OVPN_SERVER_CA:
			snprintf(name, len, "ca");
			break;
		case OVPN_CLIENT_CERT:
		case OVPN_SERVER_CERT:
			snprintf(name, len, "crt");
			break;
		case OVPN_CLIENT_KEY:
		case OVPN_SERVER_KEY:
			snprintf(name, len, "key");
			break;
		case OVPN_CLIENT_CRL:
		case OVPN_SERVER_CRL:
			snprintf(name, len, "crl");
			break;
		case OVPN_SERVER_CA_KEY:
			snprintf(name, len, "ca_key");
			break;
		case OVPN_SERVER_DH:
			snprintf(name, len, "dh");
			break;
		case OVPN_SERVER_CLIENT_CERT:
			snprintf(name, len, "client_crt");
			break;
		case OVPN_SERVER_CLIENT_KEY:
			snprintf(name, len, "client_key");
			break;
		default:
			return NULL;
	}
	return name;
}

#if defined(RTCONFIG_JFFS2) || defined(RTCONFIG_BRCM_NAND_JFFS2) || defined(RTCONFIG_UBIFS)
static char* _get_ovpn_key_fpath(ovpn_key_t type, int unit, char* fpath, size_t len)
{
	switch(type) {
		case OVPN_CLIENT_STATIC:
			snprintf(fpath, len, "%s/vpn_crt_client%d_static", OVPN_DIR_SAVE, unit);
			break;
		case OVPN_SERVER_STATIC:
			snprintf(fpath, len, "%s/vpn_crt_server%d_static", OVPN_DIR_SAVE, unit);
			break;
		case OVPN_CLIENT_CA:
			snprintf(fpath, len, "%s/vpn_crt_client%d_ca", OVPN_DIR_SAVE, unit);
			break;
		case OVPN_SERVER_CA:
			snprintf(fpath, len, "%s/vpn_crt_server%d_ca", OVPN_DIR_SAVE, unit);
			break;
		case OVPN_CLIENT_CERT:
			snprintf(fpath, len, "%s/vpn_crt_client%d_crt", OVPN_DIR_SAVE, unit);
			break;
		case OVPN_SERVER_CERT:
			snprintf(fpath, len, "%s/vpn_crt_server%d_crt", OVPN_DIR_SAVE, unit);
			break;
		case OVPN_CLIENT_KEY:
			snprintf(fpath, len, "%s/vpn_crt_client%d_key", OVPN_DIR_SAVE, unit);
			break;
		case OVPN_SERVER_KEY:
			snprintf(fpath, len, "%s/vpn_crt_server%d_key", OVPN_DIR_SAVE, unit);
			break;
		case OVPN_CLIENT_CRL:
			snprintf(fpath, len, "%s/vpn_crt_client%d_crl", OVPN_DIR_SAVE, unit);
			break;
		case OVPN_SERVER_CRL:
			snprintf(fpath, len, "%s/vpn_crt_server%d_crl", OVPN_DIR_SAVE, unit);
			break;
		case OVPN_SERVER_CA_KEY:
			snprintf(fpath, len, "%s/vpn_crt_server%d_ca_key", OVPN_DIR_SAVE, unit);
			break;
		case OVPN_SERVER_DH:
			snprintf(fpath, len, "%s/vpn_crt_server%d_dh", OVPN_DIR_SAVE, unit);
			break;
		case OVPN_SERVER_CLIENT_CERT:
			snprintf(fpath, len, "%s/vpn_crt_server%d_client_crt", OVPN_DIR_SAVE, unit);
			break;
		case OVPN_SERVER_CLIENT_KEY:
			snprintf(fpath, len, "%s/vpn_crt_server%d_client_key", OVPN_DIR_SAVE, unit);
			break;
		default:
			return NULL;
	}
	return fpath;
}

static char* _get_ovpn_key_from_file(char* fpath, char* buf, size_t len)
{
	FILE *fp;
	char *p = buf;
	int n;

	fp = fopen(fpath, "r");
	if(fp) {
		while(fgets(buf, len, fp)) {
			if(!strncmp(buf, "-----BEGIN", 10))
				break;
		}
		if(feof(fp)) {	//no data
			memset(buf, 0, len);
			fclose(fp);
			return NULL;
		}
		else {
			p += strlen(buf);
			n = fread (p, 1, buf+len-p-1, fp);
			if(n > 0) {
				p += n;
				*p = '\0';
				fclose(fp);
				return buf;
			}
			else {
				memset(buf, 0, len);
				fclose(fp);
				return NULL;
			}
		}
	}
	return NULL;
}

static int _set_ovpn_key_to_file(char* buf, char* fpath)
{
	char *p;

	p = strstr(buf, "-----BEGIN");
	if(p) {
		return f_write_string(fpath, p, 0, 0600);
	}
	else {
		return -1;
	}
}
#endif

char* get_ovpn_key(ovpn_type_t type, int unit, ovpn_key_t key_type, char *buf, size_t len)
{
	char prefix[32] = {0};
	char attr[32] = {0};
	char fpath[128] = {0};
	int ret = -1;

	if(type == OVPN_TYPE_SERVER)
		snprintf(prefix, sizeof(prefix), "vpn_crt_server%d_", unit);
	else
		snprintf(prefix, sizeof(prefix), "vpn_crt_client%d_", unit);

	if(!_get_ovpn_key_attr(key_type, attr, sizeof(attr)))
		return NULL;

	memset(buf, 0, len);
	snprintf(buf, len, nvram_pf_safe_get(prefix, attr));

#if defined(RTCONFIG_JFFS2) || defined(RTCONFIG_BRCM_NAND_JFFS2) || defined(RTCONFIG_UBIFS)
	if(!d_exists(OVPN_DIR_SAVE))
		mkdir(OVPN_DIR_SAVE, S_IRWXU);

	if(!_get_ovpn_key_fpath(key_type, unit, fpath, sizeof(fpath)))
		return NULL;

	if(strlen(buf)) {
		//save to file, clear attr
		if(_set_ovpn_key_to_file(buf, fpath) < 0) {
			ret = -1;
		}
		else {
			nvram_pf_set(prefix, attr, "");
			ret = 0;
		}
	}
	else {
		//get from file
		if(_get_ovpn_key_from_file(fpath, buf, len)) {
			ret = 0;
		}
		else {
			ret = -1;
		}
	}
#endif

	if(ret < 0)
		return NULL;
	else
		return buf;
}

int set_ovpn_key(ovpn_type_t type, int unit, ovpn_key_t key_type, char *buf, char *path)
{
#if defined(RTCONFIG_JFFS2) || defined(RTCONFIG_BRCM_NAND_JFFS2) || defined(RTCONFIG_UBIFS)
	char target_path[256] = {0};

	if(!d_exists(OVPN_DIR_SAVE))
		mkdir(OVPN_DIR_SAVE, S_IRWXU);

	if(!_get_ovpn_key_fpath(key_type, unit, target_path, sizeof(target_path)))
		return -1;

	if(buf && strlen(buf))
		return _set_ovpn_key_to_file(buf, target_path);
	else if(path && f_exists(path))
		return eval("cp", path, target_path);
	else {	//clean
		return unlink(target_path);
	}
#else
	char prefix[32] = {0};
	char attr[32] = {0};
	char tmp_buf[4096] ={0};

	if(type == OVPN_TYPE_SERVER)
		snprintf(prefix, sizeof(prefix), "vpn_crt_server%d_", unit);
	else
		snprintf(prefix, sizeof(prefix), "vpn_crt_client%d_", unit);

	if(_get_ovpn_key_attr(key_type, attr, sizeof(attr)))
		return -1;

	if(buf && strlen(buf)) {
		p = strstr(buf, "-----BEGIN");
		if(p) {
			return nvram_pf_set(prefix, attr, buf);
		}
		else {
			return -1;
		}
	}
	else if(path && f_exists(path)) {
		if(_get_ovpn_key_from_file(path, tmp_buf, sizeof(tmp_buf)))
			return nvram_pf_set(prefix, attr, tmp_buf);
		else
			return -1;
	}
	else {	//clean
		return nvram_pf_set(prefix, attr, "");
	}
#endif
}

int ovpn_key_exists(ovpn_type_t type, int unit, ovpn_key_t key_type)
{
	char buf[4096] = {0};
	if(get_ovpn_key(type, unit, key_type, buf, sizeof(buf)))
		if(strlen(buf))
			return 1;
		else
			return 0;
	else
		return 0;
}

char* get_lan_cidr(char* buf, size_t len)
{
	uint32_t ip, mask;
	struct in_addr in;
	int count = 0;

	ip = (uint32_t)inet_addr(nvram_safe_get("lan_ipaddr"));
	mask = (uint32_t)inet_addr(nvram_safe_get("lan_netmask"));

	in.s_addr = ip & mask;

	mask = ntohl(mask);
	while(mask) {
		mask <<= 1;
		count++;
	}

	snprintf(buf, len, "%s/%d", inet_ntoa(in), count);

	return buf;
}

char* get_ovpn_sconf_remote(char* buf, size_t len)
{
	const char *address;

	if (nvram_get_int("ddns_enable_x") && nvram_get_int("ddns_status") && nvram_invmatch("ddns_hostname_x", ""))
		address = nvram_safe_get("ddns_hostname_x");
	else {
		address = (char *) get_wanip();
		if (inet_addr_(address) == INADDR_ANY)
			address = "0.0.0.0"; /* error */
	}

	snprintf(buf, len, address);
	return buf;
}

void update_ovpn_status(ovpn_type_t type, int unit, ovpn_status_t status_type)
{
	char prefix[32] = {0};

	if(type == OVPN_TYPE_SERVER)
		snprintf(prefix, sizeof(prefix), "vpn_server%d_", unit);
	else
		snprintf(prefix, sizeof(prefix), "vpn_client%d_", unit);

	switch(status_type) {
		case OVPN_STS_STOP:
			nvram_pf_set(prefix, "state", "0");
			nvram_pf_set(prefix, "errno", "0");
			break;
		case OVPN_STS_INIT:
			nvram_pf_set(prefix, "state", "1");
			nvram_pf_set(prefix, "errno", "0");
			break;
		case OVPN_STS_RUNNING:
			nvram_pf_set(prefix, "state", "2");
			nvram_pf_set(prefix, "errno", "0");
			break;
		case OVPN_STS_STOPPING:
			nvram_pf_set(prefix, "state", "3");
			nvram_pf_set(prefix, "errno", "0");
	}
}

void wait_time_sync(int max)
{
	while (!nvram_match("ntp_ready", "1") && max--)
		sleep(1);
}


ovpn_accnt_info_t* get_ovpn_accnt(ovpn_accnt_info_t *accnt_info) 
{
	char *nv, *nvp, *b;
	char *username, *password;
	int i = 0;
#ifdef RTCONFIG_NVRAM_ENCRYPT
	char dec_passwd[256];
#endif

	if(!accnt_info)
		return NULL;

	memset(accnt_info, 0, sizeof(ovpn_accnt_info_t));

	nvp = nv = strdup(nvram_safe_get("vpn_serverx_clientlist"));
	while(nv && (b = strsep(&nvp, "<")) != NULL){
		if(vstrsep(b, ">", &username, &password) != 2) continue;
		if(strlen(username) == 0 || strlen(password) == 0) continue;

#ifdef RTCONFIG_NVRAM_ENCRYPT
			memset(dec_passwd, 0, sizeof(dec_passwd));
			pw_dec(password, dec_passwd);
			password = dec_passwd;
#endif
		snprintf(accnt_info->account[i].username, sizeof(accnt_info->account[i].username),
			"%s", username);
		snprintf(accnt_info->account[i].password, sizeof(accnt_info->account[i].password),
			"%s", password);
		accnt_info->count++;
		if(++i >= OVPN_ACCNT_MAX)
			break;
	}
	free(nv);
	return accnt_info;
}

void reset_ovpn_setting(ovpn_type_t type, int unit)
{
	struct nvram_tuple *t;
	char prefix_df[32] = {0};
	char prefix_nv[32] = {0};

	if(type == OVPN_TYPE_SERVER) {
		snprintf(prefix_df, sizeof(prefix_df), "vpn_server_");
		snprintf(prefix_nv, sizeof(prefix_nv), "vpn_server%d_", unit);
	}
	else {
		snprintf(prefix_df, sizeof(prefix_df), "vpn_client_");
		snprintf(prefix_nv, sizeof(prefix_nv), "vpn_client%d_", unit);
		nvram_pf_set(prefix_nv, "username", "");
		nvram_pf_set(prefix_nv, "password", "");
	}

	for (t = router_defaults; t->name; t++) {
		if ( strlen(t->name) > strlen(prefix_df)
			&& !strncmp(t->name, prefix_df, strlen(prefix_df))
			&& !strstr(t->name, "unit")
		) {
			_dprintf("reset %s%s=%s\n", prefix_nv, t->name + strlen(prefix_df), t->value);
			nvram_pf_set(prefix_nv, t->name + strlen(prefix_df), t->value);
		}
	}

	if(type == OVPN_TYPE_SERVER) {
		set_ovpn_key(type, unit, OVPN_SERVER_CA, NULL, NULL);
		set_ovpn_key(type, unit, OVPN_SERVER_CA_KEY, NULL, NULL);
		set_ovpn_key(type, unit, OVPN_SERVER_CERT, NULL, NULL);
		set_ovpn_key(type, unit, OVPN_SERVER_KEY, NULL, NULL);
		set_ovpn_key(type, unit, OVPN_SERVER_STATIC, NULL, NULL);
		set_ovpn_key(type, unit, OVPN_SERVER_DH, NULL, NULL);
		set_ovpn_key(type, unit, OVPN_SERVER_CRL, NULL, NULL);
		set_ovpn_key(type, unit, OVPN_SERVER_CLIENT_CERT, NULL, NULL);
		set_ovpn_key(type, unit, OVPN_SERVER_CLIENT_KEY, NULL, NULL);
	}
	else {
		set_ovpn_key(type, unit, OVPN_CLIENT_CA, NULL, NULL);
		set_ovpn_key(type, unit, OVPN_CLIENT_CERT, NULL, NULL);
		set_ovpn_key(type, unit, OVPN_CLIENT_KEY, NULL, NULL);
		set_ovpn_key(type, unit, OVPN_CLIENT_STATIC, NULL, NULL);
		set_ovpn_key(type, unit, OVPN_CLIENT_CRL, NULL, NULL);
	}
}

char* adjust_smp_affinity(ovpn_type_t type, int unit)
{
	int model = get_model();

	switch(model)
	{
		default:
			return NULL;
	}

	return NULL;
}

int need_dnsmasq_serverfile()
{
#ifdef RTCONFIG_YANDEXDNS
	int yadns_mode = nvram_get_int("yadns_enable_x") ? nvram_get_int("yadns_mode") : YADNS_DISABLED;
	if (yadns_mode != YADNS_DISABLED)
		return 0;
#endif
	return 1;
}
