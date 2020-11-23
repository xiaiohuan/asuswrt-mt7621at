#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <signal.h>
#include <crypt.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <shared.h>
#include <shutils.h>

#include "openvpn_config.h"

#define BUF_SIZE 10000

#define PUSH_LAN_METRIC 500

#define OVPN_DIR_CONF	"/etc/openvpn"
#define OVPN_DIR_TMP	"/tmp/openvpn"
#define OVPN_DEFAULT_DH	"/rom/dh2048.pem"
#define OVPN_PRG_OPENVPN	"/usr/sbin/openvpn"
#define OVPN_PRG_OPENSSL	"/usr/sbin/openssl"
#define OVPN_PRG_OPENSSL_CONF	"/rom/easy-rsa/openssl-1.0.0.cnf"
#define OVPN_PRG_PKITOOL	"/rom/easy-rsa/pkitool"
#define OVPN_PRG_CROND_CRU	"/usr/sbin/cru"
#define OVPN_LIB_PAM	"/usr/lib/openvpn-plugin-auth-pam.so"
#define OVPN_RETRY_MIN	1

static int _ovpn_is_running(ovpn_type_t type, int unit)
{
	char name[16];

	if(type == OVPN_TYPE_CLIENT)
		snprintf(name, sizeof(name), "vpnclient%d", unit);
	else if(type == OVPN_TYPE_SERVER)
		snprintf(name, sizeof(name), "vpnserver%d", unit);

	if( pidof(name) > 0 ) {
		return 1;
	}
	else {
		return 0;
	}
}

static void _ovpn_check_dir(ovpn_type_t type, int unit)
{
	char path[128];

	if(!d_exists(OVPN_DIR_CONF)) {
		mkdir(OVPN_DIR_CONF, 0700);
	}

	if(type == OVPN_TYPE_CLIENT)
		snprintf(path, sizeof(path), "%s/client%d", OVPN_DIR_CONF, unit);
	else if(type == OVPN_TYPE_SERVER)
		snprintf(path, sizeof(path), "%s/server%d", OVPN_DIR_CONF, unit);
	if(!d_exists(path)) {
		mkdir(path, 0700);
	}

	// Make sure symbolic link exists
	if(type == OVPN_TYPE_CLIENT)
		snprintf(path, sizeof(path), "%s/vpnclient%d", OVPN_DIR_CONF, unit);
	else if(type == OVPN_TYPE_SERVER)
		snprintf(path, sizeof(path), "%s/vpnserver%d", OVPN_DIR_CONF, unit);
	unlink(path);
	symlink(OVPN_PRG_OPENVPN, path);
}

static void _ovpn_tunnel_create(ovpn_if_t if_type, char* if_name)
{
	char buf[128];

	eval(OVPN_PRG_OPENVPN, "--mktun", "--dev", if_name);

	snprintf(buf, sizeof(buf), "/sys/class/net/%s/ifindex", if_name);
	f_wait_exists(buf, 3);

	if( if_type == OVPN_IF_TAP ) {
		eval("brctl", "addif", "br0", if_name);
	}

	eval("ifconfig", if_name, "up", "promisc");
}

static void _ovpn_tunnel_remove(ovpn_type_t type, int unit)
{
	char buf[128];
	char if_name[8];

	if(type == OVPN_TYPE_CLIENT)
		snprintf(if_name, sizeof(if_name), "tun%d", OVPN_CLIENT_BASE + unit);
	else
		snprintf(if_name, sizeof(if_name), "tun%d", OVPN_SERVER_BASE + unit);

	snprintf(buf, sizeof(buf), "/sys/class/net/%s", if_name);
	if(d_exists(buf)) {
		eval("ifconfig", if_name, "down");
		eval(OVPN_PRG_OPENVPN, "--rmtun", "--dev", if_name);
	}

	sleep(1);

	if(type == OVPN_TYPE_CLIENT)
		snprintf(if_name, sizeof(if_name), "tap%d", OVPN_CLIENT_BASE + unit);
	else
		snprintf(if_name, sizeof(if_name), "tap%d", OVPN_SERVER_BASE + unit);

	snprintf(buf, sizeof(buf), "/sys/class/net/%s", if_name);
	if(d_exists(buf)) {
		eval("ifconfig", if_name, "down");
		eval("brctl", "delif", "br0", if_name);
		eval(OVPN_PRG_OPENVPN, "--rmtun", "--dev", if_name);
	}
}

static int _ovpn_client_write_keys(int unit, ovpn_cconf_t *conf)
{
	FILE *fp;
	char fpath[128];
	char buf[BUF_SIZE];

	//TLS
	if(conf->auth_mode == OVPN_AUTH_TLS) {
		if(get_ovpn_key(OVPN_TYPE_CLIENT, unit, OVPN_CLIENT_CA, buf, sizeof(buf))) {
			snprintf(fpath, sizeof(fpath), "%s/client%d/ca.crt", OVPN_DIR_CONF, unit);
			fp = fopen(fpath, "w");
			if(fp) {
				fputs(buf, fp);
				fclose(fp);
				chmod(fpath, S_IRUSR|S_IWUSR);
			}
			else
				return -1;
		}
		else
			return -1;

		if (!conf->useronly) {
			if(get_ovpn_key(OVPN_TYPE_CLIENT, unit, OVPN_CLIENT_KEY, buf, sizeof(buf))) {
				snprintf(fpath, sizeof(fpath), "%s/client%d/client.key", OVPN_DIR_CONF, unit);
				fp = fopen(fpath, "w");
				if(fp) {
					fputs(buf, fp);
					fclose(fp);
					chmod(fpath, S_IRUSR|S_IWUSR);
				}
				else
					return -2;
			}
			else
				return -2;

			if(get_ovpn_key(OVPN_TYPE_CLIENT, unit, OVPN_CLIENT_CERT, buf, sizeof(buf))) {
				snprintf(fpath, sizeof(fpath), "%s/client%d/client.crt", OVPN_DIR_CONF, unit);
				fp = fopen(fpath, "w");
				if(fp) {
					fputs(buf, fp);
					fclose(fp);
					chmod(fpath, S_IRUSR|S_IWUSR);
				}
				else
					return -3;
			}
			else
				return -3;
		}

		if(get_ovpn_key(OVPN_TYPE_CLIENT, unit, OVPN_CLIENT_CRL, buf, sizeof(buf))) {
			snprintf(fpath, sizeof(fpath), "%s/client%d/crl.pem", OVPN_DIR_CONF, unit);
			fp = fopen(fpath, "w");
			if(fp) {
				fputs(buf, fp);
				fclose(fp);
				chmod(fpath, S_IRUSR|S_IWUSR);
			}
			else
				return -4;
		}

		if (conf->userauth) {
			snprintf(fpath, sizeof(fpath), "%s/client%d/up", OVPN_DIR_CONF, unit);
			fp = fopen(fpath, "w");
			if(fp) {
				fprintf(fp, "%s\n%s\n", conf->username, conf->password);
				fclose(fp);
				chmod(fpath, S_IRUSR|S_IWUSR);
			}
			else
				return -5;
		}
	}

	//static key
	if ( conf->auth_mode == OVPN_AUTH_STATIC
		|| (conf->auth_mode == OVPN_AUTH_TLS && conf->direction >= 0)
	) {
		if(get_ovpn_key(OVPN_TYPE_CLIENT, unit, OVPN_CLIENT_STATIC, buf, sizeof(buf))) {
			snprintf(fpath, sizeof(fpath), "%s/client%d/static.key", OVPN_DIR_CONF, unit);
			fp = fopen(fpath, "w");
			if(fp) {
				fputs(buf, fp);
				fclose(fp);
				chmod(fpath, S_IRUSR|S_IWUSR);
			}
			else
				return -6;
		}
		else
			return -6;
	}

	return 0;
}

static int _ovpn_server_write_keys(int unit, ovpn_sconf_t *conf)
{
	FILE *fp;
	char fpath[128];
	char buf[BUF_SIZE];

	//TLS
	if(conf->auth_mode == OVPN_AUTH_TLS) {
		if(get_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_CA_KEY, buf, sizeof(buf))) {
			snprintf(fpath, sizeof(fpath), "%s/server%d/ca.key", OVPN_DIR_CONF, unit);
			fp = fopen(fpath, "w");
			if(fp) {
				fputs(buf, fp);
				fclose(fp);
				chmod(fpath, S_IRUSR|S_IWUSR);
			}
			else
				return -1;
		}
		else
			return -1;

		if(get_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_CA, buf, sizeof(buf))) {
			snprintf(fpath, sizeof(fpath), "%s/server%d/ca.crt", OVPN_DIR_CONF, unit);
			fp = fopen(fpath, "w");
			if(fp) {
				fputs(buf, fp);
				fclose(fp);
				chmod(fpath, S_IRUSR|S_IWUSR);
			}
			else
				return -2;
		}
		else
			return -2;

		if(get_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_KEY, buf, sizeof(buf))) {
			snprintf(fpath, sizeof(fpath), "%s/server%d/server.key", OVPN_DIR_CONF, unit);
			fp = fopen(fpath, "w");
			if(fp) {
				fputs(buf, fp);
				fclose(fp);
				chmod(fpath, S_IRUSR|S_IWUSR);
			}
			else
				return -3;
		}
		else
			return -3;

		if(get_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_CERT, buf, sizeof(buf))) {
			snprintf(fpath, sizeof(fpath), "%s/server%d/server.crt", OVPN_DIR_CONF, unit);
			fp = fopen(fpath, "w");
			if(fp) {
				fputs(buf, fp);
				fclose(fp);
				chmod(fpath, S_IRUSR|S_IWUSR);
			}
			else
				return -4;
		}
		else
			return -4;

		if(get_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_CRL, buf, sizeof(buf))) {
			if(strlen(buf)) {
				snprintf(fpath, sizeof(fpath), "%s/server%d/crl.pem", OVPN_DIR_CONF, unit);
				fp = fopen(fpath, "w");
				if(fp) {
					fputs(buf, fp);
					fclose(fp);
					chmod(fpath, S_IRUSR|S_IWUSR);
				}
				else
					return -5;
			}
		}

		if(get_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_DH, buf, sizeof(buf))) {
			snprintf(fpath, sizeof(fpath), "%s/server%d/dh.pem", OVPN_DIR_CONF, unit);
			fp = fopen(fpath, "w");
			if(fp) {
				fputs(buf, fp);
				fclose(fp);
				chmod(fpath, S_IRUSR|S_IWUSR);
			}
			else
				return -6;
		}
		else
			return -6;
	}

	//static key
	if ( conf->auth_mode == OVPN_AUTH_STATIC
		|| (conf->auth_mode == OVPN_AUTH_TLS && conf->direction >= 0)
	) {
		if(get_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_STATIC, buf, sizeof(buf))) {
			snprintf(fpath, sizeof(fpath), "%s/server%d/static.key", OVPN_DIR_CONF, unit);
			fp = fopen(fpath, "w");
			if(fp) {
				fputs(buf, fp);
				fclose(fp);
				chmod(fpath, S_IRUSR|S_IWUSR);
			}
			else
				return -7;
		}
		else
			return -7;
	}

	return 0;
}

/***********************************************************
 * return value:
 * -1: error
 * 0: selfsigned and key size mismatch
 * 1: not selfsigned
 * 2: selfsigned and key size match
 ***********************************************************/
static int _ovpn_server_verify_selfsigned_ca(char* buf, int match_keysize)
{
	BIO *bio = NULL;
	X509 *x509data = NULL;
	char issuer[128] = {0};
	EVP_PKEY *public_key = NULL;
	int real_keysize = 0 ;
	int ret = -1;

	if(!buf)
		return -1;

	bio = BIO_new(BIO_s_mem());

	if(BIO_write(bio, buf, strlen(buf)) <= 0)
		goto finish;

	x509data = PEM_read_bio_X509(bio, NULL, 0, NULL);

	X509_NAME_oneline(X509_get_issuer_name(x509data), issuer, sizeof(issuer));
	//cprintf("issuer: %s\n", issuer);
	if(!strstr(issuer, "ASUS") && !strstr(issuer, get_productid())) {
		ret = 1;
		goto finish;
	}

	public_key = X509_get_pubkey(x509data);
	real_keysize = EVP_PKEY_bits(public_key);
	//cprintf("key size: %d\n", real_keysize);
	if(real_keysize == match_keysize)
		ret = 2;
	else
		ret = 0;

finish:
	BIO_free(bio);
	return ret;
}

/***********************************************************
 * return value:
 * -1: error
 * 0: dh size < 768
 * 1: dh size >= 768
 ***********************************************************/
static int _ovpn_server_verify_dh(char* buf)
{
	BIO *bio = NULL;
	DH *dh = NULL;
	int dh_size;
	int ret = -1;

	if(!buf)
		return -1;

	bio = BIO_new(BIO_s_mem());

	if(BIO_write(bio, buf, strlen(buf)) <= 0)
		goto finish;

	dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	dh_size = BN_num_bits(dh->p);
	//cprintf("dh size: %d\n", dh_size);
	if(dh_size < 768)
		ret = 0;
	else
		ret = 1;

finish:
	BIO_free(bio);
	return ret;
}

static void _ovpn_server_check_keys(int unit, ovpn_sconf_t *conf)
{
	char fpath[128];
	FILE *fp;
	char buf[BUF_SIZE];
	int dh_valid;

	mkdir(OVPN_DIR_TMP, 0700);

	//certificate and key
	if( !get_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_CA, buf, sizeof(buf))
		|| !_ovpn_server_verify_selfsigned_ca(buf, conf->tls_keysize)
	) {
		//generate certificate and key
		snprintf(fpath, sizeof(fpath), "/tmp/genvpncert.sh");
		fp = fopen(fpath, "w");
		if(fp) {
			fprintf(fp,
				"#!/bin/sh\n"
				"export OPENSSL=\"%s\"\n"	//openssl
				"export GREP=\"/bin/grep\"\n"
				"export KEY_CONFIG=\"%s\"\n"	//openssl conf
				"export KEY_DIR=\"%s\"\n"	//OVPN_DIR_TMP
				"export KEY_SIZE=%d\n"	//tls_keysize
				"export CA_EXPIRE=3650\n"
				"export KEY_EXPIRE=3650\n"
				"export KEY_COUNTRY=\"TW\"\n"
				"export KEY_PROVINCE=\"TW\"\n"
				"export KEY_CITY=\"Taipei\"\n"
				"export KEY_ORG=\"ASUS\"\n"
				"export KEY_EMAIL=\"me@myhost.mydomain\"\n"
				"export KEY_CN=\"%s\"\n"	//productid
				"touch %s/index.txt\n"	//OVPN_DIR_TMP
				"echo 01 >%s/serial\n"	//OVPN_DIR_TMP
				"%s --initca\n"	//pkitool
				"%s --server server\n"	//pkitool
				, OVPN_PRG_OPENSSL, OVPN_PRG_OPENSSL_CONF
				, OVPN_DIR_TMP, conf->tls_keysize, get_productid()
				, OVPN_DIR_TMP, OVPN_DIR_TMP
				, OVPN_PRG_PKITOOL, OVPN_PRG_PKITOOL
			);

			//undefined common name, default use username-as-common-name
			fprintf(fp, "\n"
				"export KEY_CN=\"\"\n"
				"%s client\n"
				, OVPN_PRG_PKITOOL
			);

			fclose(fp);
			chmod(fpath, 0700);
			system(fpath);
			unlink(fpath);
		}

		//set certification and key to nvram or jffs
		snprintf(fpath, sizeof(fpath), "%s/ca.key", OVPN_DIR_TMP);
		set_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_CA_KEY, NULL, fpath);
		snprintf(fpath, sizeof(fpath), "%s/ca.crt", OVPN_DIR_TMP);
		set_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_CA, NULL, fpath);

		snprintf(fpath, sizeof(fpath), "%s/server.key", OVPN_DIR_TMP);
		set_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_KEY, NULL, fpath);
		snprintf(fpath, sizeof(fpath), "%s/server.crt", OVPN_DIR_TMP);
		set_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_CERT, NULL, fpath);

		snprintf(fpath, sizeof(fpath), "%s/client.key", OVPN_DIR_TMP);
		set_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_CLIENT_KEY, NULL, fpath);
		snprintf(fpath, sizeof(fpath), "%s/client.crt", OVPN_DIR_TMP);
		set_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_CLIENT_CERT, NULL, fpath);
	}

	//DH
	dh_valid = 0;
	if ( get_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_DH, buf, sizeof(buf)) ) {
		dh_valid = _ovpn_server_verify_dh(buf);
	}
	if(dh_valid == 0) {
		set_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_DH, NULL, OVPN_DEFAULT_DH);
	}

	//STATIC KEY
	if( (conf->auth_mode == OVPN_AUTH_STATIC || (conf->auth_mode == OVPN_AUTH_TLS && conf->direction >= 0))
		&& !ovpn_key_exists(OVPN_TYPE_SERVER, unit, OVPN_SERVER_STATIC)
	) {
		snprintf(fpath, sizeof(fpath), "%s/static.key", OVPN_DIR_TMP);
		snprintf(buf, sizeof(buf), "%s --genkey --secret %s", OVPN_PRG_OPENVPN, fpath);
		system(buf);
		f_wait_exists(fpath, 3);
		set_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_STATIC, NULL, fpath);
	}

	eval("rm", "-rf", OVPN_DIR_TMP);
}

static int _ovpn_server_verify_client_crt(int unit)
{
	char buf[BUF_SIZE];
	char fpath[128];
	FILE *fp;
	int valid = 0;
	BIO *crtbio = NULL;
	X509 *x509data = NULL;
	X509_STORE *store = NULL;
	X509_STORE_CTX *ctx = NULL;
	int ret = 0;

	OpenSSL_add_all_algorithms();

	//Load the certificate
	get_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_CLIENT_CERT, buf, sizeof(buf));
	crtbio = BIO_new(BIO_s_mem());
	ret = BIO_write(crtbio, buf, strlen(buf));
	if(ret <= 0) {
		goto end;
	}
	x509data = PEM_read_bio_X509(crtbio, NULL, 0, NULL);
	if(x509data == NULL) {
		goto end;
	}

	//Load the CA
	mkdir(OVPN_DIR_TMP, 0700);
	snprintf(fpath, sizeof(fpath), "%s/ca.crt", OVPN_DIR_TMP);
	fp = fopen(fpath, "w");
	if(fp) {
		get_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_CA, buf, sizeof(buf));
		fputs(buf, fp);
		fclose(fp);
	}
	else {
		goto end;
	}
	store = X509_STORE_new();
	if(store == NULL) {
		goto end;
	}
	ret = X509_STORE_load_locations(store, fpath, NULL);
	if (ret != 1) {
		goto end;
	}

	//Check the certficate
	ctx = X509_STORE_CTX_new();
	if(ctx == NULL) {
		goto end;
	}
	if(!X509_STORE_CTX_init(ctx, store, x509data, NULL)) {
		goto end;
	}
	ret = X509_verify_cert(ctx);
	if(ret > 0) {
		valid = 1;
	}
	else if(ctx->error == X509_V_ERR_CERT_NOT_YET_VALID) {
		valid = 2;
	}
	else {
		cprintf("error: %s\n", X509_verify_cert_error_string(ctx->error));
	}

end:
	if(crtbio)
		BIO_free(crtbio);
	if(store)
		X509_STORE_free(store);
	if(ctx)
		X509_STORE_CTX_free(ctx);

	eval("rm", "-rf", OVPN_DIR_TMP);

	return valid;
}

/* e.g.
 * iptables -t nat -I PREROUTING -p tcp --dport 1194 -j ACCEPT
 * iptables -I INPUT -p tcp --dport 1194 -j ACCEPT
 * iptables -I INPUT -i tun21 -j ACCEPT
 * iptables -I FORWARD -i tun21 -j ACCEPT
 */
static void _ovpn_server_fw_rule_add(int unit, ovpn_sconf_t *conf)
{
	FILE* fp;
	char fpath[128];

	snprintf(fpath, sizeof(fpath), "/etc/openvpn/server%d/fw.sh", unit);
	fp = fopen(fpath, "w");
	if(fp) {
		fprintf(fp, "#!/bin/sh\n\n");
		fprintf(fp, "iptables -t nat -I PREROUTING -p %s --dport %d -j ACCEPT\n"
			, strcmp(conf->proto, "udp")?"tcp":"udp"
			, conf->port
		);
		fprintf(fp, "iptables -I INPUT -p %s --dport %d -j ACCEPT\n"
			, strcmp(conf->proto, "udp")?"tcp":"udp"
			, conf->port
		);
		fprintf(fp, "iptables -I INPUT -i %s -j ACCEPT\n", conf->if_name);
		fprintf(fp, "iptables -I FORWARD -i %s -j ACCEPT\n", conf->if_name);
		fclose(fp);
		chmod(fpath, S_IRUSR|S_IWUSR|S_IXUSR);
		eval(fpath);
	}
}

static void _ovpn_server_fw_rule_del(int unit)
{
	char fpath[128];

	snprintf(fpath, sizeof(fpath), "/etc/openvpn/server%d/fw.sh", unit);
	if(f_exists(fpath)) {
		eval("sed", "-i", "s/-I/-D/", fpath);
		eval(fpath);
		unlink(fpath);
	}
}

static void _ovpn_client_fw_rule_add(int unit, ovpn_cconf_t *conf)
{
	FILE* fp;
	char fpath[128];
	char buf[32];

	snprintf(fpath, sizeof(fpath), "/etc/openvpn/client%d/fw.sh", unit);
	fp = fopen(fpath, "w");
	if(fp) {
		fprintf(fp, "#!/bin/sh\n\n");
		fprintf(fp, "iptables -I INPUT -i %s -j ACCEPT\n", conf->if_name);
		fprintf(fp, "iptables -I FORWARD -i %s -j ACCEPT\n", conf->if_name);

		if ( conf->if_type == OVPN_IF_TUN && conf->nat ) {
			fprintf(fp, "iptables -t nat -I POSTROUTING -s %s -o %s -j MASQUERADE\n",
				get_lan_cidr(buf, sizeof(buf)), conf->if_name);
		}

		fclose(fp);
		chmod(fpath, S_IRUSR|S_IWUSR|S_IXUSR);
		eval(fpath);
	}
}

static void _ovpn_client_fw_rule_del(int unit)
{
	char fpath[128];

	snprintf(fpath, sizeof(fpath), "/etc/openvpn/client%d/fw.sh", unit);
	if(f_exists(fpath)) {
		eval("sed", "-i", "s/-I/-D/", fpath);
		eval(fpath);
		unlink(fpath);
	}
}

static void _ovpn_cron_job_add(ovpn_type_t type, int unit, void* conf)
{
	char buf[256];
	int min = OVPN_RETRY_MIN;

	if(type == OVPN_TYPE_SERVER) {
		if(conf)
			min = ((ovpn_sconf_t*)conf)->poll;
		snprintf(buf, sizeof(buf),
			"%s a start_vpnserver%d \"*/%d * * * * service start_vpnserver%d\""
			, OVPN_PRG_CROND_CRU, unit, min, unit);
	}
	else {
		if(conf)
			min = ((ovpn_cconf_t*)conf)->poll;
		snprintf(buf, sizeof(buf),
			"%s a start_vpnclient%d \"*/%d * * * * service start_vpnclient%d\""
			, OVPN_PRG_CROND_CRU, unit, min, unit);
	}

	if( min > 0 )
		system(buf);
}

static void _ovpn_cron_job_del(ovpn_type_t type, int unit)
{
	char buf[256];

	if(type == OVPN_TYPE_SERVER) {
		snprintf(buf, sizeof(buf), "%s d start_vpnserver%d", OVPN_PRG_CROND_CRU, unit);
	}
	else {
		snprintf(buf, sizeof(buf), "%s d start_vpnclient%d", OVPN_PRG_CROND_CRU, unit);
	}

	system(buf);
}

static int _ovpn_server_gen_conf(int unit, ovpn_sconf_t *conf)
{
	char buf[BUF_SIZE];
	FILE *fp, *fp_client, *fp_cc;
	int i;
	int ret;
	char *pch;

	snprintf(buf, sizeof(buf), "%s/server%d/config.ovpn", OVPN_DIR_CONF, unit);
	fp = fopen(buf, "w");
	snprintf(buf, sizeof(buf), "%s/server%d/client.ovpn", OVPN_DIR_CONF, unit);
	fp_client = fopen(buf, "w");

	if( !fp || !fp_client )
		return -1;

// Tunnel options
	fprintf(fp,
		"# Automatically generated configuration\n"
		"\n"
		"# Tunnel options\n"
	);

	//remote (client)
	fprintf(fp_client, "remote %s %d\n", get_ovpn_sconf_remote(buf, sizeof(buf)), conf->port);

	//Allow remote peer to change its IP address and/or port number (client)
	fprintf(fp_client, "float\n");

	//Do not bind to local address and port (client)
	fprintf(fp_client, "nobind\n");

	//protocol
	if( !strcmp(conf->proto, "udp") ) {
		fprintf(fp, "proto udp\n");
		fprintf(fp, "multihome\n");
		fprintf(fp_client, "proto udp\n");
	}
	else {
		fprintf(fp, "proto tcp-server\n");
		fprintf(fp_client, "proto tcp-client\n");
	}

	//port
	fprintf(fp, "port %d\n", conf->port);

	//dev
	fprintf(fp, "dev %s\n", conf->if_name);
	if( conf->if_type == OVPN_IF_TUN ) {
		fprintf(fp_client, "dev tun\n");
	}
	else if( conf->if_type == OVPN_IF_TAP ) {
		fprintf(fp_client,
			"dev tap\n\n"
			"# Windows needs the TAP-Win32 adapter name\n"
			"# from the Network Connections panel\n"
			"# if you have more than one.  On XP SP2,\n"
			"# you may need to disable the firewall\n"
			"# for the TAP adapter.\n"
			";dev-node MyTap\n\n"
		);
	}

	//ip
	if(conf->auth_mode == OVPN_AUTH_STATIC) {
		if( conf->if_type == OVPN_IF_TUN ) {
			fprintf(fp, "ifconfig %s %s\n", conf->local, conf->remote);
			fprintf(fp_client, "ifconfig %s %s\n", conf->remote, conf->local);
		}
	}

	//OS socket buffer
	fprintf(fp, "sndbuf 0\n");
	fprintf(fp_client, "sndbuf 0\n");
	fprintf(fp, "rcvbuf 0\n");
	fprintf(fp_client, "rcvbuf 0\n");

	//Ping remote
	//keep alive
	fprintf(fp, "keepalive 15 60\n");
	fprintf(fp_client, "keepalive 15 60\n");

	//progname
	fprintf(fp, "daemon vpnserver%d\n", unit);

	//log verbosity
	if( conf->verb >= 0 )
		fprintf(fp, "verb %d\n", conf->verb);

	//client status
	fprintf(fp, "status-version 2\n");
	fprintf(fp, "status status 10\n");

	//compression
	if( strlen(conf->comp) && strcmp(conf->comp, "-1") ) {
		fprintf(fp, "comp-lzo %s\n", conf->comp);
		fprintf(fp_client, "comp-lzo %s\n", conf->comp);
	}

	//authentication
	if( conf->auth_mode == OVPN_AUTH_TLS ) {
		fprintf(fp, "plugin %s openvpn\n", OVPN_LIB_PAM);
		fprintf(fp_client, "auth-user-pass\n");
	}

//Server Mode
	fprintf(fp,
		"\n"
		"# Server Mode\n"
	);
	if( conf->auth_mode == OVPN_AUTH_TLS ) {
		if( conf->if_type == OVPN_IF_TUN ) {
			fprintf(fp, "server %s ", conf->network);
			fprintf(fp, "%s\n", conf->netmask);
		}
		else if( conf->if_type == OVPN_IF_TAP ) {
			fprintf(fp, "server-bridge");
			if( conf->dhcp ) {
				//--server-bridge
				//DHCP-proxy mode
				//will push "route-gateway dhcp"
				fprintf(fp, "\n");
				//fprintf(fp, "push \"route 0.0.0.0 255.255.255.255 net_gateway\"");
			}
			else {
				//--server-bridge gateway netmask pool-start-IP pool-end-IP
				fprintf(fp, " %s %s %s %s\n"
					, conf->lan_ipaddr, conf->lan_netmask, conf->pool_start, conf->pool_end);
			}
		}

		fprintf(fp_client, "client\n");
	}

	//route, push message
	if( conf->auth_mode == OVPN_AUTH_TLS ) {
		//client config dir
		if ( conf->ccd ) {
			fprintf(fp, "client-config-dir ccd\n");

			if ( conf->c2c )
				fprintf(fp, "client-to-client\n");

			if ( conf->ccd_excl )
				fprintf(fp, "ccd-exclusive\n");
			else
				fprintf(fp, "duplicate-cn\n");

			snprintf(buf, sizeof(buf), "%s/server%d/ccd", OVPN_DIR_CONF, unit);
			mkdir(buf, 0700);
			chdir(buf);

			for(i=0; i<conf->ccd_info.count; i++) {
				if( conf->ccd_info.ccd_val[i].enable ) {
					fp_cc = fopen(conf->ccd_info.ccd_val[i].name, "w");
					if(fp_cc) {
						fprintf(fp_cc, "iroute %s %s\n"
							, conf->ccd_info.ccd_val[i].network, conf->ccd_info.ccd_val[i].netmask);
						fprintf(fp, "route %s %s\n"
							, conf->ccd_info.ccd_val[i].network, conf->ccd_info.ccd_val[i].netmask);

						if( conf->c2c && conf->ccd_info.ccd_val[i].push ) {
							fprintf(fp, "push \"route %s %s\"\n"
								, conf->ccd_info.ccd_val[i].network, conf->ccd_info.ccd_val[i].netmask);
						}

						fclose(fp_cc);
						chmod(conf->ccd_info.ccd_val[i].name, S_IRUSR|S_IWUSR);
					}
				}
			}
		}
		else {
			fprintf(fp, "duplicate-cn\n");
		}

		//router LAN
		if ( conf->push_lan && conf->if_type == OVPN_IF_TUN ) {
			get_lan_cidr(buf, sizeof(buf));
			pch = strchr(buf, '/');
			*pch = '\0';
			fprintf(fp, "push \"route %s %s vpn_gateway %d\"\n",
				buf, conf->lan_netmask, PUSH_LAN_METRIC);
		}

		//router as gateway
		if ( conf->redirect_gateway ) {
			fprintf(fp, "push \"redirect-gateway def1\"\n");
			//if ( conf->if_type == OVPN_IF_TAP )
				//fprintf(fp, "push \"route-gateway %s\"\n", conf->lan_ipaddr);
		}

		//DNS
		if ( conf->push_dns ) {
			fprintf(fp, "push \"dhcp-option DNS %s\"\n", conf->lan_ipaddr);
		}
	}

	//ignore client certificate
	if ( conf->auth_mode == OVPN_AUTH_TLS && conf->useronly ) {
		fprintf(fp, "client-cert-not-required\n");
		fprintf(fp, "username-as-common-name\n");
	}

//Data Channel Encryption Options:
	fprintf(fp,
		"\n"
		"# Data Channel Encryption Options\n"
	);

	//HMAC digest algorithm
	if ( strlen(conf->digest) && strcmp(conf->digest, "default") ) {
		fprintf(fp, "auth %s\n", conf->digest);
		fprintf(fp_client, "auth %s\n", conf->digest);
	}

	//cipher
	if ( strlen(conf->cipher) && strcmp(conf->cipher, "default") ) {
		fprintf(fp, "cipher %s\n", conf->cipher);
		fprintf(fp_client, "cipher %s\n", conf->cipher);
	}

	if ( conf->auth_mode == OVPN_AUTH_STATIC ) {
		fprintf(fp, "secret static.key\n");
	}

//TLS Mode Options:
	if ( conf->auth_mode == OVPN_AUTH_TLS ) {
		fprintf(fp,
			"\n"
			"# TLS Mode Options\n"
		);
		//certificate and keys
		fprintf(fp, "ca ca.crt\n");
		fprintf(fp, "dh dh.pem\n");
		fprintf(fp, "cert server.crt\n");
		fprintf(fp, "key server.key\n");

		snprintf(buf, sizeof(buf), "vpn_crt_server%d_crl", unit);
		if ( ovpn_key_exists(OVPN_TYPE_SERVER, unit, OVPN_SERVER_CRL) )
			fprintf(fp, "crl-verify crl.pem\n");

		//TLS-Auth, HMAC
		if ( conf->direction >= 0 ) {
			fprintf(fp, "tls-auth static.key");
			if ( conf->direction < 2 )
				fprintf(fp, " %d", conf->direction);
			fprintf(fp, "\n");
		}

		//TLS Renegotiation Time
		if( conf->reneg >= 0 ) {
			fprintf(fp, "reneg-sec %d\n", conf->reneg);
			fprintf(fp_client, "reneg-sec %d\n", conf->reneg);
		}

		//Require that peer certificate was signed with an explicit nsCertType designation of "client" or "server".
		fprintf(fp_client, "ns-cert-type server\n");
	}

	//custom config
	fprintf(fp,
		"\n"
		"# Custom Configuration\n"
	);
	fputs(conf->custom, fp);
	fclose(fp);

	// Write client inline certification and key
	if ( conf->auth_mode == OVPN_AUTH_TLS ) {
		fprintf(fp_client,
			"<ca>\n"
			"%s\n"
			"</ca>\n\n"
			, get_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_CA, buf, sizeof(buf))
		);

		//if(!conf->useronly) {
			ret = _ovpn_server_verify_client_crt(unit);
			if( ret ) {
				if(ret == 2) {
					fprintf(fp_client,
						"#\n"
						"# Update client certificate and key if necessary\n"
						"#\n");
				}
				fprintf(fp_client,
					"<cert>\n"
					"%s\n"
					"</cert>\n\n"
					, get_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_CLIENT_CERT, buf, sizeof(buf))
				);
				fprintf(fp_client,
					"<key>\n"
					"%s\n"
					"</key>\n\n"
					, get_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_CLIENT_KEY, buf, sizeof(buf))
				);
			} else {
				fprintf(fp_client,
					"<cert>\n"
					"    paste client certificate data here\n"
					"</cert>\n\n"
					"<key>\n"
					"    paste client key data here\n"
					"</key>\n\n"
				);
			}
		//}

		if ( conf->direction >= 0 ) {
			fprintf(fp_client,
				"<tls-auth>\n"
				"%s\n"
				"</tls-auth>\n\n"
				, get_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_STATIC, buf, sizeof(buf))
			);
			if(conf->direction == 1)
				fprintf(fp_client, "key-direction 0\n\n");
			else if(conf->direction == 0)
				fprintf(fp_client, "key-direction 1\n\n");
		}
	}
	else if ( conf->auth_mode == OVPN_AUTH_STATIC ) {
		fprintf(fp_client,
			"<secret>\n"
			"%s\n"
			"</secret>\n\n"
			, get_ovpn_key(OVPN_TYPE_SERVER, unit, OVPN_SERVER_STATIC, buf, sizeof(buf))
		);
	}
	fclose(fp_client);
	return 0;
}

static int _ovpn_client_gen_conf(int unit, ovpn_cconf_t *conf)
{
	char buf[BUF_SIZE];
	FILE *fp;

	snprintf(buf, sizeof(buf), "%s/client%d/config.ovpn", OVPN_DIR_CONF, unit);
	fp = fopen(buf, "w");

	if(!fp)
		return -1;

// Tunnel options
	fprintf(fp,
		"# Automatically generated configuration\n"
		"\n"
		"# Tunnel options\n"
	);

	//remote
	fprintf(fp, "remote %s\n", conf->addr);

	//retry resolve hostname
	if ( conf->retry >= 0 )
		fprintf(fp, "resolv-retry %d\n", conf->retry);
	else
		fprintf(fp, "resolv-retry infinite\n");

	//Do not bind to local address and port
	fprintf(fp, "nobind\n");

	//protocol
	if( !strcmp(conf->proto, "udp") ) {
		fprintf(fp, "proto udp\n");
	}
	else {
		fprintf(fp, "proto tcp-client\n");
	}

	//port
	fprintf(fp, "port %d\n", conf->port);

	//dev
	fprintf(fp, "dev %s\n", conf->if_name);

	//ip pool
	if( conf->auth_mode == OVPN_AUTH_STATIC ) {
		if( conf->if_type == OVPN_IF_TUN ) {
			fprintf(fp, "ifconfig %s %s\n", conf->local, conf->remote);
		}
		//else if( conf->if_type == OVPN_IF_TAP ) {
			//fprintf(fp, "ifconfig %s %s\n", conf->remote, conf->netmask);
		//}
	}

	//TODO: TLS recevie routing info, add/ignore rules for dual wan multi route table
	// redirect gateway
	if( conf->redirect_gateway ) {
		if( conf->if_type == OVPN_IF_TAP && strlen(conf->gateway) )
			fprintf(fp, "route-gateway %s\n", conf->gateway);
		fprintf(fp, "redirect-gateway def1\n");
	}

	//OS socket buffer
	fprintf(fp, "sndbuf 0\n");
	fprintf(fp, "rcvbuf 0\n");

	//Don't close and reopen TUN/TAP device
	fprintf(fp, "persist-tun\n");

	//Don't re-read key files across SIGUSR1 or --ping-restart
	fprintf(fp, "persist-key\n");

	//to update DNS info
	if( conf->auth_mode == OVPN_AUTH_TLS && conf->adns ) {
		snprintf(buf, sizeof(buf), "%s/ovpn-up", OVPN_DIR_CONF);
		symlink("/sbin/rc", buf);
		fprintf(fp, "up '%s %d'\n", buf, unit);
		snprintf(buf, sizeof(buf), "%s/ovpn-down", OVPN_DIR_CONF);
		symlink("/sbin/rc", buf);
		fprintf(fp, "down '%s %d'\n", buf, unit);
		fprintf(fp, "script-security 2\n");
	}

	//progname
	fprintf(fp, "daemon vpnclient%d\n", unit);

	//log verbosity
	if( conf->verb >= 0 )
		fprintf(fp, "verb %d\n", conf->verb);

	//status
	fprintf(fp, "status-version 2\n");
	fprintf(fp, "status status 10\n");

	//compression
	if( strlen(conf->comp) && strcmp(conf->comp, "-1") ) {
		fprintf(fp, "comp-lzo %s\n", conf->comp);
	}

// Client Mode
	fprintf(fp,
		"\n"
		"# Client Mode\n"
	);
	if( conf->auth_mode == OVPN_AUTH_TLS ) {
		fprintf(fp, "client\n");
		//authentication
		if (conf->userauth) {
			fprintf(fp, "auth-user-pass up\n");
		}
	}

//Data Channel Encryption Options:
	fprintf(fp,
		"\n"
		"# Data Channel Encryption Options\n"
	);

	//HMAC digest algorithm
	if ( strlen(conf->digest) && strcmp(conf->digest, "default") ) {
		fprintf(fp, "auth %s\n", conf->digest);
	}

	//cipher
	if ( strlen(conf->cipher) && strcmp(conf->cipher, "default") ) {
		fprintf(fp, "cipher %s\n", conf->cipher);
	}

	if ( conf->auth_mode == OVPN_AUTH_STATIC ) {
		fprintf(fp, "secret static.key\n");
	}

//TLS Mode Options:
	if ( conf->auth_mode == OVPN_AUTH_TLS ) {
		fprintf(fp,
			"\n"
			"# TLS Mode Options\n"
		);
		//certificate and keys
		fprintf(fp, "ca ca.crt\n");
		if ( !conf->useronly ) {
			fprintf(fp, "cert client.crt\n");
			fprintf(fp, "key client.key\n");
		}

		if ( ovpn_key_exists(OVPN_TYPE_CLIENT, unit, OVPN_CLIENT_CRL) )
			fprintf(fp, "crl-verify crl.pem\n");

		if ( conf->tls_remote) {
			fprintf(fp, "tls-remote %s\n", conf->common_name);
		}

		//TLS-Auth, HMAC
		if ( conf->direction >= 0 ) {
			fprintf(fp, "tls-auth static.key");
			if ( conf->direction < 2 )
				fprintf(fp, " %d", conf->direction);
			fprintf(fp, "\n");
		}

		//TLS Renegotiation Time
		if( conf->reneg >= 0 ) {
			fprintf(fp, "reneg-sec %d\n", conf->reneg);
		}
	}


	//custom config
	fprintf(fp,
		"\n"
		"# Custom Configuration\n"
	);
	fputs(conf->custom, fp);
#ifdef RTCONFIG_VPN_FUSION
	fprintf(fp, "\nroute-noexec\n");
	fprintf(fp, "script-security 2\n");
	fprintf(fp, "up '/etc/openvpn/ovpnc-up %d'\n", unit);
	fprintf(fp, "down '/etc/openvpn/ovpnc-down %d'\n", unit);
	fprintf(fp, "route-up '/etc/openvpn/ovpnc-route-up %d'", unit);
#endif
	fclose(fp);
	return 0;
}

static void _ovpn_stop_wait(ovpn_type_t type, int unit)
{
	char name[16] = {0};
	int n = 0;

	if( _ovpn_is_running(type, unit) == 0 )
		return;

	if(type == OVPN_TYPE_CLIENT)
		snprintf(name, sizeof(name), "vpnclient%d", unit);
	else if(type == OVPN_TYPE_SERVER)
		snprintf(name, sizeof(name), "vpnserver%d", unit);

	if ( killall(name, SIGTERM) == 0) {
		n = 10;
		while ((killall(name, 0) == 0) && (n-- > 0)) {
			_dprintf("%s: waiting %s n=%d\n", __FUNCTION__, name, n);
			sleep(1);
		}
		if (n < 0) {
			n = 10;
			while ((killall(name, SIGKILL) != 0) && (n-- > 0)) {
				_dprintf("%s: SIGKILL %s n=%d\n", __FUNCTION__, name, n);
				sleep(1);
			}
		}
	}
}

void start_ovpn_client(int unit)
{
	char buf[256];
	ovpn_cconf_t conf;
	int ret;

	if(unit == 0 || unit > OVPN_CLIENT_MAX)
		return;

	if( _ovpn_is_running(OVPN_TYPE_CLIENT, unit) ) {
		_dprintf("OpenVPN Client %d is running\n", unit);
		return;
	}

	//get config
	if( !get_ovpn_cconf(unit, &conf)) {
		_dprintf("get_ovpn_cconf failed\n");
		_ovpn_cron_job_add(OVPN_TYPE_CLIENT, unit, NULL);
		return;
	}

	if(conf.enable == 0)
		return;

	//initializing
	update_ovpn_status(OVPN_TYPE_CLIENT, unit, OVPN_STS_INIT);

	//work directory
	_ovpn_check_dir(OVPN_TYPE_CLIENT, unit);

	//load module
	eval("modprobe", "tun");
	f_wait_exists("/dev/net/tun", 5);

	//setup interface
	_ovpn_tunnel_create(conf.if_type, conf.if_name);

	//generate config and script files
	if( _ovpn_client_gen_conf(unit, &conf) < 0 ) {
		_dprintf("_ovpn_client_gen_conf failed\n");
		_ovpn_cron_job_add(OVPN_TYPE_CLIENT, unit, NULL);
		return;
	}
	if( (ret = _ovpn_client_write_keys(unit, &conf)) < 0 ) {
		_dprintf("_ovpn_client_write_keys return %d\n", ret);
		_ovpn_cron_job_add(OVPN_TYPE_CLIENT, unit, NULL);
		return;
	}

	//start
	//[<CPUx>] openvpn --cd <dir> --config <file> NULL
	char *argv[] = { "", "", "", "", "", "", NULL};
	int argc = 1;
	snprintf(buf, sizeof(buf),
		"%s/vpnclient%d --cd %s/client%d --config config.ovpn"
		, OVPN_DIR_CONF, unit, OVPN_DIR_CONF, unit);
	for (argv[argc] = strtok(buf, " "); argv[argc] != NULL; argv[++argc] = strtok(NULL, " "));
	if( NULL != (argv[0] = adjust_smp_affinity(OVPN_TYPE_CLIENT, unit)) ) {
		_cpu_eval(NULL, argv);
	}
	else {
		_eval(argv+1, NULL, 0, NULL);
	}

	//firewall
	_ovpn_client_fw_rule_add(unit, &conf);

	//cron job
	_ovpn_cron_job_del(OVPN_TYPE_CLIENT, unit);
	_ovpn_cron_job_add(OVPN_TYPE_CLIENT, unit, &conf);

}

void stop_ovpn_client(int unit)
{
	char buf[256];
	ovpn_cconf_t conf;

	if(unit == 0 || unit > OVPN_CLIENT_MAX)
		return;

	get_ovpn_cconf(unit, &conf);

	// Remove cron
	_ovpn_cron_job_del(OVPN_TYPE_CLIENT, unit);

	// Remove firewall rules
	_ovpn_client_fw_rule_del(unit);

	// Stop the VPN client
	_ovpn_stop_wait(OVPN_TYPE_CLIENT, unit);

	// remove interface
	_ovpn_tunnel_remove(OVPN_TYPE_CLIENT, unit);

	eval("modprobe", "-r", "tun");

	// Delete config
	snprintf(buf, sizeof(buf), "%s/client%d", OVPN_DIR_CONF, unit);
	eval("rm", "-rf", buf);

	update_ovpn_status(OVPN_TYPE_CLIENT, unit, OVPN_STS_STOP);

}

void start_ovpn_server(int unit)
{
	char buf[256];
	ovpn_sconf_t conf;
	int ret;

	if(unit == 0 || unit > OVPN_SERVER_MAX)
		return;

	if( _ovpn_is_running(OVPN_TYPE_SERVER, unit) ) {
		_dprintf("OpenVPN Server %d is running\n", unit);
		return;
	}

	//get config
	if( !get_ovpn_sconf(unit, &conf) ) {
		_ovpn_cron_job_add(OVPN_TYPE_SERVER, unit, NULL);
		return;
	}

	if(conf.enable == 0)
		return;

	//initializing
	update_ovpn_status(OVPN_TYPE_SERVER, unit, OVPN_STS_INIT);

	//work directory
	_ovpn_check_dir(OVPN_TYPE_SERVER, unit);

	//load module
	eval("modprobe", "tun");
	f_wait_exists("/dev/net/tun", 5);

	//setup interface
	_ovpn_tunnel_create(conf.if_type, conf.if_name);

	//generate config and script files
	_ovpn_server_check_keys(unit, &conf);
	if( (ret = _ovpn_server_write_keys(unit, &conf)) < 0 ) {
		_dprintf("_ovpn_server_write_keys return %d\n", ret);
		_ovpn_cron_job_add(OVPN_TYPE_SERVER, unit, NULL);
		return;
	}
	if( _ovpn_server_gen_conf(unit, &conf) < 0 ) {
		_ovpn_cron_job_add(OVPN_TYPE_SERVER, unit, NULL);
		return;
	}

	//start
	//[<CPUx>] openvpn --cd <dir> --config <file> NULL
	char *argv[] = { "", "", "", "", "", "", NULL};
	int argc = 1;
	snprintf(buf, sizeof(buf),
		"%s/vpnserver%d --cd %s/server%d --config config.ovpn"
		, OVPN_DIR_CONF, unit, OVPN_DIR_CONF, unit);
	for (argv[argc] = strtok(buf, " "); argv[argc] != NULL; argv[++argc] = strtok(NULL, " "));
	if( NULL != (argv[0] = adjust_smp_affinity(OVPN_TYPE_SERVER, unit)) ) {
		_cpu_eval(NULL, argv);
	}
	else {
		_eval(argv+1, NULL, 0, NULL);
	}

	//firewall
	_ovpn_server_fw_rule_add(unit, &conf);

	//cron job
	_ovpn_cron_job_del(OVPN_TYPE_SERVER, unit);
	_ovpn_cron_job_add(OVPN_TYPE_SERVER, unit, &conf);

	//running
	if ( conf.auth_mode == OVPN_AUTH_STATIC ) {
		update_ovpn_status(OVPN_TYPE_SERVER, unit, OVPN_STS_RUNNING);
	}
}

void stop_ovpn_server(int unit)
{
	char buf[256];
	ovpn_sconf_t conf;

	if(unit == 0 || unit > OVPN_SERVER_MAX)
		return;

	update_ovpn_status(OVPN_TYPE_SERVER, unit, OVPN_STS_STOPPING);

	get_ovpn_sconf(unit, &conf);

	// Remove cron
	_ovpn_cron_job_del(OVPN_TYPE_SERVER, unit);

	// Remove firewall rules
	_ovpn_server_fw_rule_del(unit);

	// Stop the VPN server
	_ovpn_stop_wait(OVPN_TYPE_SERVER, unit);

	// Remove interface
	_ovpn_tunnel_remove(OVPN_TYPE_SERVER, unit);

	// Remove module
	eval("modprobe", "-r", "tun");

	// Delete config
	snprintf(buf, sizeof(buf), "%s/server%d", OVPN_DIR_CONF, unit);
	eval("rm", "-rf", buf);

	update_ovpn_status(OVPN_TYPE_SERVER, unit, OVPN_STS_STOP);
}

void start_ovpn_eas()
{
	ovpn_sconf_common_t sconf_common;
	ovpn_cconf_common_t cconf_common;
	int unit;

	get_ovpn_sconf_common(&sconf_common);
	get_ovpn_cconf_common(&cconf_common);

	// wait ntp for a while
	wait_time_sync(5);

	// start servers
	for(unit = 1; unit <= OVPN_SERVER_MAX; unit++) {
		if( sconf_common.enable[unit-1] ) {
			if( _ovpn_is_running(OVPN_TYPE_SERVER, unit) )
				stop_ovpn_server(unit);
			start_ovpn_server(unit);
		}
	}

	// start clients
	for(unit = 1; unit <= OVPN_CLIENT_MAX; unit++) {
		if( cconf_common.enable[unit-1] ) {
			if( _ovpn_is_running(OVPN_TYPE_CLIENT, unit) )
				stop_ovpn_client(unit);
			start_ovpn_client(unit);
		}
	}
}

void stop_ovpn_eas()
{
	ovpn_sconf_common_t sconf_common;
	ovpn_cconf_common_t cconf_common;
	int unit;

	get_ovpn_sconf_common(&sconf_common);
	get_ovpn_cconf_common(&cconf_common);

	// stop servers
	for(unit = 1; unit <= OVPN_SERVER_MAX; unit++) {
		if( sconf_common.enable[unit-1] ) {
			if( _ovpn_is_running(OVPN_TYPE_SERVER, unit) )
				stop_ovpn_server(unit);
		}
	}

	// stop clients
	for(unit = 1; unit <= OVPN_CLIENT_MAX; unit++) {
		if( cconf_common.enable[unit-1] ) {
			if( _ovpn_is_running(OVPN_TYPE_CLIENT, unit) )
				stop_ovpn_client(unit);
		}
	}
}

void run_ovpn_fw_scripts()
{
	char buf[128];
	int unit;

	for(unit = 1; unit <= OVPN_SERVER_MAX; unit++) {
		snprintf(buf, sizeof(buf), "%s/server%d/fw.sh", OVPN_DIR_CONF, unit);
		if(f_exists(buf))
			eval(buf);
	}
	for(unit = 1; unit <= OVPN_CLIENT_MAX; unit++) {
		snprintf(buf, sizeof(buf), "%s/client%d/fw.sh", OVPN_DIR_CONF, unit);
		if(f_exists(buf))
			eval(buf);
	}
}

void write_ovpn_dnsmasq_config(FILE* f)
{
	ovpn_sconf_common_t sconf_common;
	ovpn_sconf_t sconf;
	int unit;

	get_ovpn_sconf_common(&sconf_common);

	for(unit = 1; unit <= OVPN_SERVER_MAX; unit++) {
		if( sconf_common.dns[unit-1] ) {
			get_ovpn_sconf(unit, &sconf);
			fprintf(f, "interface=%s\n", sconf.if_name);
		}
	}

	//TODO: VPN client recevie DNS info, update DNS policy/server info
}

int write_ovpn_resolv(FILE* fp_resolv, FILE* fp_servers)
{
	char file_path[128];
	FILE* f_in;
	char buf[128];

	// get from /etc/openvpn/resolv.xxx
	snprintf(file_path, sizeof(file_path), "%s/resolv.conf", OVPN_DIR_CONF);
	f_in = fopen(file_path, "r");
	if(f_in)
	{
		while( !feof(f_in) )
		{
			if(fgets(buf, sizeof(buf), f_in) && strlen(buf) > 7)
			{
				fputs(buf, fp_resolv);
			}
		}
		fclose(f_in);
	}
	else
	{
		return 0;
	}

	snprintf(file_path, sizeof(file_path), "%s/resolv.dnsmasq", OVPN_DIR_CONF);
	f_in = fopen(file_path, "r");
	if(f_in)
	{
		while( !feof(f_in) )
		{
			if(fgets(buf, sizeof(buf), f_in) && strlen(buf) > 7)
			{
				fputs(buf, fp_servers);
			}
		}
		fclose(f_in);
	}

	return 1;
}

void create_ovpn_passwd()
{
	FILE *fps, *fpp;
	unsigned char s[512];
	char salt[32], *p;
	ovpn_accnt_info_t account_info;
	int gid = 200; /* OpenVPN GID */
	int uid = 200;
	int i;

	strcpy(salt, "$1$");
	f_read("/dev/urandom", s, 6);
	base64_encode(s, salt + 3, 6);
	salt[3 + 8] = 0;
	p = salt;
	while (*p) {
		if (*p == '+') *p = '.';
		++p;
	}

	fps = fopen("/etc/shadow.openvpn", "w");
	fpp = fopen("/etc/passwd.openvpn", "w");
	if (fps == NULL || fpp == NULL)
		goto error;

	get_ovpn_accnt(&account_info);

	for (i = 0; i < account_info.count; i++) {
		p = crypt(account_info.account[i].password, salt);
		fprintf(fps, "%s:%s:0:0:99999:7:0:0:\n", account_info.account[i].username, p);
		fprintf(fpp, "%s:x:%d:%d::/dev/null:/dev/null\n", account_info.account[i].username, uid, gid);
		uid++;
	}

error:
	if (fps)
		fclose(fps);
	if (fpp)
		fclose(fpp);

	chmod("/etc/shadow.openvpn", S_IRUSR|S_IWUSR);
	chmod("/etc/passwd.openvpn", S_IRUSR|S_IWUSR);
}

static int _is_dup_ovpn_accnt(char *accnt_str)
{
	ovpn_accnt_info_t accnt_info;
	int i;
	int is_duplicate = 0;

	if( !accnt_str )
		return 0;

	get_ovpn_accnt(&accnt_info);

	for (i = 0; i < accnt_info.count; i++) {
		//_dprintf("%s-account(%s)-(%s)\n", __FUNCTION__, account_str, username);
		if( !strcmp(accnt_str, accnt_info.account[i].username) ) {
			is_duplicate = 1;
			break;
		}
	}

	return is_duplicate;
}

/*
	work around, OpenVpn server account would duplicate with system and samba
	need to deal with it before a formal account management function is
	implmented, or OpenVpn account won't work..

	Samba account only need an entry, so when account is duplicate with openvpn
	account, replaced with OpenVPN account
*/
void append_ovpn_accnt(const char *path, const char *ovpn_path)
{
	char tmpfile[256];
	char buf[512];
	char account[32];
	FILE *fp;
	FILE *fp_tmp;

	if( !path || !ovpn_path)
		return;

	if( !f_exists(path) || !f_exists(ovpn_path) )
		return;

	//remove duplicate account
	snprintf(tmpfile, sizeof(tmpfile), "%s.tmp", path);
	if( (fp = fopen(path, "r")) != NULL ) {
		if( (fp_tmp = fopen(tmpfile, "w+")) != NULL ) {
			//first line for admin account
			if (fgets(buf, sizeof(buf), fp)) {
				fputs(buf, fp_tmp);
			}

			while( fgets(buf, sizeof(buf), fp) ) {
				if (sscanf(buf, "%31[^:]:%*s", account) == 1) {
					//_dprintf("%s-account(%s)\n", __FUNCTION__, account);
					if( !_is_dup_ovpn_accnt(account) ) {
						fputs(buf, fp_tmp);
					}
				}
				else {
					fputs(buf, fp_tmp);
				}
			}
		}
		else {
			fclose(fp);
			return;
		}

		fclose(fp);
		fclose(fp_tmp);

		unlink(path);
		rename(tmpfile, path);
		chmod(path, 0644);
	}
	else {
		return;
	}

	snprintf(buf, sizeof(buf), "cd /etc; cat %s >> %s", ovpn_path, path);
	system(buf);
}

void update_ovpn_profie_remote()
{
	ovpn_sconf_common_t sconf_common;
	int unit;
	char file_path[128];
	char address[64];
	char cmd[256];

	get_ovpn_sconf_common(&sconf_common);

	for(unit = 1; unit <= OVPN_SERVER_MAX; unit++)
	{
		if( sconf_common.enable[unit-1] )
		{
			snprintf(file_path, sizeof(file_path), "%s/server%d/client.ovpn", OVPN_DIR_CONF, unit);
			if(f_exists(file_path) && f_size(file_path) > 0)
			{
				get_ovpn_sconf_remote(address, sizeof(address));
				snprintf(cmd, sizeof(cmd), "sed -ir 's/remote .* (.+)/remote %s \\1/' %s", address, file_path);
				system(cmd);
			}
		}
	}
}

static void _ovpn_client_foreign_option_handler(int unit)
{
	char env[32] = "foreign_option_XXX";
	char* foreign_option_x = NULL;
	int i = 1;
	char resolv_path[128];
	char server_path[128];
	FILE* fp;

	snprintf(resolv_path, sizeof(resolv_path), "%s/client%d/resolv.conf", OVPN_DIR_CONF, unit);
	snprintf(server_path, sizeof(server_path), "%s/client%d/resolv.dnsmasq", OVPN_DIR_CONF, unit);
	unlink(resolv_path);
	unlink(server_path);

	while(1)
	{
		snprintf(env, sizeof(env), "foreign_option_%d", i++);
		foreign_option_x = getenv(env);
		if(!foreign_option_x)
			break;
		else
		{
			if( !strncmp(foreign_option_x, "dhcp-option DNS ", 16) )
			{
				fp = fopen(resolv_path, "a");
				if(fp)
				{
					fprintf(fp, "nameserver %s\n", &foreign_option_x[16]);
					fclose(fp);
				}

				fp = fopen(server_path, "a");
				if(fp)
				{
					fprintf(fp, "server=%s\n", &foreign_option_x[16]);
					fclose(fp);
				}
			}
			else if( !strncmp(foreign_option_x, "dhcp-option DOMAIN ", 19) )
			{
				fp = fopen(resolv_path, "a");
				if(fp)
				{
					fprintf(fp, "search %s\n", &foreign_option_x[19]);
					fclose(fp);
				}
			}
		}
	}

}

void ovpn_up_handler(int unit)
{
	char target_path[128];
	char link_path[128];

	_ovpn_client_foreign_option_handler(unit);

	// generate /etc/openvpn/resolv.xxx
	snprintf(target_path, sizeof(target_path), "%s/client%d/resolv.conf", OVPN_DIR_CONF, unit);
	snprintf(link_path, sizeof(link_path), "%s/resolv.conf", OVPN_DIR_CONF);
	if(f_exists(target_path))
	{
		symlink(target_path, link_path);
	}

	if(need_dnsmasq_serverfile())
	{
		snprintf(target_path, sizeof(target_path), "%s/client%d/resolv.dnsmasq", OVPN_DIR_CONF, unit);
		snprintf(link_path, sizeof(link_path), "%s/resolv.dnsmasq", OVPN_DIR_CONF);
		if(f_exists(target_path))
		{
			symlink(target_path, link_path);
		}
	}
}

void ovpn_down_handler(int unit)
{
	char path[128];

	// remove /etc/openvpn/resolv.xxx
	snprintf(path, sizeof(path), "%s/resolv.conf", OVPN_DIR_CONF);
	unlink(path);
	snprintf(path, sizeof(path), "%s/resolv.dnsmasq", OVPN_DIR_CONF);
	unlink(path);

	//TODO: check active vpn client
}
