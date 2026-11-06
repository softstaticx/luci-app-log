/*
 * log-viewer-geoip - batch GeoLite2 lookup helper for luci-app-log-viewer.
 *
 * Keeps both MaxMind databases mapped once and answers a whole batch of
 * addresses in a single process. The shell fallback in /usr/bin/flint4-geoip
 * forks mmdblookup(1) twice per address, which is too expensive for a 15 s
 * refresh loop on router-class hardware.
 *
 * Output is newline-delimited JSON, one object per address:
 *   {"ip":"1.2.3.4","country_code":"DE","country_name":"Germany",
 *    "asn":"3320","asn_organization":"Deutsche Telekom AG"}
 *
 * Missing databases, unknown addresses and invalid input all produce an object
 * rather than an error, so the caller can keep one code path.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <maxminddb.h>

#define DEFAULT_DB_DIR "/usr/share/GeoIP"
#define MAX_PATH 512
#define MAX_IP 128
#define MAX_CC 8
#define MAX_COUNTRY 128
#define MAX_ASN 16
#define MAX_ORG 256

static const char *g_db_dir = DEFAULT_DB_DIR;
static MMDB_s g_country;
static MMDB_s g_asn;
static int g_have_country;
static int g_have_asn;

static void json_write(const char *value)
{
	const unsigned char *p = (const unsigned char *) (value ? value : "");

	putchar('"');
	for (; *p; p++) {
		switch (*p) {
		case '"':
			fputs("\\\"", stdout);
			break;
		case '\\':
			fputs("\\\\", stdout);
			break;
		case '\n':
			fputs("\\n", stdout);
			break;
		case '\r':
			fputs("\\r", stdout);
			break;
		case '\t':
			fputs("\\t", stdout);
			break;
		default:
			if (*p < 0x20)
				printf("\\u%04x", *p);
			else
				putchar(*p);
		}
	}
	putchar('"');
}

static int open_database(MMDB_s *db, const char *path)
{
	return MMDB_open(path, MMDB_MODE_MMAP, db) == MMDB_SUCCESS;
}

static int copy_string(MMDB_entry_s *entry, const char *key1,
		       const char *key2, const char *key3,
		       char *out, size_t outlen)
{
	MMDB_entry_data_s data;
	int status;

	if (key3)
		status = MMDB_get_value(entry, &data, key1, key2, key3, NULL);
	else if (key2)
		status = MMDB_get_value(entry, &data, key1, key2, NULL);
	else
		status = MMDB_get_value(entry, &data, key1, NULL);

	if (status != MMDB_SUCCESS || !data.has_data ||
	    data.type != MMDB_DATA_TYPE_UTF8_STRING)
		return 0;

	if (data.data_size >= outlen)
		return 0;

	memcpy(out, data.utf8_string, data.data_size);
	out[data.data_size] = '\0';
	return 1;
}

static int copy_uint32(MMDB_entry_s *entry, const char *key,
		       char *out, size_t outlen)
{
	MMDB_entry_data_s data;

	if (MMDB_get_value(entry, &data, key, NULL) != MMDB_SUCCESS ||
	    !data.has_data || data.type != MMDB_DATA_TYPE_UINT32)
		return 0;

	snprintf(out, outlen, "%lu", (unsigned long) data.uint32);
	return 1;
}

static void lookup_and_emit(const char *ip)
{
	char cc[MAX_CC] = "";
	char country[MAX_COUNTRY] = "";
	char asn[MAX_ASN] = "";
	char org[MAX_ORG] = "";
	int gai_error = 0;
	int mmdb_error = 0;

	if (!ip || !*ip || strlen(ip) >= MAX_IP) {
		fputs("{\"ip\":", stdout);
		json_write(ip);
		fputs(",\"error\":\"invalid ip\"}\n", stdout);
		return;
	}

	if (g_have_country) {
		MMDB_lookup_result_s result =
			MMDB_lookup_string(&g_country, ip, &gai_error, &mmdb_error);

		if (gai_error != 0) {
			fputs("{\"ip\":", stdout);
			json_write(ip);
			fputs(",\"error\":\"invalid ip\"}\n", stdout);
			return;
		}
		if (result.found_entry) {
			copy_string(&result.entry, "country", "iso_code", NULL,
				    cc, sizeof(cc));
			copy_string(&result.entry, "country", "names", "en",
				    country, sizeof(country));
		}
	}

	if (g_have_asn) {
		MMDB_lookup_result_s result =
			MMDB_lookup_string(&g_asn, ip, &gai_error, &mmdb_error);

		if (gai_error == 0 && result.found_entry) {
			copy_uint32(&result.entry, "autonomous_system_number",
				    asn, sizeof(asn));
			copy_string(&result.entry, "autonomous_system_organization",
				    NULL, NULL, org, sizeof(org));
		}
	}

	fputs("{\"ip\":", stdout);
	json_write(ip);
	fputs(",\"country_code\":", stdout);
	json_write(cc);
	fputs(",\"country_name\":", stdout);
	json_write(country);
	fputs(",\"asn\":", stdout);
	json_write(asn);
	fputs(",\"asn_organization\":", stdout);
	json_write(org);
	if (g_have_country || g_have_asn)
		fputs("}\n", stdout);
	else
		fputs(",\"error\":\"no database\"}\n", stdout);
	fflush(stdout);
}

static void open_databases(void)
{
	char path[MAX_PATH];

	if (snprintf(path, sizeof(path), "%s/GeoLite2-Country.mmdb", g_db_dir) <
	    (int) sizeof(path))
		g_have_country = open_database(&g_country, path);

	if (snprintf(path, sizeof(path), "%s/GeoLite2-ASN.mmdb", g_db_dir) <
	    (int) sizeof(path))
		g_have_asn = open_database(&g_asn, path);
}

static void usage(void)
{
	fputs("usage: log-viewer-geoip [--db DIR] --batch [IP...]\n"
	      "       log-viewer-geoip [--db DIR] --json IP\n", stderr);
}

int main(int argc, char **argv)
{
	const char *ips[512];
	int count = 0;
	int i;
	int batch = 0;
	int single = 0;
	const char *json_ip = NULL;
	char line[MAX_IP];

	setvbuf(stdout, NULL, _IOLBF, 0);

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
			g_db_dir = argv[++i];
		} else if (strcmp(argv[i], "--batch") == 0) {
			batch = 1;
		} else if (strcmp(argv[i], "--json") == 0 && i + 1 < argc) {
			single = 1;
			json_ip = argv[++i];
		} else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
			usage();
			return 0;
		} else if (batch && count < (int) (sizeof(ips) / sizeof(ips[0]))) {
			ips[count++] = argv[i];
		} else {
			usage();
			return 2;
		}
	}

	if (!batch && !single) {
		usage();
		return 2;
	}

	open_databases();

	if (single) {
		lookup_and_emit(json_ip);
		return 0;
	}

	if (count == 0) {
		while (fgets(line, sizeof(line), stdin)) {
			size_t len = strlen(line);
			while (len > 0 && (line[len - 1] == '\n' ||
					   line[len - 1] == '\r' ||
					   line[len - 1] == ' ' ||
					   line[len - 1] == '\t'))
				line[--len] = '\0';
			if (len == 0 || line[0] == '#')
				continue;
			lookup_and_emit(line);
		}
		return 0;
	}

	for (i = 0; i < count; i++)
		lookup_and_emit(ips[i]);

	return 0;
}
