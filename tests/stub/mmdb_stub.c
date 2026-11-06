/*
 * Test stub for libmaxminddb, used only by the local build check for
 * src/log-viewer-geoip.c. It implements the handful of entry points the helper
 * uses and returns canned data so the JSON writer and argument handling can be
 * exercised without a real .mmdb file.
 */
#include <maxminddb.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int valid_ipv4(const char *ip)
{
	int parts = 0;
	int value = 0;
	int digits = 0;
	const char *p = ip;

	for (;; p++) {
		if (*p >= '0' && *p <= '9') {
			value = value * 10 + (*p - '0');
			digits++;
			if (value > 255 || digits > 3)
				return 0;
		} else if (*p == '.' || *p == '\0') {
			if (!digits)
				return 0;
			parts++;
			value = 0;
			digits = 0;
			if (*p == '\0')
				break;
		} else {
			return 0;
		}
	}
	return parts == 4;
}

int MMDB_open(const char *const filename, uint32_t flags, MMDB_s *const mmdb)
{
	FILE *file = fopen(filename, "rb");

	if (!file)
		return MMDB_FILE_OPEN_ERROR;

	fclose(file);
	memset(mmdb, 0, sizeof(*mmdb));
	mmdb->flags = flags;
	return MMDB_SUCCESS;
}

void MMDB_close(MMDB_s *const mmdb)
{
	(void) mmdb;
}

const char *MMDB_strerror(int code)
{
	(void) code;
	return "stub";
}

MMDB_lookup_result_s MMDB_lookup_string(const MMDB_s *const mmdb,
					const char *const ipstr,
					int *const gai_error,
					int *const mmdb_error)
{
	MMDB_lookup_result_s result;

	memset(&result, 0, sizeof(result));
	*gai_error = 0;
	*mmdb_error = 0;

	if (!valid_ipv4(ipstr) && strchr(ipstr, ':') == NULL) {
		*gai_error = 1;
		return result;
	}

	result.found_entry = true;
	result.entry.mmdb = mmdb;
	return result;
}

static void set_string(MMDB_entry_data_s *data, const char *value)
{
	data->has_data = true;
	data->type = MMDB_DATA_TYPE_UTF8_STRING;
	data->utf8_string = value;
	data->data_size = (uint32_t) strlen(value);
}

int MMDB_get_value(MMDB_entry_s *const start, MMDB_entry_data_s *const entry_data,
		   ...)
{
	va_list ap;
	const char *keys[3] = { NULL, NULL, NULL };
	int i;

	(void) start;
	memset(entry_data, 0, sizeof(*entry_data));

	va_start(ap, entry_data);
	for (i = 0; i < 3; i++) {
		keys[i] = va_arg(ap, const char *);
		if (!keys[i])
			break;
	}
	va_end(ap);

	if (keys[0] && keys[1] && !keys[2] && strcmp(keys[0], "country") == 0 &&
	    strcmp(keys[1], "iso_code") == 0) {
		set_string(entry_data, "DE");
		return MMDB_SUCCESS;
	}
	if (keys[0] && keys[1] && keys[2] && strcmp(keys[0], "country") == 0 &&
	    strcmp(keys[1], "names") == 0 && strcmp(keys[2], "en") == 0) {
		set_string(entry_data, "Germany \"quoted\"");
		return MMDB_SUCCESS;
	}
	if (keys[0] && !keys[1] &&
	    strcmp(keys[0], "autonomous_system_number") == 0) {
		entry_data->has_data = true;
		entry_data->type = MMDB_DATA_TYPE_UINT32;
		entry_data->uint32 = 3320;
		return MMDB_SUCCESS;
	}
	if (keys[0] && !keys[1] &&
	    strcmp(keys[0], "autonomous_system_organization") == 0) {
		set_string(entry_data, "Deutsche Telekom AG");
		return MMDB_SUCCESS;
	}

	return MMDB_SUCCESS;
}
