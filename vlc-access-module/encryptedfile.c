#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#define fseek64 fseek
#define ftell64 ftell

#include "xtslib.h"

#include <vlc_common.h>
#include <vlc_plugin.h>

#include <assert.h>

#include <vlc_access.h>
#include <vlc_dialog.h>
#include <vlc_network.h>
#include <vlc_url.h>

#include <stdio.h>

#define AES_128_KEY_LEN_BYTES 32
#define AES_256_KEY_LEN_BYTES 64

static int  Open(vlc_object_t*);
static void Close(vlc_object_t*);
static ssize_t Read(access_t *, uint8_t *, size_t);
static int Seek(access_t *, uint64_t);
static int Control(access_t *, int, va_list);

static int initialized_xts_lib = 0;

vlc_module_begin()
	set_shortname("FileBrowser-Encrypted")
	set_description(N_("FileBrowser App AES Encrypted Input"))
	set_capability("access", 60)
	set_category(CAT_INPUT)
	set_subcategory(SUBCAT_INPUT_ACCESS)
	add_shortcut("encrypted")
	set_callbacks(Open, Close)
vlc_module_end ()

struct access_sys_t {
	FILE *file;
	CIPHER_CONTEXT *cipher_ctx;
	unsigned char *sector_buffer;
	unsigned char *temp_buffer;
	unsigned int buffer_pos;
	unsigned int buffer_use;
	unsigned int sector_size;
	uint64_t sector_number;
	uint64_t filesize;
};

static int hex2data(unsigned char *data, const char *hexstring, unsigned int len) {
	const char *pos = hexstring;
	char *endptr;
	size_t count = 0;

	if ((hexstring[0] == '\0') || (strlen(hexstring) % 2)) {
		return -1;
	}

	for(count = 0; count < len; count++) {
		char buf[5] = {'0', 'x', pos[0], pos[1], 0};
		data[count] = strtol(buf, &endptr, 0);
		pos += 2 * sizeof(char);

		if (endptr[0] != '\0') {
			return -1;
		}
	}
	return 0;
}

static int ReadSector(access_sys_t *p_sys, uint64_t sector_number) {
	if (feof(p_sys->file)) {
		return -1;
	}

	int rlen = fread(p_sys->temp_buffer, 1, p_sys->sector_size, p_sys->file);
	xts_decrypt_buffer(p_sys->cipher_ctx, p_sys->temp_buffer, p_sys->sector_buffer, rlen, sector_number);
	p_sys->buffer_use = rlen;
	p_sys->buffer_pos = 0;
	p_sys->sector_number = sector_number;
	return rlen;
}

static int Open(vlc_object_t* p_this) {
	access_t *p_access = (access_t*)p_this;
	access_sys_t *p_sys;
	char *file_path = NULL;
	unsigned char *key = NULL;
	int key_len = -1;
	int sector_size = 0;
	char *tok = NULL;
	char *temp_string = NULL;

	const char* raw_mrl = p_access->psz_location;

	msg_Dbg(p_access, "MRL IS %s", raw_mrl);

	if(!raw_mrl) {
		msg_Err(p_access, "invalid encrypted URI: encrypted://%s", raw_mrl);
		return VLC_EGENERIC;
	}

	// MRL Syntax: encrypted://file_path|aes_key|sector_size;
	temp_string = strdup(raw_mrl);
	tok = temp_string;
	while ((tok = strtok(tok, "|")) != NULL) {
		if (file_path == NULL) {
			file_path = tok;
		} else if (key == NULL) {
			key_len = strlen(tok) / 2;
			if (key_len != AES_128_KEY_LEN_BYTES && key_len != AES_256_KEY_LEN_BYTES) {
				msg_Err(p_access, "key length is %d, should be 256 bits for AES 128, 512 bits for AES_256.", key_len);
				goto error;
			}
			key = (unsigned char*)malloc(sizeof(unsigned char) * key_len);
			int res = hex2data(key, tok, key_len);
			if (res == -1) {
				msg_Err(p_access, "Error parsing key.");
				goto error;
			}
		} else {
			sector_size = atoi(tok);
		}
		tok = NULL;
	}

	msg_Dbg(p_access, "File Path %s", file_path);
	msg_Dbg(p_access, "Sector Size %d", sector_size);

	if (EMPTY_STR(file_path)) {
		msg_Err(p_access, "missing file path.");
		goto error;
	}
	if (key_len == -1) {
		msg_Err(p_access, "missing key.");
		goto error;
	}
	if (sector_size == 0) {
		msg_Err(p_access, "missing sector size.");
		goto error;
	}

	STANDARD_READ_ACCESS_INIT;

	p_sys->file = fopen(file_path, "r");
	if (p_sys->file == NULL) {
		msg_Err(p_access, "error opening encrypted file: %s", raw_mrl);
		goto error;
	}

	p_sys->sector_size = sector_size;

	AES_MODE aes_mode;
	if (key_len == AES_128_KEY_LEN_BYTES) {
		msg_Dbg(p_access, "Key is AES 128");
		aes_mode = AES_128;
	} else {
		msg_Dbg(p_access, "Key is AES 256");
		aes_mode = AES_256;
	}

	if (!initialized_xts_lib) {
		xts_init_library();
		initialized_xts_lib = 1;
	}

	p_sys->cipher_ctx = xts_new_cipher_context(aes_mode, key);
	p_sys->sector_buffer = (unsigned char*)calloc(p_sys->sector_size, 1);
	p_sys->temp_buffer = (unsigned char*)calloc(p_sys->sector_size, 1);

	fseek(p_sys->file, 0L, SEEK_END);
	p_sys->filesize = ftell64(p_sys->file);
	fseek(p_sys->file, 0L, SEEK_SET);

	ReadSector(p_sys, 0);

	free(temp_string);
	free(key);

	return VLC_SUCCESS;

error:
	if (temp_string != NULL) {
		free(temp_string);
	}
	if (key != NULL) {
		free(key);
	}
	return VLC_EGENERIC;
}

static void Close(vlc_object_t* p_this) {
	access_t *p_access = (access_t*)p_this;
	access_sys_t *p_sys = p_access->p_sys;

	fclose(p_sys->file);

	xts_free_cipher_context(p_sys->cipher_ctx);
	free(p_sys->sector_buffer);
	free(p_sys->temp_buffer);

	free(p_sys);
}

static int Seek(access_t* p_access, uint64_t i_pos) {
	access_sys_t *p_sys = p_access->p_sys;

	uint64_t closest_sector = i_pos / p_sys->sector_size;
	uint64_t sector_offset = closest_sector * p_sys->sector_size;
	uint64_t position_in_sector = i_pos % p_sys->sector_size;

	int ret = fseek64(p_sys->file, sector_offset, SEEK_SET);
	if (ret) {
		msg_Err(p_access, "seek failed");
		return VLC_EGENERIC;
	}

	ReadSector(p_sys, closest_sector);
	p_sys->buffer_pos = position_in_sector;

	p_access->info.b_eof = false;

	return VLC_SUCCESS;
}

static ssize_t Read(access_t *p_access, uint8_t *p_buffer, size_t i_len) {
	access_sys_t *p_sys = p_access->p_sys;

	size_t remaining = i_len;
	size_t out_buffer_position = 0;

	while (remaining > 0) {
		unsigned int remaining_buffer = p_sys->buffer_use - p_sys->buffer_pos;
		size_t bytes_to_copy = remaining < remaining_buffer ? remaining : remaining_buffer;

		memcpy(p_buffer + out_buffer_position, p_sys->sector_buffer + p_sys->buffer_pos, bytes_to_copy);
		p_sys->buffer_pos += bytes_to_copy;
		out_buffer_position += bytes_to_copy;
		remaining -= bytes_to_copy;

		if (p_sys->buffer_pos == p_sys->buffer_use) {
			int actual_read = ReadSector(p_sys, p_sys->sector_number + 1);
			if (actual_read < 0) { // eof
				break;
			}
		}
	}

	return out_buffer_position;
}

static int Control(access_t* p_access, int i_query, va_list args) {
	bool* pb_bool;
	int64_t* pi_64;

	switch(i_query) {
	case ACCESS_CAN_SEEK:
	case ACCESS_CAN_FASTSEEK:
	case ACCESS_CAN_PAUSE:
	case ACCESS_CAN_CONTROL_PACE:
		pb_bool = (bool*)va_arg(args, bool*);
		*pb_bool = true;
		break;

	case ACCESS_GET_SIZE:
		*va_arg(args, uint64_t *) = p_access->p_sys->filesize;
		break;

	case ACCESS_GET_PTS_DELAY:
		pi_64 = (int64_t*)va_arg(args, int64_t *);
		*pi_64 = var_InheritInteger(p_access, "file-caching");
		*pi_64 *= 1000;
		break;

	case ACCESS_SET_PAUSE_STATE:
		break;

	default:
		return VLC_EGENERIC;
	}

	return VLC_SUCCESS;
}

