/**
 * Lua interface to Libgcrypt.
 *
 * Copyright (C) 2016 Peter Wu <peter@lekensteyn.nl>
 * Licensed under the MIT license. See the LICENSE file for details.
 */
#include <windows.h>
#include <gcrypt.h>
#include <lua.h>
#include <lauxlib.h>
#include <intrin.h>

int luaopen_luagcrypt(lua_State* L);

/* {{{ Compatibility with older Lua */
#if LUA_VERSION_NUM == 501 && !defined(luaL_newlib)
static void
luaL_setfuncs(lua_State* L, const luaL_Reg* l, int nup)
{
    if (nup) {
        luaL_error(L, "nup == 0 is not supported by this compat function");
    }
    for (; l->name; l++) {
        lua_pushcclosure(L, l->func, 0);
        lua_setfield(L, -2, l->name);
    }
}

#define luaL_newlibtable(L,l)   lua_createtable(L, 0, sizeof(l)/sizeof*(l) - 1)
#define luaL_newlib(L,l)        (luaL_newlibtable(L,l), luaL_setfuncs(L,l,0))
#endif
#ifndef luaL_checkint
#define luaL_checkint(L,n)      ((int)luaL_checkinteger(L,n))
#endif
/* }}} */

/* {{{ Symmetric encryption */
typedef struct {
    gcry_cipher_hd_t h;
    int mode;           /* Cipher mode */
} LgcryptCipher;

/* Initializes a new gcrypt.Cipher userdata and pushes it on the stack. */
static LgcryptCipher*
lgcrypt_cipher_new(lua_State* L)
{
    LgcryptCipher* state;

    state = (LgcryptCipher*)lua_newuserdata(L, sizeof(LgcryptCipher));
    state->h = NULL;
    state->mode = 0;
    luaL_getmetatable(L, "gcrypt.Cipher");
    lua_setmetatable(L, -2);
    return state;
}

static int
lgcrypt_cipher_open(lua_State* L)
{
    int algo, mode, flags;
    LgcryptCipher* state;
    gcry_error_t err;

    algo = luaL_checkint(L, 1);
    mode = luaL_checkint(L, 2);
    flags = (unsigned int)luaL_optinteger(L, 3, 0);

    state = lgcrypt_cipher_new(L);
    state->mode = mode;

    err = gcry_cipher_open(&state->h, algo, mode, flags);
    if (err) {
        lua_pop(L, 1);
        luaL_error(L, "gcry_cipher_open() failed with %s", gcry_strerror(err));
    }
    return 1;
}

static LgcryptCipher*
getCipher(lua_State* L, int arg)
{
    return (LgcryptCipher*)luaL_checkudata(L, arg, "gcrypt.Cipher");
}

static LgcryptCipher*
checkCipher(lua_State* L, int arg)
{
    LgcryptCipher* state = getCipher(L, arg);
    if (!state->h) {
        luaL_error(L, "Called into a dead object");
    }
    return state;
}

static int
lgcrypt_cipher___gc(lua_State* L)
{
    LgcryptCipher* state = getCipher(L, 1);

    if (state->h) {
        gcry_cipher_close(state->h);
        state->h = NULL;
    }
    return 0;
}


static int
lgcrypt_cipher_setkey(lua_State* L)
{
    LgcryptCipher* state = checkCipher(L, 1);
    size_t key_len;
    const char* key = luaL_checklstring(L, 2, &key_len);
    gcry_error_t err;

    err = gcry_cipher_setkey(state->h, key, key_len);
    if (err) {
        luaL_error(L, "gcry_cipher_setkey() failed with %s", gcry_strerror(err));
    }
    return 0;
}

static int
lgcrypt_cipher_setiv(lua_State* L)
{
    LgcryptCipher* state = checkCipher(L, 1);
    size_t iv_len;
    const char* iv = luaL_checklstring(L, 2, &iv_len);
    gcry_error_t err;

    err = gcry_cipher_setiv(state->h, iv, iv_len);
    if (err) {
        luaL_error(L, "gcry_cipher_setiv() failed with %s", gcry_strerror(err));
    }
    return 0;
}

static int
lgcrypt_cipher_setctr(lua_State* L)
{
    LgcryptCipher* state = checkCipher(L, 1);
    size_t ctr_len;
    const char* ctr = luaL_checklstring(L, 2, &ctr_len);
    gcry_error_t err;

    err = gcry_cipher_setctr(state->h, ctr, ctr_len);
    if (err) {
        luaL_error(L, "gcry_cipher_setctr() failed with %s", gcry_strerror(err));
    }
    return 0;
}

static int
lgcrypt_cipher_reset(lua_State* L)
{
    LgcryptCipher* state = checkCipher(L, 1);
    gcry_error_t err;

    err = gcry_cipher_reset(state->h);
    if (err) {
        luaL_error(L, "gcry_cipher_reset() failed with %s", gcry_strerror(err));
    }
    return 0;
}

#if GCRYPT_VERSION_NUMBER >= 0x010600 /* 1.6.0 */
static int
lgcrypt_cipher_authenticate(lua_State* L)
{
    LgcryptCipher* state = checkCipher(L, 1);
    size_t abuf_len;
    const char* abuf = luaL_checklstring(L, 2, &abuf_len);
    gcry_error_t err;

    err = gcry_cipher_authenticate(state->h, abuf, abuf_len);
    if (err) {
        luaL_error(L, "gcry_cipher_authenticate() failed with %s", gcry_strerror(err));
    }
    return 0;
}

/* Libgcrypt 1.6.5 has some quirks
 * https://lists.gnupg.org/pipermail/gcrypt-devel/2016-March/003754.html */
static size_t
get_tag_length(LgcryptCipher* state)
{
#if GCRYPT_VERSION_NUMBER >= 0x010700 /* 1.7.0 */
    size_t nbytes = 0;
    gcry_error_t err;

    err = gcry_cipher_info(state->h, GCRYCTL_GET_TAGLEN, NULL, &nbytes);
    return !err ? nbytes : 0;
#else
    return state->mode == GCRY_CIPHER_MODE_GCM ? 16 : 0;
#endif
}

static int
lgcrypt_cipher_gettag(lua_State* L)
{
    LgcryptCipher* state = checkCipher(L, 1);
    char tag[16];
    size_t tag_len;
    gcry_error_t err;

    tag_len = get_tag_length(state);
    if (tag_len == 0) {
        luaL_error(L, "Unsupported cipher mode");
    }
    err = gcry_cipher_gettag(state->h, tag, tag_len);
    if (err) {
        luaL_error(L, "gcry_cipher_gettag() failed with %s", gcry_strerror(err));
    }
    lua_pushlstring(L, tag, tag_len);
    return 1;
}

static int
lgcrypt_cipher_checktag(lua_State* L)
{
    LgcryptCipher* state = checkCipher(L, 1);
    size_t tag_len;
    const char* tag = luaL_checklstring(L, 2, &tag_len);
    gcry_error_t err;

    err = gcry_cipher_checktag(state->h, tag, tag_len);
    if (err) {
        luaL_error(L, "gcry_cipher_checktag() failed with %s", gcry_strerror(err));
    }
    return 0;
}
#endif

static int
lgcrypt_cipher_encrypt(lua_State* L)
{
    LgcryptCipher* state = checkCipher(L, 1);
    size_t in_len, out_len;
    const char* in;
    char* out;
    gcry_error_t err;

    in = luaL_checklstring(L, 2, &in_len);

    out_len = in_len;
    out = lua_newuserdata(L, out_len);
    err = gcry_cipher_encrypt(state->h, out, out_len, in, in_len);
    if (err) {
        luaL_error(L, "gcry_cipher_encrypt() failed with %s", gcry_strerror(err));
    }
    lua_pushlstring(L, out, out_len);
    lua_remove(L, -2);
    return 1;
}

static int
lgcrypt_cipher_decrypt(lua_State* L)
{
    LgcryptCipher* state = checkCipher(L, 1);
    size_t in_len, out_len;
    const char* in;
    char* out;
    gcry_error_t err;

    in = luaL_checklstring(L, 2, &in_len);

    out_len = in_len;
    out = lua_newuserdata(L, out_len);
    err = gcry_cipher_decrypt(state->h, out, out_len, in, in_len);
    if (err) {
        luaL_error(L, "gcry_cipher_decrypt() failed with %s", gcry_strerror(err));
    }
    lua_pushlstring(L, out, out_len);
    lua_remove(L, -2);
    return 1;
}


/* https://gnupg.org/documentation/manuals/gcrypt/Working-with-cipher-handles.html */
static const struct luaL_Reg lgcrypt_cipher_meta[] = {
    {"__gc",            lgcrypt_cipher___gc},
    {"setkey",          lgcrypt_cipher_setkey},
    {"setiv",           lgcrypt_cipher_setiv},
    {"setctr",          lgcrypt_cipher_setctr},
    {"reset",           lgcrypt_cipher_reset},
#if GCRYPT_VERSION_NUMBER >= 0x010600 /* 1.6.0 */
    {"authenticate",    lgcrypt_cipher_authenticate},
    {"gettag",          lgcrypt_cipher_gettag},
    {"checktag",        lgcrypt_cipher_checktag},
#endif
    {"encrypt",         lgcrypt_cipher_encrypt},
    {"decrypt",         lgcrypt_cipher_decrypt},
    {NULL,              NULL}
};
/* }}} */
/* {{{ Message digests */
typedef struct {
    gcry_md_hd_t h;
} LgcryptHash;

/* Initializes a new gcrypt.Hash userdata and pushes it on the stack. */
static LgcryptHash*
lgcrypt_hash_new(lua_State* L)
{
    LgcryptHash* state;

    state = (LgcryptHash*)lua_newuserdata(L, sizeof(LgcryptHash));
    state->h = NULL;
    luaL_getmetatable(L, "gcrypt.Hash");
    lua_setmetatable(L, -2);
    return state;
}

static int
lgcrypt_hash_open(lua_State* L)
{
    int algo;
    unsigned int flags;
    LgcryptHash* state;
    gcry_error_t err;

    algo = luaL_checkint(L, 1);
    flags = (unsigned int)luaL_optinteger(L, 2, 0);

    state = lgcrypt_hash_new(L);

    err = gcry_md_open(&state->h, algo, flags);
    if (err) {
        lua_pop(L, 1);
        luaL_error(L, "gcry_md_open() failed with %s", gcry_strerror(err));
    }
    return 1;
}

static LgcryptHash*
getHash(lua_State* L, int arg)
{
    return (LgcryptHash*)luaL_checkudata(L, arg, "gcrypt.Hash");
}

static LgcryptHash*
checkHash(lua_State* L, int arg)
{
    LgcryptHash* state = getHash(L, arg);
    if (!state->h) {
        luaL_error(L, "Called into a dead object");
    }
    return state;
}

static int
lgcrypt_hash___gc(lua_State* L)
{
    LgcryptHash* state = getHash(L, 1);

    if (state->h) {
        gcry_md_close(state->h);
        state->h = NULL;
    }
    return 0;
}


static int
lgcrypt_hash_setkey(lua_State* L)
{
    LgcryptHash* state = checkHash(L, 1);
    size_t key_len;
    const char* key = luaL_checklstring(L, 2, &key_len);
    gcry_error_t err;

    err = gcry_md_setkey(state->h, key, key_len);
    if (err) {
        luaL_error(L, "gcry_md_setkey() failed with %s", gcry_strerror(err));
    }
    return 0;
}

static int
lgcrypt_hash_reset(lua_State* L)
{
    LgcryptHash* state = checkHash(L, 1);
    gcry_md_reset(state->h);
    return 0;
}

static int
lgcrypt_hash_write(lua_State* L)
{
    LgcryptHash* state = checkHash(L, 1);
    size_t buffer_len;
    const char* buffer = luaL_checklstring(L, 2, &buffer_len);

    gcry_md_write(state->h, buffer, buffer_len);
    return 0;
}

static int
lgcrypt_hash_read(lua_State* L)
{
    LgcryptHash* state = checkHash(L, 1);
    unsigned char* digest;
    size_t digest_len;
    int algo;

    algo = (int)luaL_optinteger(L, 2, gcry_md_get_algo(state->h));
    if (!gcry_md_is_enabled(state->h, algo)) {
        luaL_error(L, "Unable to obtain digest for a disabled algorithm");
    }

    digest_len = gcry_md_get_algo_dlen(algo);
    if (!digest_len) {
        luaL_error(L, "Invalid digest length detected");
    }
    digest = gcry_md_read(state->h, algo);
    if (!digest) {
        luaL_error(L, "Failed to obtain digest");
    }
    lua_pushlstring(L, (const char*)digest, digest_len);
    return 1;
}



/* https://gnupg.org/documentation/manuals/gcrypt/Working-with-hash-algorithms.html */
static const struct luaL_Reg lgcrypt_hash_meta[] = {
    {"__gc",    lgcrypt_hash___gc},
    {"setkey",  lgcrypt_hash_setkey},
    {"reset",   lgcrypt_hash_reset},
    {"write",   lgcrypt_hash_write},
    {"read",    lgcrypt_hash_read},
    {NULL,      NULL}
};
/* }}} */

static int
lgcrypt_init(lua_State* L)
{
    if (gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
        luaL_error(L, "Libgcrypt was already initialized");
    }
    gcry_check_version(NULL);
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    return 0;
}

static int
lgcrypt_check_version(lua_State* L)
{
    const char* req_version, * version;

    req_version = luaL_optstring(L, 1, NULL);
    version = gcry_check_version(req_version);
    lua_pushstring(L, version);
    return 1;
}

static const struct luaL_Reg lgcrypt[] = {
    {"init",            lgcrypt_init},
    {"check_version",   lgcrypt_check_version},
    {"Cipher",          lgcrypt_cipher_open},
    {"Hash",            lgcrypt_hash_open},
    {NULL, NULL}
};

static void
register_metatable(lua_State* L, const char* name, const struct luaL_Reg* funcs)
{
    luaL_newmetatable(L, name);
    luaL_setfuncs(L, funcs, 0);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    lua_pop(L, 1);
}

int
luaopen_luagcrypt(lua_State* L)
{
    register_metatable(L, "gcrypt.Cipher", lgcrypt_cipher_meta);
    register_metatable(L, "gcrypt.Hash", lgcrypt_hash_meta);

    luaL_newlib(L, lgcrypt);

#define INT_GCRY(name) do { \
    lua_pushinteger(L, GCRY_ ## name); \
    lua_setfield(L, -2, #name); \
    } while (0)

    /* Add constants for gcrypt.Cipher */
    /* https://gnupg.org/documentation/manuals/gcrypt/Available-ciphers.html */
    INT_GCRY(CIPHER_IDEA);
    INT_GCRY(CIPHER_3DES);
    INT_GCRY(CIPHER_CAST5);
    INT_GCRY(CIPHER_BLOWFISH);
    /* GCRY_CIPHER_AES and GCRY_CIPHER_RIJNDAEL* are redundant, do not expose
     * them for now. */
    INT_GCRY(CIPHER_AES128);
    INT_GCRY(CIPHER_AES192);
    INT_GCRY(CIPHER_AES256);
    INT_GCRY(CIPHER_TWOFISH);
    INT_GCRY(CIPHER_TWOFISH128);
    INT_GCRY(CIPHER_ARCFOUR);
    INT_GCRY(CIPHER_DES);
    INT_GCRY(CIPHER_SERPENT128);
    INT_GCRY(CIPHER_SERPENT192);
    INT_GCRY(CIPHER_SERPENT256);
    INT_GCRY(CIPHER_RFC2268_40);
    INT_GCRY(CIPHER_RFC2268_128);
    INT_GCRY(CIPHER_SEED);
    INT_GCRY(CIPHER_CAMELLIA128);
    INT_GCRY(CIPHER_CAMELLIA192);
    INT_GCRY(CIPHER_CAMELLIA256);
#if GCRYPT_VERSION_NUMBER >= 0x010600 /* 1.6.0 */
    INT_GCRY(CIPHER_SALSA20);
    INT_GCRY(CIPHER_SALSA20R12);
    INT_GCRY(CIPHER_GOST28147);
#endif
#if GCRYPT_VERSION_NUMBER >= 0x010700 /* 1.7.0 */
    INT_GCRY(CIPHER_CHACHA20);
#endif

    /* https://gnupg.org/documentation/manuals/gcrypt/Available-cipher-modes.html */
    INT_GCRY(CIPHER_MODE_ECB);
    INT_GCRY(CIPHER_MODE_CFB);
    INT_GCRY(CIPHER_MODE_CBC);
    INT_GCRY(CIPHER_MODE_STREAM);
    INT_GCRY(CIPHER_MODE_OFB);
    INT_GCRY(CIPHER_MODE_CTR);
#if GCRYPT_VERSION_NUMBER >= 0x010500 /* 1.5.0 */
    INT_GCRY(CIPHER_MODE_AESWRAP);
#endif
#if GCRYPT_VERSION_NUMBER >= 0x010600 /* 1.6.0 */
    INT_GCRY(CIPHER_MODE_CCM);
    INT_GCRY(CIPHER_MODE_GCM);
#endif
#if GCRYPT_VERSION_NUMBER >= 0x010700 /* 1.7.0 */
    INT_GCRY(CIPHER_MODE_POLY1305);
    INT_GCRY(CIPHER_MODE_OCB);
    INT_GCRY(CIPHER_MODE_CFB8);
#endif

    INT_GCRY(CIPHER_CBC_CTS);

    /* https://gnupg.org/documentation/manuals/gcrypt/Available-hash-algorithms.html */
    INT_GCRY(MD_SHA1);
    INT_GCRY(MD_RMD160);
    INT_GCRY(MD_MD5);
    INT_GCRY(MD_MD4);
    INT_GCRY(MD_TIGER);
#if GCRYPT_VERSION_NUMBER >= 0x010500 /* 1.5.0 */
    INT_GCRY(MD_TIGER1);
    INT_GCRY(MD_TIGER2);
#endif
    INT_GCRY(MD_SHA224);
    INT_GCRY(MD_SHA256);
    INT_GCRY(MD_SHA384);
    INT_GCRY(MD_SHA512);
    INT_GCRY(MD_CRC32);
    INT_GCRY(MD_CRC32_RFC1510);
    INT_GCRY(MD_CRC24_RFC2440);
    INT_GCRY(MD_WHIRLPOOL);
#if GCRYPT_VERSION_NUMBER >= 0x010600 /* 1.6.0 */
    INT_GCRY(MD_GOSTR3411_94);
    INT_GCRY(MD_STRIBOG256);
    INT_GCRY(MD_STRIBOG512);
#endif
#if GCRYPT_VERSION_NUMBER >= 0x010700 /* 1.7.0 */
    INT_GCRY(MD_GOSTR3411_CP);
    INT_GCRY(MD_SHA3_224);
    INT_GCRY(MD_SHA3_256);
    INT_GCRY(MD_SHA3_384);
    INT_GCRY(MD_SHA3_512);
    INT_GCRY(MD_SHAKE128);
    INT_GCRY(MD_SHAKE256);
#endif

    INT_GCRY(MD_FLAG_HMAC);
#undef INT_GCRY

    return 1;
}




BOOL APIENTRY  DllMain(
	HINSTANCE hinstDLL,  // handle to DLL module
	DWORD fdwReason,     // reason for calling function
	LPVOID lpvReserved)  // reserved
{
    //__debugbreak();
	// Perform actions based on the reason for calling.
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		// Initialize once for each new process.
		// Return FALSE to fail DLL load.
		break;

	case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
		break;

	case DLL_THREAD_DETACH:
		// Do thread-specific cleanup.
		break;

	case DLL_PROCESS_DETACH:

		

		// Perform any necessary cleanup.
		break;
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH.
}