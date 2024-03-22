#define lmemlib_c

#define LUAMEMLIB_API

#include "lmemlib.h"

#ifndef _KERNEL
#include <string.h>
#else
#include <linux/string.h>
#endif /* _KERNEL */

typedef struct luamem_Ref {
	char *mem;
	size_t len;
	luamem_Unref unref;
} luamem_Ref;

#define unref(L,r)	if (r->unref) ref->unref(L, r->mem, r->len)

static int luaunref (lua_State *L) {
	luamem_Ref *ref = (luamem_Ref *)luaL_testudata(L, 1, LUAMEM_REF);
	if (ref) unref(L, ref);
	return 0;
}

LUAMEMLIB_API void luamem_newref(lua_State *L) {
    luamem_Ref *ref = (luamem_Ref *)lua_newuserdata(L, sizeof(luamem_Ref));
    ref->mem = NULL;
    ref->len = 0;
    ref->unref = NULL;
    if (luaL_newmetatable(L, LUAMEM_REF)) {
        lua_pushcfunction(L, luaunref);
        lua_setfield(L, -2, "__gc");
    }
    lua_setmetatable(L, -2);
}

LUAMEMLIB_API int luamem_setref (lua_State *L, int idx, 
                                 char *mem, size_t len, luamem_Unref unref) {
	luamem_Ref *ref = (luamem_Ref *)luaL_testudata(L, idx, LUAMEM_REF);
	if (ref) {
		if (mem != ref->mem) {
			unref(L, ref);
			ref->mem = mem;
		}
		ref->len = len;
		ref->unref = unref;
		return 1;
	}
	return 0;
}

LUAMEMLIB_API int luamem_type (lua_State *L, int idx) {
	int type = LUAMEM_TNONE;
	if (lua_type(L, idx) == LUA_TUSERDATA) {
		if (lua_getmetatable(L, idx)) {  /* does it have a metatable? */
			luaL_getmetatable(L, LUAMEM_ALLOC);  /* get allocated memory metatable */
			if (lua_rawequal(L, -1, -2)) type = LUAMEM_TALLOC;
			else {
				lua_pop(L, 1);  /* remove allocated memory metatable */
				luaL_getmetatable(L, LUAMEM_REF);  /* get referenced memory metatable */
				if (lua_rawequal(L, -1, -2)) type = LUAMEM_TREF;
			}
			lua_pop(L, 2);  /* remove both metatables */
		}
	}
	return type;
}

LUAMEMLIB_API char *luamem_tomemoryx (lua_State *L, int idx,
                                      size_t *len, luamem_Unref *unref,
                                      int *type) {
	int typemem;
	if (!type) type = &typemem;
	*type = luamem_type(L, idx);
	switch (*type) {
		case LUAMEM_TALLOC:
			if (len) *len = lua_rawlen(L, idx);
			if (unref) *unref = NULL;
			return (char *)lua_touserdata(L, idx);
		case LUAMEM_TREF: {
			luamem_Ref *ref = (luamem_Ref *)lua_touserdata(L, idx);
			if (len) *len = ref->len;
			if (unref) *unref = ref->unref;
			return ref->mem;
		}
	}
	if (len) *len = 0;
	if (unref) *unref = NULL;
	return NULL;
}
