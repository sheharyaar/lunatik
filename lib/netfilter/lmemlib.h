#ifndef lstraux_h
#define lstraux_h

#include <lauxlib.h>
#include <lua.h>

#ifndef LUAMEMLIB_API
#define LUAMEMLIB_API LUALIB_API
#endif

#ifndef LUAMEMMOD_API
#define LUAMEMMOD_API LUAMOD_API
#endif

#define LUAMEM_TNONE 0
#define LUAMEM_TALLOC 1
#define LUAMEM_TREF 2

#define LUAMEM_ALLOC "char[]"
#define LUAMEM_REF "luamem_Ref"

typedef void (*luamem_Unref)(lua_State *L, void *mem, size_t len);

LUAMEMLIB_API void(luamem_newref)(lua_State *L);
LUAMEMLIB_API int(luamem_setref)(lua_State *L, int idx, char *mem, size_t len,
                                 luamem_Unref unref);

LUAMEMLIB_API int(luamem_type)(lua_State *L, int idx);

#define luamem_tomemory(L, I, S) (luamem_tomemoryx(L, I, S, NULL, NULL))

LUAMEMLIB_API char *(luamem_tomemoryx)(lua_State *L, int idx, size_t *len,
                                       luamem_Unref *unref, int *type);

#endif