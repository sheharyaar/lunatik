/*
 * Copyright (c) 2023 ring-0 Ltda.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <lauxlib.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/version.h>
#include <lua.h>
#include <lualib.h>
#include <lunatik.h>

#define NFLUA_NAME_MAXSIZE 64        /* Max length of Lua state name  */
#define NFLUA_SCRIPTNAME_MAXSIZE 255 /* Max length of Lua state name  */

typedef struct luaxt_s {
    lunatik_object_t *runtime;
    // What data need to be stored in the module ??
} luaxt_t;

struct xt_lua_mtinfo {
    // What data needs to be passed on through the match functions ??
    luaxt_t *state;
};

static bool nflua_user_ops(lua_State *L, luaxt_t *state,
                           const struct sk_buff *skb) {
    // sample error code
    int ret = false;
    int nargs = 1; /* skb_buff */

    // call the user defined function
    if (lunatik_getregistry(L, state) != LUA_TFUNCTION) {
        pr_err("could not find luaxt callback\n");
        goto err;
    }

    lua_pushlightuserdata(L, skb);
    if (lua_pcall(L, nargs, 1, 0) != LUA_OK) { /* callback(event, ...) */
        pr_err("%s\n", lua_tostring(L, -1));
        goto err;
    }

    ret = lua_toboolean(L, -1);
    pr_warn("nflua_user_ops: %d\n", ret);
err:
    return ret;
}

static int nflua_mt_checkentry(const struct xt_mtchk_param *par) {
    pr_warn("nflua_mt_checkentry\n");
    return 0;
}

static void nflua_mt_destroy(const struct xt_mtdtor_param *par) {
    // destroy
    pr_warn("nflua_mt_destroy\n");
}

static bool nflua_match(const struct sk_buff *skb,
                        struct xt_action_param *par) {
    pr_warn("nflua_match\n");

    int ret;
    struct xt_lua_mtinfo *info = par->matchinfo;
    lunatik_run(info->state->runtime, nflua_user_ops, ret, info->state, skb);

    return ret;
}

static int luaxt_new(lua_State *L);

static void luaxt_release(void *private) {
    luaxt_t *skel = (luaxt_t *)private;
    (void)skel; /* do nothing */
}

// this will be called as xt.new
static const luaL_Reg luaxt_lib[] = {{"new", luaxt_new}, {NULL, NULL}};

// this will be called as xt:match
static const luaL_Reg luaxt_mt[] = {{"__gc", lunatik_deleteobject},
                                    {NULL, NULL}};

static struct xt_match nflua_mt_reg __read_mostly = {
    .name = "lua",
    .revision = 0,
    .family = NFPROTO_UNSPEC,
    .match = nflua_match,
    .checkentry = nflua_mt_checkentry,
    .destroy = nflua_mt_destroy,
    .matchsize = sizeof(struct xt_lua_mtinfo),
#if 0
    .usersize = offsetof(struct xt_lua_mtinfo, state),
#endif
    .me = THIS_MODULE};

static const lunatik_class_t luaxt_class = {
    .name = "xt",
    .methods = luaxt_mt,
    .release = luaxt_release,
    .sleep = true,
};

static int luaxt_new(lua_State *L) {
    luaL_checktype(L, 1, LUA_TTABLE); /* xt callbacks */

    lunatik_object_t *object =
        lunatik_newobject(L, &luaxt_class, sizeof(luaxt_t));
    luaxt_t *xt = (luaxt_t *)object->private;

    memset(xt, 0, sizeof(luaxt_t));

    xt->runtime = lunatik_toruntime(L);
    lunatik_getobject(xt->runtime);

    /* handle netfilter stuff */
    lunatik_registerobject(L, 1, object);
    return 1;
}

LUNATIK_NEWLIB(xt, luaxt_lib, &luaxt_class, NULL);

static int __init luaxt_init(void) {
    pr_warn("loading xt module\n");
    return xt_register_match(&nflua_mt_reg);
}

static void __exit luaxt_exit(void) {
    pr_warn("unloading xt module\n");
    xt_unregister_match(&nflua_mt_reg);
}

module_init(luaxt_init);
module_exit(luaxt_exit);
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>");
