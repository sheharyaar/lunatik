/*
 * Copyright (C) 2017-2019  CUJO LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/netfilter/x_tables.h>
#include <linux/printk.h>
#include <linux/version.h>
#include <lua.h>
#include <lunatik.h>
#include <net/netns/generic.h>

#include "netfilter/kpi_compat.h"
#include "netfilter/luapacket.h"
#include "netfilter/luautil.h"
#include "netfilter/netlink.h"
#include "netfilter/nf_util.h"
#include "netfilter/states.h"
#include "netfilter/xt_lua.h"
#include "netfilter/xt_lua_common.h"

extern int xt_lua_net_id;

typedef struct luanetfilter_s {
    lunatik_object_t *runtime;
    bool match_registered;
    bool target_registered;
} luanetfilter_t;

static void nflua_mt_destroy(const struct xt_mtdtor_param *par) {
    struct xt_lua_mtinfo *info = par->matchinfo;

    if (info->state != NULL) nflua_state_put(info->state);
}

static int nflua_mt_checkentry(const struct xt_mtchk_param *par) {
    struct xt_lua_mtinfo *info = par->matchinfo;
    struct nflua_state *s;

    if ((s = nflua_state_lookup(xt_lua_pernet(par->net), info->name)) == NULL)
        return -EPERM;

    if (!nflua_state_get(s)) return -ESTALE;

    info->state = s;
    return 0;
}

enum mode { NFLUA_MATCH, NFLUA_TARGET };

static int nflua_docall(lua_State *L) {
    const char *func = lua_touserdata(L, 1);
    struct sk_buff *skb = lua_touserdata(L, 2);
    int hooknum = lua_tointeger(L, 3);
    int mode = lua_tointeger(L, 4);
    int error;

    lua_settop(L, 0);

    luapacket_new(L, skb, hooknum);

    if (lua_getglobal(L, func) != LUA_TFUNCTION)
        return luaL_error(L, "couldn't find function: %s\n", func);

    lua_pushvalue(L, 1);
    error = lua_pcall(L, 1, 1, 0);

    if (mode == NFLUA_TARGET && lua_isstring(L, -1) &&
        strcmp(lua_tostring(L, -1), "stolen") == 0)
        luapacket_stolen(L, 1);
    else
        luapacket_unref(L, 1);

    if (error) return lua_error(L);

    return 1;
}

static unsigned int string_to_tg(const char *s) {
    struct target_pair {
        const char *k;
        int v;
    };
    static struct target_pair targets[] = {
        {"drop", NF_DROP},   {"accept", NF_ACCEPT}, {"stolen", NF_STOLEN},
        {"queue", NF_QUEUE}, {"repeat", NF_REPEAT}, {"stop", NF_STOP}};
    int i;

    for (i = 0; i < sizeof(targets) / sizeof(*targets); i++)
        if (strcmp(targets[i].k, s) == 0) return targets[i].v;

    return XT_CONTINUE;
}

union call_result {
    bool mt;
    unsigned int tg;
};

static union call_result nflua_call(struct sk_buff *skb,
                                    struct xt_action_param *par, int mode) {
    const struct xt_lua_mtinfo *info = par->matchinfo;
    lua_State *L = info->state->L;
    union call_result r;
    int base;

    switch (mode) {
        case NFLUA_MATCH:
            r.mt = false;
            break;
        case NFLUA_TARGET:
            r.tg = XT_CONTINUE;
            break;
    }

    // TODO: call the handlers
    spin_lock(&info->state->lock);
    if (L == NULL) {
        pr_err("invalid lua state");
        goto unlock;
    }

    base = lua_gettop(L);
    lua_pushcfunction(L, nflua_docall);
    lua_pushlightuserdata(L, (void *)info->func);
    lua_pushlightuserdata(L, skb);
    lua_pushinteger(L, kpi_xt_hooknum(par));
    lua_pushinteger(L, mode);
    if (luaU_pcall(L, 4, 1)) {
        pr_err("%s\n", lua_tostring(L, -1));
        goto cleanup;
    }

    // TODO: fetch return value from the handlers
    switch (mode) {
        case NFLUA_MATCH:
            if (lua_isboolean(L, -1))
                r.mt = lua_toboolean(L, -1);
            else if (lua_isstring(L, -1) &&
                     strcmp(lua_tostring(L, -1), "hotdrop") == 0)
                par->hotdrop = true;
            else
                pr_warn("invalid match return");
            break;
        case NFLUA_TARGET:
            if (lua_isstring(L, -1)) r.tg = string_to_tg(lua_tostring(L, -1));
            break;
    }

cleanup:
    lua_settop(L, base);
unlock:
    spin_unlock(&info->state->lock);
    return r;
}

static bool nflua_match(const struct sk_buff *skb,
                        struct xt_action_param *par) {
    pr_warn("nflua_match\n");
    bool ret;
	luanetfilter_t *netfilter = (luanetfilter_t *)par->matchinfo;  
    lunatik_lock(netfilter->runtime);
    ret = (netfilter->match_registered);
    lunatik_unlock(netfilter->runtime);

    pr_warn("nflua_match: %d\n", ret);
    return !ret;
    // return nflua_call((struct sk_buff *)skb, par, NFLUA_MATCH).mt;
}

static void nflua_tg_destroy(const struct xt_tgdtor_param *par) {
    struct xt_lua_mtinfo *info = par->targinfo;

    if (info->state != NULL) nflua_state_put(info->state);
}

static int nflua_tg_checkentry(const struct xt_tgchk_param *par) {
    struct xt_lua_mtinfo *info = par->targinfo;
    struct nflua_state *s;

    s = nflua_state_lookup(xt_lua_pernet(par->net), info->name);
    if (s == NULL) return -ENOENT;

    if (!nflua_state_get(s)) return -ESTALE;

    info->state = s;
    return 0;
}

static unsigned int nflua_target(struct sk_buff *skb,
                                 const struct xt_action_param *par) {
    return nflua_call(skb, (struct xt_action_param *)par, NFLUA_TARGET).tg;
}

static struct xt_match nflua_mt_reg __read_mostly = {
    .name = "luanetfilter",
    .revision = 0,
    .family = NFPROTO_UNSPEC,
    .match = nflua_match,
    .checkentry = nflua_mt_checkentry,
    .destroy = nflua_mt_destroy,
    .matchsize = sizeof(struct xt_lua_mtinfo),
#ifdef KPI_XT_MATCH_USERSIZE
    .usersize = offsetof(struct xt_lua_mtinfo, state),
#endif
    .me = THIS_MODULE};

static struct xt_target nflua_tg_reg __read_mostly = {
    .name = "luanetfilter",
    .revision = 0,
    .family = NFPROTO_UNSPEC,
    .target = nflua_target,
    .checkentry = nflua_tg_checkentry,
    .destroy = nflua_tg_destroy,
    .targetsize = sizeof(struct xt_lua_mtinfo),
#ifdef KPI_XT_MATCH_USERSIZE
    .usersize = offsetof(struct xt_lua_mtinfo, state),
#endif
    .me = THIS_MODULE};

/************* Library & module reg *****************************/
static int luanetfilter_new(lua_State *L);

static int luanetfilter_match(lua_State *L) {
    // register user matching function to lua state
    pr_warn("luanetfilter_match\n");
    return 0;
}

static int luanetfilter_target(lua_State *L) {
    // register user target function to lua state
    pr_warn("luanetfilter_target\n");
    return 0;
}

static void luanetfilter_release(void *private) {}

static const luaL_Reg luanetfilter_lib[] = {{"new", luanetfilter_new},
                                            {NULL, NULL}};

static const luaL_Reg luanetfilter_mt[] = {{"__gc", lunatik_deleteobject},
                                           {"match", luanetfilter_match},
                                           {"target", luanetfilter_target},
                                           {NULL, NULL}};

static const lunatik_class_t luanetfilter_class = {
    .name = "netfilter",
    .methods = luanetfilter_mt,
    .release = luanetfilter_release,
    .sleep = false,
};

static int __net_init luanetfilter_net_init(struct net *net) {
    struct xt_lua_net *xt_lua = xt_lua_pernet(net);

    nflua_states_init(xt_lua);

    if (nflua_netlink_init(xt_lua, net)) {
        pr_err("Netlink Socket initialization failed!\n");
        return -ENOMEM;
    }

    return 0;
}

static void __net_exit luanetfilter_net_exit(struct net *net) {
    struct xt_lua_net *xt_lua = xt_lua_pernet(net);

    nflua_netlink_exit(xt_lua);
    nflua_states_exit(xt_lua);
}

static struct pernet_operations luanetfilter_net_ops = {
    .init = luanetfilter_net_init,
    .exit = luanetfilter_net_exit,
    .id = &xt_lua_net_id,
    .size = sizeof(struct xt_lua_net),
};

static int luanetfilter_new(lua_State *L) {
    pr_warn("luanetfilter_new\n");
    lunatik_object_t *object =
        lunatik_newobject(L, &luanetfilter_class, sizeof(luanetfilter_t));
    luanetfilter_t *netfilter = (luanetfilter_t *)object->private;

    netfilter->runtime = lunatik_toruntime(L);
    netfilter->match_registered = false;
    netfilter->target_registered = false;
    lunatik_getobject(netfilter->runtime);

    lunatik_registerobject(L, 1, object);
    return 1; /* object */
}

LUNATIK_NEWLIB(netfilter, luanetfilter_lib, &luanetfilter_class, NULL);

static int __init luanetfilter_init(void) {
    int ret;

    pr_warn("initializing luanetfilter module\n");

    if ((ret = register_pernet_subsys(&luanetfilter_net_ops))) return ret;

    if ((ret = xt_register_match(&nflua_mt_reg))) {
        unregister_pernet_subsys(&luanetfilter_net_ops);
        return ret;
    }

    // if ((ret = xt_register_target(&nflua_tg_reg))) {
    //     unregister_pernet_subsys(&luanetfilter_net_ops);
    //     xt_unregister_match(&nflua_mt_reg);
    //     return ret;
    // }

    return ret;
}

static void __exit luanetfilter_exit(void) {
    pr_warn("unloading luanetfilter module\n");
    xt_unregister_match(&nflua_mt_reg);
    // xt_unregister_target(&nflua_tg_reg);
    unregister_pernet_subsys(&luanetfilter_net_ops);
}

module_init(luanetfilter_init);
module_exit(luanetfilter_exit);
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Mohammad Shehar Yaar Tausif <sheharyaar48@gmail.com>");
MODULE_ALIAS("xt_luanetfilter");