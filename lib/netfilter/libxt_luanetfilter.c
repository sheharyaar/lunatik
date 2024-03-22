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

#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include "xt_lua_common.h"
#include <xtables.h>

enum { O_STATE = 0x01, O_FUNCTION = 0x02, O_TCP_PAYLOAD = 0x04 };

static void nflua_help(void) { printf("Netfilter Lua\n"); }

static int nflua_parse(int c, char **argv, int invert, unsigned int *flags,
                       const void *entry, struct xt_entry_match **match) {
    return 1;
}

static void nflua_check(unsigned int flags) { printf("nflua_check\n"); }

static const struct option nflua_opts[] = {
    {.name = "state", .has_arg = 1, .val = O_STATE},
    {.name = "function", .has_arg = 1, .val = O_FUNCTION},
    {.name = "tcp-payload", .has_arg = 0, .val = O_TCP_PAYLOAD},
    XT_GETOPT_TABLEEND,
};

static void nflua_print(const void *ip, const struct xt_entry_match *match,
                        int numeric) {
    printf("nfua_print\n");
}

static void nflua_save(const void *ip, const struct xt_entry_match *match) {
    printf("nfua_save\n");
}

static struct xtables_match nflua_mt_reg = {
    .version = XTABLES_VERSION,
    .name = "luanetfilter",
    .revision = 0,
    .family = NFPROTO_UNSPEC,
    .size = XT_ALIGN(sizeof(struct xt_lua_mtinfo)),
    .userspacesize = XT_ALIGN(sizeof(struct xt_lua_mtinfo)),
    .help = nflua_help,
    .parse = nflua_parse,
    .final_check = nflua_check,
    // .extra_opts = nflua_opts,
    .save = nflua_save,
    .print = nflua_print,
};

static void _init(void) { xtables_register_match(&nflua_mt_reg); }
