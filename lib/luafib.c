/*
* SPDX-FileCopyrightText: (c) 2023-2024 Ring Zero Desenvolvimento de Software LTDA
* SPDX-License-Identifier: MIT OR GPL-2.0-only
*/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/kernel.h>
#include <linux/module.h>
#include <net/fib_rules.h>

#include <lua.h>
#include <lauxlib.h>

#include <lunatik.h>

#define luafib_nl_sizeof(t)	(nla_total_size(sizeof(t)))

#define LUAFIB_NL_SIZE	(NLMSG_ALIGN(sizeof(struct fib_rule_hdr)) 	\
		+ luafib_nl_sizeof(u8)		/* FRA_PROTOCOL */	\
		+ luafib_nl_sizeof(u32))	/* FRA_PRITORITY */

typedef struct luafib_rule_s {
	struct net *net;
	int (*command)(struct sk_buff *, struct nlmsghdr *, struct netlink_ext_ack *);
	u32 table;
	u32 priority;
} luafib_rule_t;

static int luafib_nl_rule(luafib_rule_t *rule)
{
	struct fib_rule_hdr *frh;
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	int ret = -1;

	if (!(skb = nlmsg_new(LUAFIB_NL_SIZE, GFP_KERNEL)) ||
	    !(nlh = nlmsg_put(skb, 0, 0, 0, sizeof(*frh), 0)))
		goto out;

	nlh->nlmsg_flags |= NLM_F_EXCL;

	frh = nlmsg_data(nlh);
	memset(frh, 0, sizeof(*frh));
	frh->family = AF_INET;
	frh->action = FR_ACT_TO_TBL;
	frh->table = rule->table;

	if (nla_put_u8(skb, FRA_PROTOCOL, RTPROT_KERNEL) ||
	    nla_put_u32(skb, FRA_PRIORITY, rule->priority))
		goto free;
	nlmsg_end(skb, nlh);

	skb->sk = rule->net->rtnl;
	ret = rule->command(skb, nlh, NULL);
free:
	nlmsg_free(skb);
out:
	return ret;
}

#define LUAFIB_OPRULE(op) 				\
static int luafib_##op(lua_State *L)			\
{							\
	luafib_rule_t rule;				\
							\
	rule.net = &init_net;				\
	rule.command = fib_nl_##op;			\
	rule.table = (u32)luaL_checkinteger(L, 1);	\
	rule.priority = (u32)luaL_checkinteger(L, 2);	\
							\
	if (luafib_nl_rule(&rule) < 0)			\
		luaL_error(L, "failed on " #op);	\
							\
	return 0;					\
}

LUAFIB_OPRULE(newrule);
LUAFIB_OPRULE(delrule);

static const luaL_Reg luafib_lib[] = {
	{"newrule", luafib_newrule},
	{"delrule", luafib_delrule},
	{NULL, NULL}
};

static const lunatik_class_t luafib_class = {
	.sleep = true,
};

LUNATIK_NEWLIB(fib, luafib_lib, &luafib_class, NULL);

static int __init luafib_init(void)
{
	return 0;
}

static void __exit luafib_exit(void)
{
}

module_init(luafib_init);
module_exit(luafib_exit);
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Lourival Vieira Neto <lourival.neto@ring-0.io>");

