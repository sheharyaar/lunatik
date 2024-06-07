local xt = require("xtable")
local action = xt.action
local family = xt.family
local drop_packet
local ignore_packet
local check_packet
local destroy_packet

function drop_packet(skb, params)
	print("drop_packet called\n")
	return action.ACCEPT
end

function ignore_packet(skb, params)
	print("ignore_packet called\n")
	return action.CONTINUE
end

function check_packet(params)
	print("sorry can't let you add this rule\n")
	return -1
end

function destroy_packet(params)
	print("destroy_packet called\n")
end

local match_ops = {
	name= "shehar",
	revision=1,
	match= drop_packet,
	checkentry=check_packet,
	destroy=drop_packet,
	family= family.UNSPEC,
}

local target_ops = {
	name= "yaar",
	revision=1,
	target= ignore_packet,
	checkentry=ignore_packet,
	destroy=ignore_packet,
	family= family.UNSPEC,
}

xt.match(match_ops)

