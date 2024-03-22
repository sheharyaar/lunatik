local netfilter = require("netfilter")

local function match_func()
    print("Matched!")
    return true;
end

local nf = netfilter.new()
nf:match(match_func)
