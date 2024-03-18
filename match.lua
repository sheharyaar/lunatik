local netfilter = require("xt")
local nf        = {}

function nf:match()
    print("match executed")
    return false
end

netfilter.new(nf)