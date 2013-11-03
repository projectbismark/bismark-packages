module("luci.controller.bismark.passive", package.seeall)

function index()
    entry({"admin", "bismark", "passive"}, cbi("bismark-passive/general", {autoapply=true}), "Passive measurements", 50).dependent=false
end
