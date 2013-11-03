module("luci.controller.bismark.experiments", package.seeall)

function index()
    entry({"admin", "bismark"}, alias("admin", "bismark", "experiments"), "BISmark", 25).index = true
    entry({"admin", "bismark", "experiments"}, cbi("bismark-experiments-manager/general", {autoapply=true}), "Experiments", 10).leaf = true
end
