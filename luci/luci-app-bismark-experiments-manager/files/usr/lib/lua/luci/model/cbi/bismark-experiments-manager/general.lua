m = Map("bismark-experiments", "Bismark Experiments")
m.on_after_commit = function()
    luci.sys.exec("/usr/bin/setup-and-teardown-experiments")
end

s = m:section(TypedSection, "experiment", "")
s.anonymous = true
s.addremove = false
s:depends("available", "1")
s:depends("installed", "1")
s:option(DummyValue, "display_name", "Experiment name")
dv = s:option(DummyValue, "description", "Experiment description")
dv.rawhtml = true
s:option(DummyValue, "required", "Required experiment")
en = s:option(Flag, "installed", "Participate in this experiment")
en.rmempty = false
en:depends("required", "0")

return m -- Returns the map
