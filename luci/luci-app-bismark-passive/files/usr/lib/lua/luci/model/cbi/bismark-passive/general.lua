m = Map("bismark-passive", "Bismark Passive")
m.on_after_commit = function()
    luci.sys.call("/tmp/etc/init.d/bismark-passive restart")
end

s = m:section(TypedSection, "whitelist", "")
s.anonymous = true
s:tab("whitelist", "Domain whitelist")
en = s:taboption("whitelist", Flag, "enabled", "Enable logging of whitelisted domains", "If enabled, we will log when devices connected to the BISmark router contact the sites on the list, including subdomains. <b>This does not record page contents, URLs, e-mail messages, or any other personal information.</b> For example, if you browse Facebook the software will only record the fact that you visited Facebook; it will record nothing about your username, your friends, your photos, etc.")
en.rmempty = false
domain = s:taboption("whitelist", DynamicList, "domain", "Whitelisted domain names")
domain.datatype = "host"

return m -- Returns the map
