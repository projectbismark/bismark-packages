module("luci.controller.bismark-oauth.genkey", package.seeall)

require("os")

function index()
	entry({"oauth", "genkey"}, template("bismark/genkey"), "redirect", 20).dependent=false
	local token = luci.http.formvalue("token")
	if not (token == nil) then
		local file = assert(io.open("/tmp/bismark/authn", "w"))
		file:write("http://projectbismark.net/check/?bearer_token=" .. token)
		os.execute("/etc/init.d/nodogsplash stop &>/dev/null")
		luci.http.redirect("/")
	end
end
