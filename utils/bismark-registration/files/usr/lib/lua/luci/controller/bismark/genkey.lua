module("luci.controller.bismark.genkey", package.seeall)

--retrieves token from get/post request and saves check url in /etc/bismark/authn

require("os")

function index()
	entry({"oauth", "genkey"}, template("bismark/genkey"), "redirect", 20).dependent=false
	local token = luci.http.formvalue("token")
	if not (token == nil) then
		local file = assert(io.open("/etc/bismark/authn", "w"))
		file:write("https://register.projectbismark.net/check/?bearer_token=" .. token)
		os.execute("/etc/init.d/nodogsplash stop &>/dev/null")
		luci.http.redirect("/")
	end
end
