#!/usr/bin/env lua

require('os')
require('bmlua.opkg')
opkg = bmlua.opkg
require('bmlua.path')
path = bmlua.path
require('bmlua.set')
set = bmlua.set

local get_managed_repositories = function()
    local managed_repositories = set.Set()
    for info in opkg.get_package_list_urls():iter() do
        local upgradable_url = path.join(info.url, "Upgradable")
        if os.execute("curl -s -f " .. upgradable_url) == 0 then
            managed_repositories:add(info.name)
        end
    end
    return managed_repositories
end

function main(arg)
    os.execute("opkg update")

    local upgradable = opkg.list_upgradable()
    local managed_repositories = get_managed_repositories()
    print 'Upgradable repositories:'
    set.print(managed_repositories)
    local candidates = opkg.get_packages_in_repositories(managed_repositories)
    for package in upgradable:intersection(candidates):iter() do
        print('Upgrading ' .. package)
        opkg.upgrade(package)
    end
end

return main(arg)
