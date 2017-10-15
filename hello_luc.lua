
require "apache2"
function hello_lua_start(r)
    r:puts("hello mod_lua\n")
    return apache2.OK
end
