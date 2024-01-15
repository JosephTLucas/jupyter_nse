local shortport = require "shortport"
local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Discover Jupyter instances (JupyterLab and JupyterHub) and check their authentication status.
]]

author = "Joseph Lucas"
license = "Your Company License"
categories = {"discovery", "safe"}

local jupyter_ports = {8000, 8888, 8889}

portrule = function(host, port)
    return shortport.port_or_service(jupyter_ports, port)
end

local function check_authentication(host, port, path, expected_content)
  local response = http.get(host, port, path)

    if response.status == 200 then
      if string.find(response.body, expected_content, 1, true) then
        return "Authentication required"
      else
        return "Potentially Unauthenticated"
      end
    end
end

action = function(host, port)
    local jupyter_results = {}

    local lab_status = check_authentication(host, port, "/lab", "Password:")
    if lab_status == "Authentication required" or lab_status == "Potentially Unauthenticated" then
        table.insert(jupyter_results, "JupyterLab: " .. lab_status)
    end

    local hub_status = check_authentication(host, port, "/hub", "Password:")
    if hub_status == "Authentication required"  or hub_status == "Potentially Unauthenticated" then
        table.insert(jupyter_results, "JupyterHub: " .. hub_status)
    end
    local output = table.concat(jupyter_results, "\n")

    if #jupyter_results == 0 then
        output = "No Jupyter instances found"
    end

    return stdnse.format_output(true, output)
end
