local micro = import("micro")
local shell = import("micro/shell")

-- JobSpawn is also the bundled linter's process-launch path.
function onBufferOpen(buf)
    shell.JobSpawn("cmd.exe", {"/c", "echo lint-probe"}, nil, nil,
        function(output, args)
            local file = assert(io.open("C:\\job-output.txt", "w"))
            file:write(output)
            file:close()
            micro.InfoBar():Message("job complete")
        end)
end
