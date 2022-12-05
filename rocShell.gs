clear_screen //if you dont like screen to be cleared remove this line

{"ver":"1.0.0", "api":false} //release. today is huge.

local = {}
local.shell = get_shell
local.computer = get_shell.host_computer
local.folder = local.computer.File(current_path)
local.router = get_router
local.user = active_user
local.lanIp = get_shell.host_computer.local_ip
local.publicIp = get_router.public_ip

if not local.computer.is_network_active then print("No internet access.")

aptclient = include_lib(current_path + "/aptclient.so")
if not aptclient then aptclient = include_lib("/lib/aptclient.so")
if not aptclient then print("missing lib apiclient.so in lib or current path")
blockchain = include_lib(current_path + "/blockchain.so")
if not blockchain then blockchain = include_lib("/lib/blockchain.so")
if not blockchain then print("missing lib blockchain.so in lib or current path")
crypto = include_lib(current_path + "/crypto.so")
if not crypto then crypto = include_lib("/lib/crypto.so")
if not crypto then print("missing lib crypto.so in lib or current path")
metaxploit = include_lib(current_path + "/metaxploit.so")
if not metaxploit then metaxploit = include_lib("/lib/metaxploit.so")
if not metaxploit then print("missing lib metaxploit.so in lib or current path")

current = {}
current.obj = local.shell
current.computer = function
	if typeof(current.obj) == "shell" then return current.obj.host_computer
	if typeof(current.obj) == "computer" then return current.obj
	return null
end function
current.router = local.router
current.folder = local.folder
current.user = local.user
current.lanIp = local.lanIp
current.publicIp = function
	return current.router.public_ip
end function

libs = {}
libs.absolutePath = function(rPath, cPath) //current path + relative path = absolute path
	if rPath.len == 0 then return print("invalid path.")
	if rPath[0] == "/" then return rPath
	if cPath.len == 0 then return print("invalid path.")
	if not cPath[0] == "/" then return print("invalid path.")
	if not cPath[-1] == "/" then cPath = cPath + "/"
	absPath = cPath + rPath
	while absPath.len > 1 and absPath[-1] == "/"
		absPath = absPath[:-1]
	end while
	return absPath
end function
libs.changeDir = function(toPath, fileObject) //go to another dir
    if not fileObject then fileObject = globals.current.folder
    while fileObject.parent
		fileObject = fileObject.parent
	end while
    if toPath.len == 0 then return print("File not found.")
    while (toPath.len > 1) and (toPath[-1] == "/") //trim end "/"
        toPath = toPath[:-1]
    end while
    while (toPath.len > 1) and (toPath[0] == "/") //trim start "/"
        toPath = toPath[1:]
    end while
    if toPath == "/" then return fileObject
    toPath = toPath.split("/")
    for p in toPath
		found = false
		for f in fileObject.get_folders
			if not f.name == p then continue
			found = true
			fileObject = f
			break
		end for
		if not found then return print("Folder not found.")
	end for
    if not fileObject.is_folder then return print("Folder not found.")
	return fileObject
end function
libs.getFile = function(toPath, fileObject) //changeDir only support folder but this works for both
	if not fileObject then fileObject = globals.current.folder
    while fileObject.parent
		fileObject = fileObject.parent
	end while
	if toPath.len == 0 then return print("File not found.")
	while (toPath.len > 1) and (toPath[-1] == "/") //trim end "/"
        toPath = toPath[:-1]
    end while
    while (toPath.len > 1) and (toPath[0] == "/") //trim start "/"
        toPath = toPath[1:]
    end while
    if toPath == "/" then return fileObject
	toPath = toPath.split("/")
    for i in toPath.indexes
		found = false
        if i == (toPath.len - 1) then
            for f in fileObject.get_folders + fileObject.get_files
                if not f.name == toPath[i] then continue
                return f
            end for
            return print("File not found")
        end if
		for f in fileObject.get_folders
			if not f.name == toPath[i] then continue
			found = true
			fileObject = f
			break
		end for
		if not found then return print("File not found.")
	end for
	return fileObject
end function
libs.allFiles = function(fileObject) //list all file object under a dir
	if not fileObject then
		fileObject = globals.current.folder
		while fileObject.parent
			fileObject = fileObject.parent
		end while
	end if
	files = [fileObject] + fileObject.get_folders + fileObject.get_files
	i = 0
	while i < files.len
		if files[i].is_folder then files = files + files[i].get_folders + files[i].get_files
		i = i + 1
        if i > 1000 then break //prevent huge file system/recursive file system(new glitch)
	end while
	return files
end function
libs.find = function(fileName, fileObject) //find files under a dir
    founded = []
    files = self.allFiles(fileObject)
	for file in files
		if lower(file.name).indexOf(lower(fileName)) != null then founded = founded + [file.path]
	end for
	return founded
end function
libs.toFile = function(anyObject)
    if typeof(anyObject) == "shell" then return anyObject.host_computer.File("/")
    if typeof(anyObject) == "computer" then return anyObject.File("/")
    if typeof(anyObject) == "file" then
        while anyObject.parent
            anyObject = anyObject.parent
        end while
        return anyObject
    end if
    return null
end function
libs.checkAccess = function(fileObject) //check perm for npc machine
    if not typeof(fileObject) == "file" then return null
	while fileObject.parent
		fileObject = fileObject.parent
	end while
	homeFolder = null
	for folder in fileObject.get_folders
		if folder.name == "root" then
			if folder.has_permission("w") and folder.has_permission("r") and folder.has_permission("x") then return "root"
		end if
		if folder.name == "home" then
			homeFolder = folder
		end if
	end for
	if not homeFolder then return "guest"
	for folder in homeFolder.get_folders
		if folder.name == "guest" then continue
		if folder.has_permission("w") and folder.has_permission("r") and folder.has_permission("x") then return folder.name
	end for
	return "guest"
end function
libs.corruptLog = function(fileObject) //corrupt system log by copy the smallest file to that dir
    if not fileObject then fileObject = current.folder
    while fileObject.parent
		fileObject = fileObject.parent
	end while
	files = self.allFiles(fileObject)
	toCopy = null
	for file in files
		if (not file.is_folder) and file.has_permission("r") then
			if not toCopy then toCopy = file
			if val(file.size) < val(toCopy.size) then toCopy = file
		end if
	end for
	if not toCopy then return print("No file to overwrite log! try using ""touch"".")
	logFile = null
	for file in files
		if not file.path == "/var/system.log" then continue
		logFile = file
		break
	end for
	if not logFile then return print("log file not found!")
	tryDelete = logFile.delete
	if tryDelete == "" then print("Log file deleted.") else return print("Error: " + deleteLogFile)
	tryCopy = toCopy.copy("/var", "system.log")
	if tryCopy == true then return print("All steps done. Log cleared.")
	return print(tryCopy)
end function
libs.fileSize = function(bytes) //translate byte to kb and mb
	bytes = bytes.to_int
	i = 0
	units = ["B","KB","MB","GB","TB","PT"]
	while bytes > 1024
		bytes = bytes / 1024
		i = i + 1
	end while
	return round(bytes, 2) + units[i]
end function
libs.scanLib = function(metaLib, metaxploit)
    if not metaLib then return null
    if not metaxploit then metaxploit = globals.metaxploit
    ret = {}
    ret.lib_name = metaLib.lib_name
    ret.version = metaLib.version
    ret.memorys = {}
    memorys = metaxploit.scan(metaLib)
    for memory in memorys
        addresses = metaxploit.scan_address(metaLib, memory).split("Unsafe check:")
        ret.memorys[memory] = []
        for address in addresses
            if address == addresses[0] then continue
            value = address[address.indexOf("<b>")+3:address.indexOf("</b>")]
            value = value.replace("\n", "")
            ret.memorys[memory] = ret.memorys[memory] + [value]
        end for
    end for
    return ret
end function

computerCommands = {}
computerCommands["ps"] = {"name":"ps", "description":"List processes running.", "args":""}
computerCommands["ps"]["run"] = function(args)
    computer = current.computer
    procs = computer.show_procs
	procs = procs.split("\n")
	output = ""
	for proc in procs
		val = proc.split(" ")
		if val[0] == "USER" then continue
		output = output + "\n" + "[" + val[0] + "] (" + val[1] + ") " + val[4] + " " + "CPU: [" + val[2] + "] " + "MEM: [" + val[3] + "]"
	end for
    return print(format_columns(output) + "\n")
end function
computerCommands["kill"] = {"name":"kill", "description":"Kill a process.", "args":"[PID]"}
computerCommands["kill"]["run"] = function(args)
	if args.len < 1 then return print("Usage: kill [PID]")
	PID = args[0].to_int
	if typeof(PID) != "number" then return print("The PID must be a number.")
	computer = current.computer
	output = computer.close_program(PID) //close PID
	if output == true then return print("Process " + PID + " closed")
	if output then return print(output)
	return print("Process " + PID + " not found")
end function
computerCommands["touch"] = {"name":"touch", "description":"Create a text file.", "args":"[file_path]"}
computerCommands["touch"]["run"] = function(args)
	if args.len < 1 then return print("Usage: touch [file_name]")
	path = libs.absolutePath(args[0], current.folder.path)
    if path == null then return print("path not found")
    parent = parent_path(path)
    name = path.split("/")[-1]
	doTouch = current.computer.touch(parent, name)
    if doTouch == true then return print("Done.")
    print(doTouch)
	return print("Failed.")
end function
computerCommands["mkdir"] = {"name":"mkdir", "description":"Create a empty folder.", "args":"[folder_path]"}
computerCommands["mkdir"]["run"] = function(args)
	if args.len < 1 then return print("Usage: mkdir [folder_path]")
	path = libs.absolutePath(args[0], current.folder.path)
    if path == null then return print("path not found")
    parent = parent_path(path)
    name = path.split("/")[-1]
	doMkdir = current.computer.create_folder(parent, name)
    if doMkdir == true then return print("Done.")
    print(doMkdir)
	return print("Failed.")
end function

shellCommands = {}
shellCommands["shell"] = {"name":"shell", "description":"Starts terminal. Watch out for active traces.", "args":"[PID]"}
shellCommands["shell"]["run"] = function(args)
	return current.obj.start_terminal
end function
shellCommands["ssh"] = {"name":"ssh", "description":"Connect to a ssh service. I hate ftp.", "args":"[user@password] [ip] [(opt) port]"}
shellCommands["ssh"]["run"] = function(args)
    if args.len < 2 then return print("usage: ssh [user@password] [ip] [(opt) port]")
    sshUser = args[0].split("@")[0]
    sshPass = args[0].split("@")[1]
    sshIp = args[1]
    if args.len > 2 then port = args[2].to_int else port = 22
    if not port isa number then return print("Invalid port.")
    localShell = current.obj
    remoteShell = localShell.connect_service(sshIp, port, sshUser, sshPass, "ssh")
    if not typeof(remoteShell) == "shell" then
        print(remoteShell)
        return print("Connection failed.")
    end if
    if sshUser == "root" then homePath = "/root" else homePath = "/home/" + sshUser
    globals.current.obj = remoteShell
    globals.current.folder = remoteShell.host_computer.File(homePath)
    globals.current.user = sshUser
    if not is_lan_ip(sshIp) then globals.current.router = get_router(sshIp)
    globals.current.lanIp = remoteShell.host_computer.local_ip
    return print("Connected.")
end function
shellCommands["up"] = {"name":"up", "description":"Upload a file. Only take absolute path.", "args":"[local_file_path] [remote_path]"}
shellCommands["up"]["run"] = function(args)
    if args.len < 2 then return print("Usage: up [local_file_path] [remote_path].")
    localShell = local.shell
    remoteShell = current.obj
	pathFrom = args[0]
	pathTo = args[1]
	fileFrom = globals.local.computer.File(pathFrom) //get file
	folderTo = globals.current.obj.host_computer.File(pathTo) //get folder
	if not folderTo then return print("Remote directory not found.") //check if folder exists
	if not folderTo.is_folder then return print("Remote directory not found.") //check if folder exists
	if not fileFrom then return print("Local file not found: " + pathFrom) //not found print error msg
	print("Uploading file: " + fileFrom.name + " to: " + pathTo) //found print target path
	upload = localShell.scp(pathFrom, pathTo, remoteShell) //func call as upload
	if not typeof(upload) == "string" then return print("File uploaded successfully.")
    return print(upload)
end function
shellCommands["dl"] = {"name":"dl", "description":"download a file.", "args":"[remote_file_path] [local_path]"}
shellCommands["dl"]["run"] = function(args)
    localShell = local.shell
    remoteShell = current.obj
    if args.len < 2 then return print("Usage: dl [remote_file_path] [local_path].")
	pathFrom = args[0]
	pathTo = args[1]
	fileFrom = globals.current.obj.host_computer.File(pathFrom)//get file
	folderTo = globals.local.computer.File(pathTo) //get folder
	if not folderTo then return print("Local directory not found.") //check if folder exists
	if not folderTo.is_folder then return print("Local directory not found.") //check if folder exists
	if not fileFrom then return print("Remote file not found: " + pathFrom) //not found print error msg
	print("Downloading file: " + fileFrom.name + " to: " + pathTo) //found print target path
	download = remoteShell.scp(pathFrom, pathTo, localShell) //func call as download
	if not typeof(download) == "string" then return print("File uploaded successfully.")
    return print(download)
end function
shellCommands["run"] = {"name":"run", "description":"Execute a program.", "args":"[path] [(opt) params]"}
shellCommands["run"]["run"] = function(args)
    if args.len < 1 then return print("Program not found")
    return current.obj.launch(args[0], args[1:].join(" "))
end function
shellCommands["ping"] = {"name":"ping", "description":"Ping a ip.", "args":"[ip]"}
shellCommands["ping"]["run"] = function(args)
    if args.len < 1 then return print("Invalid ip.")
    result = current.obj.ping(params[0])
    if result then
        if typeof(result) == "string" then
            print(result) 
        else
            print("Ping successful")
        end if
    else
        print("ip unreachable");
    end if
    return true
end function
shellCommands["build"] = {"name":"build", "description":"Compile a program.", "args":"[source_path] [to_path] [(opt) allow_import]"}
shellCommands["build"]["run"] = function(args)
    if args.len < 2 then return print("Path invalid.")
    allowedImport = false
    if args.len > 2 then
        if (args[2].lower == "true") or (args[2].to_int == 1) then allowedImport = true
    end if
    return print(current.obj.build(args[0], args[1], allowedImport))
end function

commands = {}
commands["re"] = {"name":"re", "description":"Remote attack.", "args":"[ip] [port] [(opt) injectArg]"}
commands["re"]["run"] = function(args)
    if args.len < 2 then return print("Usage: re [ip] [port] [(opt) injectArg]")
    targetIp = args[0]
    if not is_valid_ip(targetIp) then targetIp = nslookup(targetIp)
    if not is_valid_ip(targetIp) then return print("Invalid ip.")
    targetPort = args[1].to_int
    if args.len > 2 then injectArg = args[2] else injectArg = ""
    netSession = metaxploit.net_use(targetIp, targetPort)
    if not netSession then return print("Unable to make net session.")
    metaLib = netSession.dump_lib
    if not metaLib then return print("Unable to dump lib.")
    exploits = libs.scanLib(metaLib, metaxploit)
    if not exploits then return print("Unable to scan for exploits.")
    results = []
    for e in exploits.memorys
        for value in e.value
            object = metaLib.overflow(e.key, value, injectArg)
            if (typeof(object) != "shell") and (typeof(object) != "computer") and (typeof(object) != "file") then continue
            result = {"object":object, "user":libs.checkAccess(libs.toFile(object)), "addr":e.key, "valn":value}
            results = results + [result]
        end for
    end for
    toPrint = ""
    for i in results.indexes
        toPrint = toPrint + str(i + 1) + ". " + results[i].user + ":" + typeof(results[i].object) + " " + results[i].addr + " " + results[i].valn + char(10)
    end for
    print(format_columns(toPrint))
    select = user_input("Select> ").to_int
    if not typeof(select) == "number" then return null
    if select > results.len then return null
    if select < 1 then return null
    select = select - 1
    globals.current.obj = results[select].object
    if not is_lan_ip(targetIp) then globals.current.router = get_router(targetIp)
    globals.current.folder = libs.toFile(results[select].object)
    globals.current.user = results[select].user
    if targetPort == 0 then
        if is_lan_ip(injectArg) then //first we guess the ip, if the injected string is a lan ip, we assume it is that.
            globals.current.lanIp = injectArg //this may not be correct.
            if libs.getFile("/lib/kernel_router.so", current.folder) then globals.current.lanIp = current.router.local_ip //if we find router kernel we set ip to router
        else
            globals.current.lanIp = current.router.local_ip //if the injected string is not a lan ip, the correct lan ip must be the router lan ip.
        end if
        if current.computer then globals.current.lanIp = current.computer.local_ip //if we have a shell or a computer, we set the ip to the correct one.
    else
        globals.current.lanIp = current.router.ping_port(targetPort).get_lan_ip //this may not be correct. TODO
    end if
    return null
end function
commands["lo"] = {"name":"lo", "description":"Local attack.", "args":"[lib_path] [(opt) injectArg]"}
commands["lo"]["run"] = function(args)
    if args.len < 1 then return print("Usage: lo [lib_path] [(opt) injectArg]")
    targetPath = args[0]
    if args.len > 1 then injectArg = args[1] else injectArg = ""
    metaLib = metaxploit.load(targetPath)
    if not metaLib then return print("Unable to load lib.")
    exploits = libs.scanLib(metaLib, metaxploit)
    if not exploits then return print("Unable to scan for exploits.")
    results = []
    for e in exploits.memorys
        for value in e.value
            object = metaLib.overflow(e.key, value, injectArg)
            if (typeof(object) != "shell") and (typeof(object) != "computer") and (typeof(object) != "file") then continue
            result = {"object":object, "user":libs.checkAccess(libs.toFile(object)), "addr":e.key, "valn":value}
            results = results + [result]
        end for
    end for
    toPrint = ""
    for i in results.indexes
        toPrint = toPrint + str(i + 1) + ". " + results[i].user + ":" + typeof(results[i].object) + " " + results[i].addr + " " + results[i].valn + char(10)
    end for
    print(format_columns(toPrint))
    select = user_input("Select> ").to_int
    if not typeof(select) == "number" then return null
    if select > results.len then return null
    if select < 1 then return null
    select = select - 1
    globals.current.obj = results[select].object
    globals.current.folder = libs.toFile(results[select].object)
    globals.current.user = results[select].user
    return null
end function
commands["nmap"] = {"name":"nmap", "description":"Scan a ip or a domain.", "args":"[ip/domain]"}
commands["nmap"]["run"] = function(args) //thanks to Nameless for this awesome nmap. I am too lazy to write a new one. It is MIT licensed anyway.
	if args.len < 1 then return print("Invalid ip.")
    targetIp = args[0]
    if not is_valid_ip(targetIp) then targetIp = nslookup(targetIp)
    if not is_valid_ip(targetIp) then return print("Invalid ip.")
    if is_lan_ip(targetIp) then //this is a huge if else statement i know sorry too lazy to change
        router = current.router
        lanPorts = router.device_ports(targetIp)
        publicPorts = router.used_ports
        print("\nLocal Machine at " + targetIp)
        if lanPorts.len == 0 then print("| | --> No local ports detected.")
        for lanPort in lanPorts
            s = "| |"
            if lanPort.is_closed then 
                s = s + "-X-> "
            else
                s = s + "---> "
            end if
            s = s + ":" + lanPort.port_number + " "
            s = s + router.port_info(lanPort)
            for publicPort in publicPorts
                iPort = router.ping_port(publicPort.port_number)
                if iPort.port_number == lanPort.port_number and iPort.get_lan_ip == targetIp then
                    s = s + "-->" + " External Address: " + router.public_ip + ":" + publicPort.port_number
                end if
            end for
            print(s)
        end for
        if not router.kernel_version then
            print("Warning: kernel_router.so not found")
        else
            print("kernel_router.so version: " + router.kernel_version) //print router version
        end if
        print("|\n|---> " + router.essid_name + " (" + router.bssid_name + ")")
        print("      Public IP: " + router.public_ip + "  Private IP: " + router.local_ip)
        print(whois(router.public_ip))
        firewall_rules = router.firewall_rules
        if typeof(firewall_rules) == "string" then return print(firewall_rules)
        print("\nScanning firewall rules...\n")
        if firewall_rules.len == 0 then return print("No rules found.")
        info = "ACTION PORT SOURCE_IP DESTINATION_IP"
        for rules in firewall_rules
            info = info + "\n" + rules
        end for
        print(format_columns(info) + "\n")
    else
        router = get_router(targetIp)
        publicPorts = router.used_ports
        print("\n" + router.essid_name + " (" + router.bssid_name + ")")
        print("Public IP: " + router.public_ip + "  Private IP: " + router.local_ip)
        print(whois(router.public_ip))
        portFwds = []
        blankPorts = []
        for publicPort in publicPorts
            lanPort = router.ping_port(publicPort.port_number)
            if lanPort then portFwds.push({"external":publicPort, "internal":lanPort})
            arrows = "--->"
            arrows2 = " ---> "
            if publicPort.is_closed then arrows = "-X->"
            if not router.ping_port(publicPort.port_number) then
                arrows2 = " ---> ? "
            else if router.ping_port(publicPort.port_number) and router.ping_port(publicPort.port_number).is_closed then
                arrows2 = " -X-> "
            end if
            print(" |  |"+arrows+" :" + publicPort.port_number + " " + router.port_info(publicPort).split(" ")[0] + " " + router.port_info(publicPort).split(" ")[1] +arrows2 + publicPort.get_lan_ip)
        end for
        if not router.devices_lan_ip then
            print(" |-> No local machines detected.")
        else
            for lanMachine in router.devices_lan_ip
                print(" |-> Machine at " + lanMachine + "")
                vbar = "|"
                if router.devices_lan_ip.indexOf(lanMachine) == (router.devices_lan_ip.len - 1) then vbar = " "
                if not router.device_ports(lanMachine) then
                    print(" " + vbar + "   |--> No ports detected.")
                else
                    for port in router.device_ports(lanMachine)
                        arrows = "-->"
                        if port.is_closed then arrows = "-X>"
                        toPrint = " " + vbar + "   |" + arrows + " :" + port.port_number + " " + router.port_info(port).split(" ")[0] + " " + router.port_info(port).split(" ")[1]
                        for portFwd in portFwds
                            if port.get_lan_ip == portFwd.internal.get_lan_ip and port.port_number == portFwd.internal.port_number then toPrint = toPrint + " ---> external port " + portFwd.external.port_number
                        end for
                        print(toPrint)
                    end for
                end if
            end for
        end if
        if not router.kernel_version then
            print("Warning: kernel_router.so not found")
        else
            print("kernel_router.so version: " + router.kernel_version) //print router version
        end if
        firewall_rules = router.firewall_rules
        if typeof(firewall_rules) == "string" then return print(firewall_rules)
        print("\nScanning firewall rules...\n")
        if firewall_rules.len == 0 then return print("No rules found.")
        info = "ACTION PORT SOURCE_IP DESTINATION_IP"
        for rules in firewall_rules
            info = info + "\n" + rules
        end for
        print(format_columns(info) + "\n")
    end if
end function
commands["cd"] = {"name":"cd", "description":"Moves to a different directory.", "args":"[(opt) path]"}
commands["cd"]["run"] = function(args)
	if args.len < 1 then
        if current.user == "root" then toPath = "/root" else toPath = "/home/" + current.user
    else
        if args[0] == "." then return null
        if args[0] == ".." then
            if current.folder.parent then globals.current.folder = current.folder.parent
            return null
        end if
        toPath = libs.absolutePath(args[0], current.folder.path)
        if not toPath then return null
    end if
    folderObj = current.folder
    while folderObj.parent
        folderObj = folderObj.parent
    end while
	toFolder = libs.changeDir(toPath, folderObj)
	if not typeof(toFolder) == "file" then
        if args.len < 1 then globals.current.folder = folderObj else print("No such directory.")
        return null
    end if
	if not toFolder.is_folder then return print("No such directory.")
	globals.current.folder = toFolder
    return true
end function
commands["ls"] = {"name":"ls", "description":"List all files.", "args":"[(opt) path]"}
commands["ls"]["run"] = function(args)
    if args.len == 0 then toPath = current.folder.path else toPath = libs.absolutePath(args[0], current.folder.path)
    if not toPath then return print("No such directory.")
    folderObj = current.folder
    while folderObj.parent
        folderObj = folderObj.parent
    end while
    toFolder = libs.changeDir(toPath, folderObj)
    if not typeof(toFolder) == "file" then return print("No such directory.")
    if not toFolder.is_folder then return print("No such directory.")
    subFiles = toFolder.get_folders + toFolder.get_files
    subFiles.sort
    output = "<b>NAME TYPE +WRX FILE_SIZE PERMISSIONS OWNER GROUP</b>"
    for subFile in subFiles
        nameFile = subFile.name.replace(" ","_")
        permission = subFile.permissions
        owner = subFile.owner
        size = subFile.size
        group = subFile.group
        type = "txt"
        if subFile.is_binary == 1 then type = "bin"
        if subFile.is_folder == 1 then type = "fld"
        WRX = ""
        if subFile.has_permission("w") then WRX = WRX + "w" else WRX = WRX + "-"
        if subFile.has_permission("r") then WRX = WRX + "r" else WRX = WRX + "-"
        if subFile.has_permission("x") then WRX = WRX + "x" else WRX = WRX + "-"
        output = output + "\n" + subFile + ">" + nameFile + " [" + type + "] [" + WRX + "] [" + libs.fileSize(size) + "] [" + permission + "] [" + owner + "] [" + group + "]"
    end for
    print(format_columns(output))
    return print("\n")
end function
commands["help"] = {"name":"help", "description":"List all commands.", "args":""}
commands["help"]["run"] = function(args)
	output = "\n" + typeof(current.obj) + " commands:" + "\n"
	for command in commands
		commandData = command.value
		output = output + char(9) + commandData.name + " " + commandData.args.trim + " -> " + commandData.description + "\n"
	end for
	if typeof(current.obj) == "computer" or typeof(current.obj) == "shell" then
		for command in computerCommands
			commandData = command.value
			output = output + char(9) + commandData.name + " " + commandData.args.trim + " -> " + commandData.description + "\n"
		end for
		if typeof(current.obj) == "shell" then
			for command in shellCommands
				commandData = command.value
				output = output + char(9) + commandData.name + " " + commandData.args.trim + " -> " + commandData.description + "\n"
			end for
		end if
	end if
	return print(output)
end function
commands["valn"] = {"name":"valn", "description":"List file with vulnerable permission.", "args":""}
commands["valn"]["run"] = function(args)
	allFiles = libs.allFiles
	files = []
	for file in allFiles
		if file.has_permission("r") or file.has_permission("w") or file.has_permission("x") then
			if file.is_folder then
				fileType = "fld"
			else if file.is_binary then
				fileType = "bin"
			else
				fileType = "txt"
			end if
			files = files + [fileType + " " + file.path + " " + file.permissions]
		end if
	end for
	output = files.sort.join("\n")
	return print(output)
end function
commands["text"] = {"name":"text", "description":"Text Editor. Will clear screen to display text.", "args":"[path_to_text]"}
commands["text"]["run"] = function(args)
	if args.len < 1 then return print("Invalid arguments!")
	pathText = libs.absolutePath(args[0], current.folder.path)
	if not pathText then return print("File not found.")
	textFile = libs.getFile(pathText)
	if not textFile then return print("File not found.")
	if textFile.is_binary or textFile.is_folder then return print("File not text.")
	text = textFile.get_content
	lines = text.split(char(10))
	while true
		clear_screen
		for i in lines.indexes
			line = "<color=orange>" + str(i + 1) + "</color>" + char(9)
			line = line + lines[i]
			print(line)
		end for
		print("x: save and exit, s: save, q: exit, i: insert, m: modify, r: remove")
		option = user_input("> ", false, true)
		if option.lower == "s" or option.lower == "x" then textFile.set_content(lines.join(char(10)))
		if option.lower == "q" or option.lower == "x" then break
		if option.lower == "i" then
			print("specify line number, c to cancel.")
			lineNum = user_input("> ").to_int
            newText = user_input("input text:" + char(10))
			if not lineNum isa number then continue
            if lineNum >= lines.len then lineNum = lines.len
            if lineNum < 0 then lineNum = 0
            lines = lines[:lineNum] + [newText] + lines[lineNum:]
            continue
		end if
        if option.lower == "m" then
			print("specify line number, c to cancel.")
			lineNum = user_input("> ").to_int
            newText = user_input("input text:" + char(10))
			if not lineNum isa number then continue
            if lineNum > lines.len then lineNum = lines.len
            if lineNum < 1 then lineNum = 1
            lines[lineNum - 1] = newText
            continue
		end if
        if option.lower == "r" then
            print("specify line number, c to cancel.")
			lineNum = user_input("> ").to_int
            if not lineNum isa number then continue
            if lineNum < 1 or lineNum > lines.len then continue
            if lines.len == 1 then
                lines[0] = ""
                continue
            end if
            lines = lines[:lineNum - 1] + lines[lineNum:]
            continue
        end if
	end while
	return print("Done.")
end function
commands["cat"] = {"name":"cat", "description":"Prints a file.", "args":"[file]"}
commands["cat"]["run"] = function(args)
	if args.len < 1 then return print("No file specified.")
    folderObj = current.folder
    while folderObj.parent
        folderObj = folderObj.parent
    end while
    toPath = libs.absolutePath(args[0], current.folder.path)
    if not toPath then return print("No file specified.")
	toPrint = libs.getFile(toPath, folderObj)
	if not typeof(toPrint) == "file" then return print("File not found: " + toPath)
	if not toPrint.has_permission("r") then return print("Permission denied.") //check perm
    if toPrint.is_binary or toPrint.is_folder then return print("File not text file.")
	return print(toPrint.get_content)
end function
commands["rm"] = {"name":"rm", "description":"Delete file.", "args":"[file]"}
commands["rm"]["run"] = function(args)
	if args.len < 1 then return print("No file specified.")
    folderObj = current.folder
    while folderObj.parent
        folderObj = folderObj.parent
    end while
    toPath = libs.absolutePath(args[0], current.folder.path)
    if not toPath then return print("No file specified.")
	toDelete = libs.getFile(toPath, folderObj)
	if not typeof(toDelete) == "file" then return print("File not found: " + toPath)
	if not toDelete.has_permission("w") then return print("Permission denied.") //check perm
	toDelete.delete //delete file
	return print("File deleted.") //output
end function
commands["hash"] = {"name":"hash", "description":"Reverse hash. Split multiple lines with commas or line breaks.", "args":"[hash]"}
commands["hash"]["run"] = function(args)
	if not crypto then return print("Error: crypto.so not loaded!")
	if args.len != 1 then return print("Invalid arguments!")
	hashes = []
	passes = args[0]
	passes = passes.split(char(10))
	for i in passes.indexes
		passes[i] = passes[i].split(",")
		for j in passes[i].indexes
			passes[i][j] = passes[i][j].split(";")
			for k in passes[i][j].indexes
				hashes = hashes + [passes[i][j][k]]
			end for
		end for
	end for
    for hsh in hashes
        hsh = hsh.split(":")
        if hsh.len > 0 then arg = hsh[0]
        if hsh.len > 1 then arg = hsh[1]
        ret = crypto.decipher(arg)
        if hsh.len > 1 then ret = hsh[0] + ":" + ret
        print(ret)
    end for
	return print("All hash done.")
end function
commands["clog"] = {"name":"clog", "description":"Clear log.", "args":""}
commands["clog"]["run"] = function(args)
	tryClearLog = libs.corruptLog(current.folder)
    if not tryClearLog then return print("Failed.")
    return print("Done.")
end function
commands["local"] = {"name":"local", "description":"Get back to local.", "args":""}
commands["local"]["run"] = function(args)
    globals.current.obj = local.shell
    globals.current.router = local.router
    globals.current.folder = local.folder
    globals.current.user = local.user
    globals.current.lanIp = local.lanIp
	return null
end function
commands["clear"] = {"name":"clear", "description":"Clear screen.", "args":""}
commands["clear"]["run"] = function(args)
	return clear_screen
end function

execute = function(input)
	cmd = input.split(" ")
	cmdName = cmd[0]
	args = cmd[1:]
	Commands = commands
	if typeof(current.obj) == "computer" or typeof(current.obj) == "shell" then
		Commands = Commands + computerCommands
		if typeof(current.obj) == "shell" then Commands = Commands + shellCommands
	end if
	if not Commands.hasIndex(cmdName.lower) then return print("Error: Command not found!")
	command = Commands[cmdName.lower]
	if args.len > 0 then
		if args[0] == "-h" or args[0] == "--help" then
			return print("Usage :" + command.name + " " + command.args.trim + " -> " + command.description + "\n")
		end if
	end if
	command.run(args)
	return null
end function

main = function()
	while true
		print("<color=white>――</color><color=yellow>(</color>" + current.user + "<color=white>:</color>" + typeof(current.obj) + "<color=white>@</color>" + current.publicIp + "<color=white>~</color>" + current.lanIp + "<color=yellow>)</color><color=white>―</color><color=yellow>[</color>" + current.folder.path + "<color=yellow>]</color>")
		if current.user == "root" then
			input = user_input("<color=white>―</color><color=red>#</color> ")
		else
			input = user_input("<color=white>―</color><color=yellow>$</color> ")
		end if
		execute(input)
	end while
	return null
end function
main