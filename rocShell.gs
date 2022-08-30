metaxploit = include_lib("/lib/metaxploit.so")
if not metaxploit then
	metaxploit = include_lib(current_path + "/metaxploit.so")
	if not metaxploit then exit("Error: missing lib metaxploit.so")
end if
cryptools = include_lib("/lib/crypto.so")
if not cryptools then
	cryptools = include_lib(current_path + "/crypto.so")
	if not cryptools then user_input("Warning: missing lib crypto.so. Hash reverse command is disabled.\nPress any key to continue...", false, true)
end if
//include libs

local = {}
local.shell = get_shell
local.computer = get_shell.host_computer
local.router = get_router
local.folder = local.computer.File(current_path)
local.user = active_user
local.lanIp = get_shell.host_computer.local_ip
local.publicIp = get_router.public_ip
//init local vars

current = {}
current.obj = local.shell
current.router = local.router
current.folder = local.folder
current.user = local.user
current.lanIp = local.lanIp
current.objType = function()
	return typeof(current.obj)
end function
current.publicIp = function()
	return current.router.public_ip
end function
//init current vars

libs = {}

libs.checkAccess = function(fileObject)
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
	if not homeFolder then return "unknown"
	for folder in homeFolder.get_folders
		if folder.name == "guest" then continue
		if folder.has_permission("w") and folder.has_permission("r") and folder.has_permission("x") then
			return folder.name
		end if
	end for
	return "guest"
end function

libs.corruptLog = function(computer = null)
	if computer == null then computer = get_shell.host_computer
	print("Corrupting log.")
	createBakFile = computer.touch("/var","system.bak")
	if createBakFile != 1 then
		print("Error: " + createBakFile)
	else
		print("Bak file created.") //if could not create backup
	end if
	logFile = computer.File("/var/system.log")
	if logFile then
		deleteLogFile = logFile.delete
		if deleteLogFile == "" then print("Log file deleted.") else return print("Error: " + deleteLogFile) //if could not delete log
	else
		return print("Error: Log file not found.") //if log file not found
	end if
	bakFile = computer.File("/var/system.bak")
	if bakFile then
		if bakFile.move("/var", "system.log") != 1 then return print("Error: Could not rename bak.") else print("Bak file renamed.") //if could not rename bak
	end if
	return print("All step done. Log cleared.") //all step done
end function

libs.fileSize = function(bytes) //translate byte to kb and mb
	bytes = bytes.to_int
	i=0
	units = ["B","KB","MB","GB","TB","PT"]
	while bytes > 1024
		bytes=bytes/1024
		i=i+1
	end while
	return round(bytes,2) + units[i]
end function

libs.nmapLanIP = function(IP)
	router = current.router //get router
	netSession = metaxploit.net_use(router.public_ip) //get net session
	routerLib = netSession.dump_lib //get router lib
	lanPorts = router.device_ports(IP) //get local ports
	publicPorts = router.used_ports //get public ports
	
	print("\n<b>" + "Local Machine at " + IP) //print first line
	if lanPorts.len == 0 then print("| | --> <i>" + "No local ports detected.</b>") //if not info print msg
	for lanPort in lanPorts //loop thru each port
		s = "| |"
		if lanPort.is_closed then 
			s = s+"-X-> "
		else
			s = s+"---> "
		end if
		s = s + ":" + lanPort.port_number + " "
		s = s + router.port_info(lanPort)
		for publicPort in publicPorts //loop thru each public port
			iPort = router.ping_port(publicPort.port_number)
			if iPort.port_number == lanPort.port_number and iPort.get_lan_ip == IP then
				s = s + "-->" + " External Address: " + router.public_ip + "" + ":" + publicPort.port_number
			end if
		end for
		print(s) //print port info
	end for
	
	print("|\n|---> <b>" + router.essid_name + "</b> (" + router.bssid_name + ")")
	print("      " + "Public IP: <b>" + router.public_ip + "</b>  " + "Private IP: <b>" + router.local_ip + "</b>")

	whoisLines = whois(router.public_ip).split(char(10)) //get whois info
	for whoisLine in whoisLines //loop thru each line
		if whoisLine.len > 1 then
			cols = whoisLine.split(":")
			print("      <b>"+ cols[0] + ":</b> " + cols[1:].join(""))
		end if
	end for

	print("      " + routerLib.lib_name + " is at version: " + routerLib.version) //print router lib info
	if not router.kernel_version then
		print("Warning: " + "kernel_router.so not found")
	else
		print("      kernel_router.so is at version: " + router.kernel_version)
	end if
end function

libs.nmapPublicIP = function(IP)
	router = get_router(IP) //get router
	netSession = metaxploit.net_use(router.public_ip) //get net session
	routerLib = netSession.dump_lib  //get router lib
	publicPorts = router.used_ports //get public ports

	if router.essid_name == "" then
		essid_name = "<i>No ESSID</i>"
	else
		essid_name = router.essid_name
	end if
	
	print("\n<b>" + essid_name + "</b> (" + router.bssid_name + ")")
	print("Public IP: <b>" + router.public_ip + "</b>  Private IP: <b>" + router.local_ip + "</b>")
	
	whoisLines = whois(router.public_ip).split(char(10))
	for whoisLine in whoisLines //loop thru each line
		if whoisLine.len > 1 then
			cols = whoisLine.split(":")
			print("<b>"+ cols[0] + ":</b> " + cols[1:].join(""))
		end if
	end for
	print(routerLib.lib_name + " is at version: " + routerLib.version)
	if not router.kernel_version then
		print("Warning: kernel_router.so not found")
	else
		print("      kernel_router.so is at version: " + router.kernel_version)
	end if
	portFwds = []
	blankPorts = []
	for publicPort in publicPorts //loop thru each public port
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
		print(" |  |"+arrows+" :" + publicPort.port_number + " " + router.port_info(publicPort).split(" ")[0] + router.port_info(publicPort).split(" ")[1] +arrows2 + publicPort.get_lan_ip)
	end for
	
	if not router.devices_lan_ip then
		print(" |-> <i>No local machines detected.</i>")
	else
		for lanMachine in router.devices_lan_ip
			print(" |-> <b>Machine at " + lanMachine + "</b>")
			vbar = "|"
			if router.devices_lan_ip.indexOf(lanMachine) == (router.devices_lan_ip.len - 1) then vbar = " "
			if not router.device_ports(lanMachine) then
				print(" " + vbar + "   |--> <i>No ports detected.</i>")
			else
				for port in router.device_ports(lanMachine)
					arrows = "-->"
					if port.is_closed then arrows = "-X>"
					toPrint = " " + vbar + "   |" + arrows + " :" + port.port_number + " " + router.port_info(port).split(" ")[0] + router.port_info(port).split(" ")[1]
					for portFwd in portFwds
						if port.get_lan_ip == portFwd.internal.get_lan_ip and port.port_number == portFwd.internal.port_number then toPrint = toPrint + " ---> external port <b>" + portFwd.external.port_number
					end for
					print(toPrint)
				end for
			end if
		end for
	end if
	
	if not router.kernel_version then
		print("Warning: kernel_router.so not found")
	else
		print("kernel_router.so : v" + router.kernel_version) //print router version
	end if

	firewall_rules = router.firewall_rules
	if typeof(firewall_rules) == "string" then return print(firewall_rules)
	print("\nScanning firewall rules...\n")
	if firewall_rules.len == 0 then return print("No rules found.")
	info = "<b>ACTION PORT SOURCE_IP DESTINATION_IP"
	for rules in firewall_rules
		info = info + "\n" + rules
	end for
	print(format_columns(info) + "\n") 
end function

libs.attack = function(metaLib = null)
    if not metaLib then return null //throw error
	print(metaLib.lib_name + " v" + metaLib.version)
    memorys = metaxploit.scan(metaLib) //scan for memory
    results = []
    for memory in memorys //loop thru memorys
        addresses = metaxploit.scan_address(metaLib, memory).split("Unsafe check:") //scan for exploit, store it
        for address in addresses //loop thru addresses
            if address == addresses[0] then continue //ignore first line
            value = address[address.indexOf("<b>")+3:address.indexOf("</b>")] //get value from address, store it
            value = value.replace("\n", "") //get rid of line break
            result = metaLib.overflow(memory, value)
            if typeof(result) != "shell" and typeof(result) != "computer" and typeof(result) != "file" then continue //if result is not a shell, computer or file, continue
            if typeof(result) == "shell" then folder = result.host_computer.File("/") //get the file object for perm testing
            if typeof(result) == "computer" then folder = result.File("/") //get the file object for perm testing
            if typeof(result) == "file" then folder = result
            user = libs.checkAccess(folder)
            resultMap = {"user": user, "obj": result, "addr": memory, "vuln": value} //store result as a map
            results.push(resultMap)
        end for
    end for
	return results //return results
end function //takes a string ip and number port and returns a list of maps

libs.getFile = function(fileList = [], folderObj)
	for folder in fileList
		found = false
		for file in folderObj.get_folders + folderObj.get_files
			if not file.name == folder then continue
			folderObj = file
			found = true
			break
		end for
		if not found then return null
	end for
	return folderObj
end function

libs.pathGetFile = function(path = "", fileObj)
	if not typeof(fileObj) == "file" then return null
	if not path.indexOf("/") then return libs.getFile([path], fileObj)
	if path[-1] == "/" and path.len > 1 then path = path[:-1]
	if path[0] == "/" then
		while fileObj.parent
			fileObj = fileObj.parent
		end while
		path = path[1:]
	end if
	fileList = path.split("/")
	if fileList.len == 0 then fileList.push(path)
	return libs.getFile(fileList, fileObj)
end function

libs.ls = function(folderObj)
	if not folderObj.is_folder then return print("No such directory.")
    subFiles = folderObj.get_folders + folderObj.get_files //get all files and folders under the object
    subFiles.sort //sort with alphabet
    output = "<b>NAME TYPE +WRX FILE_SIZE PERMISSIONS OWNER GROUP</b>" //first line of output
    for subFile in subFiles //loop thru each subfile
        nameFile = subFile.name.replace(" ","_") //space to underline
        permission = subFile.permissions //get perms
        owner = subFile.owner //get owner
        size = subFile.size //get size
        group = subFile.group //get group
        type = "txt" //init type, txt as default
        if subFile.is_binary == 1 then type = "bin" //if bin then bin
        if subFile.is_folder == 1 then type = "fld" //if fld then fld
        WRX = "" //declear wrx
        if subFile.has_permission("w") then WRX = WRX + "w" else WRX = WRX + "-" //set wrx as perms
        if subFile.has_permission("r") then WRX = WRX + "r" else WRX = WRX + "-"
        if subFile.has_permission("x") then WRX = WRX + "x" else WRX = WRX + "-"
        output = output + "\n" + subFile + ">" + nameFile + " [" + type + "] [" + WRX + "] [" + libs.fileSize(size) + "] [" + permission + "] [" + owner + "] [" + group + "]" //update output
    end for
    print(format_columns(output)) //print output
    return print("\n") //new line
end function

allCommands = {}
allCommands.re = function(args)
	if not globals.current.publicIp == globals.local.publicIp then return print("You must be on the machine executing this program to use this command.")
	if not globals.current.lanIp == globals.local.lanIp then return print("You must be on the machine executing this program to use this command.")
	if args.len > 1 then //only run if there is at least 2 arguments
		targetIp = args[0] //store target ip
		if not is_valid_ip(targetIp) then //if not valid, maybe it is a domain
			if is_valid_ip(nslookup(targetIp)) then targetIp = nslookup(targetIp) else return print("IP not found!")
		end if
		targetPort = args[1].to_int //store the port as integer
		if typeof(targetPort) != "number" then return print("Port invalid.") //dont put random args PLS
		if args.len > 2 then injectArg = args[2] else injectArg = null //if there is an arg[2], use it
		
		netSession = metaxploit.net_use(targetIp, targetPort) //get net session using target ip and port
		if typeof(netSession) != "NetSession" then return print("Error: net session didnot establish") //did not get the net session, sth is wrong
		metaLib = netSession.dump_lib //get the lib from net session
		
		results = libs.attack(metaLib) //get results

		if typeof(results) != "list" then return print("Error: Unknown error.") //if no results, sth is wrong
		if results.len == 0 then return print("Error: No results found.") //if no results, sth is wrong
		for result in results //loop to print result
			print((results.indexOf(result) + 1) + "." + result.user + ":" + typeof(result.obj) + " " + result.addr + " " + result.vuln) //print it with number
		end for
		if results.len == 0 then return print("No exploit found!") //no exploit found
		if results.len <= 9 then selectObj = user_input("select an object with number >", false, true).to_int else selectObj = user_input("select an object with number >").to_int //ask user for object number
		if typeof(selectObj) == "number" and selectObj <= results.len then //TRY NOT TO THROW RANDOM STUFF IN
			selectObj = selectObj - 1 //minus 1 makes the number index
			globals.current.obj = results[selectObj].obj //update object
			if is_lan_ip(targetIp) then
				globals.current.lanIp = targetIp //update lan ip
			else
				globals.current.router = get_router(targetIp)//update router
				portObj = globals.current.router.ping_port(targetPort)
				if targetPort == 0 then globals.current.lanIp = globals.current.router.local_ip else globals.current.lanIp = portObj.get_lan_ip //update lan ip
			end if
			globals.current.user = results[selectObj].user //update username
			if typeof(results[selectObj].obj) == "file" then
				while results[selectObj].obj.parent
					results[selectObj].obj = results[selectObj].obj.parent
				end while
				globals.current.folder = results[selectObj].obj //update folder
			end if
			if typeof(results[selectObj].obj) == "computer" then globals.current.folder = results[selectObj].obj.File("/") //update path
			if typeof(results[selectObj].obj) == "shell" then globals.current.folder = results[selectObj].obj.host_computer.File("/") //update path
		end if
	end if
end function

allCommands.mre = function(args)
	if args.len > 3 then
		targetIp = args[0] //store target ip
		if not is_valid_ip(targetIp) then //if not valid, maybe it is a domain
			if is_valid_ip(nslookup(targetIp)) then targetIp = nslookup(targetIp) else return print("IP not found!")
		end if
		targetPort = args[1].to_int //store target port
		if typeof(targetPort) != "number" then return print("Port invalid.") //dont put random args PLS
		memory = args[2] //store memory
		value = args[3] //store value
		if args.len > 4 then injectArg = args[4] else injectArg = null //if there is an arg[2], use it
		netSession = metaxploit.net_use(targetIp, targetPort) //get net session using target ip and port
		if typeof(netSession) != "NetSession" then return print("Error: net session didnot establish") //did not get the net session, sth is wrong
		metaLib = netSession.dump_lib //get the lib from net session
		if injectArg then result = metaLib.overflow(memory, value, injectArg) else result = metaLib.overflow(memory, value) //run the exploit
		if typeof(result) != "shell" and typeof(result) != "computer" and typeof(result) != "file" then return print("Error: exploit failed") //exploit failed
		if typeof(result) == "shell" then folder = result.host_computer.File("/") //get the file object for perm testing
        if typeof(result) == "computer" then folder = result.File("/") //get the file object for perm testing
        if typeof(result) == "file" then folder = result
        user = libs.checkAccess(folder)
		YorN = user_input("Exploit succeeded! Press any key to continue, Press n to escape.\n" + user + ":" + typeof(result) + " " + memory + " " + value, false ,true) //print exploit success
		if YorN.lower == "n" then return null //escape
		globals.current.obj = result //set current object
		globals.current.user = user //set current user
		if not is_lan_ip(targetIp) then globals.current.router = get_router(targetIp) //update router
		if typeof(result) == "file" then
			while result.parent
				result = result.parent
			end while
			globals.current.folder = result
		end if
		if typeof(result) == "shell" then globals.current.folder = result.host_computer.File("/")
		if typeof(result) == "computer" then globals.current.folder = result.File("/")
		return true
	end if
	return print("Invalid arguments!") //invalid args
end function

allCommands.nmap = function(args)
	if args.len > 0 then
		targetIp = args[0] //init targetIp
		port = null
		ipAddr = null
		if not is_valid_ip(targetIp) then //if not valid ip
			if is_valid_ip(nslookup(targetIp)) then //if valid domain
				targetIp = nslookup(targetIp) //set targetIp to domain ip
			else //if not valid domain
				return print("IP not found!") //return print error msg
			end if
		end if
		ipAddr = targetIp //set ipAddr to targetIp
		if is_lan_ip(ipAddr) then //if ip is local
			libs.nmapLanIP(ipAddr) //call nmapLanIP
		else //if ip is not local
			libs.nmapPublicIP(ipAddr) //call nmapPublicIP
		end if
	end if
end function

allCommands.local = function(args)
	globals.current.obj = local.shell
	globals.current.router = local.router
	globals.current.folder = local.folder
	globals.current.user = local.user
	globals.current.lanIp = local.lanIp
	return true
end function

allCommands.hash = function(args)
	if not cryptools then return print("Error: crypto.so not loaded!")
	if args.len != 1 then return print("Invalid arguments!")
	hashes = args[0].split(",") //split multiple hash
	if hashes.len == 0 then hashes.push(args[0]) //no comma then push hash in
	for hash in hashes //loop thru each hash
		userPass = hash.split(":") //split user and pass
		password = cryptools.decipher(userPass[1]) //decipher pass
		print(userPass[0] + ":" + password) //output
	end for
	return print("Done.")
end function

commands = {}

commands["shell"] = {}

commands["shell"]["help"] = {"name":"help", "description":"List all commands.", "args":""}
commands["shell"]["help"]["run"] = function(args) //func that runs
	output = "\n" + "Shell commands:" + "\n" //first line that needs to be print
	for command in commands.shell //loop thru each command from Commands
		commandData = command.value //store command info in a var
		output = output + "		" + commandData.name + " " + commandData.args.trim + " -> " + commandData.description+"\n" //store info in output ready to be print
	end for
	return print(output) //PRINT IT OUT
end function

commands["shell"]["nmap"] = {"name":"nmap", "description":"Scans an ip/domain for ports and local ips.", "args":"[ip/domain]"}
commands["shell"]["nmap"]["run"] = function(args)
	return allCommands.nmap(args)
end function

commands["shell"]["re"] = {"name":"re", "description":"Remote attack.", "args":"[ip] [port] [(opt) injectArg]"}
commands["shell"]["re"]["run"] = function(args)
	return allCommands.re(args)
end function

commands["shell"]["lo"] = {"name": "lo","description": "local attack. Must run this script from target terminal.","args": "[libname] [(opt) injectArg]"}
commands["shell"]["lo"]["run"] = function(args)
	if not globals.current.publicIp == globals.local.publicIp then return print("You must be on the machine executing this program to use this command.")
	if not globals.current.lanIp == globals.local.lanIp then return print("You must be on the machine executing this program to use this command.")
	if args.len > 0 then
		targetPath = args[0]
		if args.len > 1 then injectArg = args[1] else injectArg = null
		targetFile = globals.current.obj.host_computer.File("/lib/" + targetPath + ".so") //get file object
		if not targetFile then return print("Lib not found.") //test if there is this file
		metaLib = metaxploit.load("/lib/" + targetPath + ".so") //load lib with path and this is what makes it unable to use on remote
		results = libs.attack(metaLib) //get results
		if results.len == 0 then return print("No exploit found!") //no exploit found
		for result in results
			print((results.indexOf(result) + 1) + "." + result.user + ":" + typeof(result.obj) + " " + result.addr + " " + result.vuln)
		end for
		if results.len <= 9 then selectObj = user_input("select an object with number >", false, true).to_int else selectObj = user_input("select an object with number >").to_int //ask user for object number
		if typeof(selectObj) == "number" and selectObj <= results.len then
			selectObj = selectObj - 1
			globals.current.obj = results[selectObj].obj
			globals.current.user = results[selectObj].user
			globals.current.router = globals.local.router
			if typeof(results[selectObj].obj) == "file" then
				while results[selectObj].obj.parent
					results[selectObj].obj = results[selectObj].obj.parent
				end while
				globals.current.folder = results[selectObj].obj
			end if
			if typeof(results[selectObj].obj) == "computer" then globals.current.folder = results[selectObj].obj.File("/")
			if typeof(results[selectObj].obj) == "shell" then globals.current.folder = results[selectObj].obj.host_computer.File("/")
		end if
	end if
end function

commands["shell"]["mre"] = {"name":"mre", "description":"Remote attack without scan.", "args":"[ip] [port] [(opt) injectArg]"}
commands["shell"]["mre"]["run"] = function(args)
	return allCommands.mre(args)
end function

commands["shell"]["mlo"] = {"name":"mlo", "description":"Local attack without scan.", "args":"[libname] [memory] [value] [(opt) injectArg]"}
commands["shell"]["mlo"]["run"] = function(args)
	if args.len > 2 then
		if not globals.current.publicIp == globals.local.publicIp then return print("You must be on the machine executing this program to use this command.")
		if not globals.current.lanIp == globals.local.lanIp then return print("You must be on the machine executing this program to use this command.")
		targetPath = args[0] //store target path
		targetFile = globals.current.obj.host_computer.File("/lib/" + targetPath + ".so") //get file
		if not targetFile then return print("Lib not found.") //test file existance
		memory = args[1] //store memory
		value = args[2] //store value
		if args.len > 3 then injectArg = args[3] else injectArg = null //if there is an arg, use it
		metaLib = metaxploit.load(targetPath) //load lib
		if injectArg then result = metaLib.overflow(memory, value, injectArg) else result = metaLib.overflow(memory, value) //run the exploit
		if typeof(result) != "shell" and typeof(result) != "computer" and typeof(result) != "file" then return print("Error: exploit failed") //exploit failed
		if typeof(result) == "shell" then folder = result.host_computer.File("/")
		if typeof(result) == "computer" then folder = result.File("/")
		if typeof(result) == "file" then
			while result.parent
				result = result.parent
			end while
			folder = result
		end if
		user = checkAccess(folder)
		YorN = user_input("Exploit succeeded! Press any key to continue, press n to escape.\n" + perm + ":" + typeof(result) + " " + memory + " " + value, false ,true) //print exploit success
		if YorN.lower == "n" then return null //escape
		globals.current.obj = result //set current object
		globals.current.folder = folder //set current folder
		globals.current.user = user //set current user
		globals.current.router = globals.local.router //set current router
	end if
end function

commands["shell"]["ps"] = {"name":"ps", "description":"Shows the active processes of the operating system.", "args":""}
commands["shell"]["ps"]["run"] = function(args)
	computer = globals.current.obj.host_computer //get computer object
	procs = computer.show_procs //get all the processes
	procs = procs.split("\n") //split em
	output = "" //declare output
	for proc in procs //loop thru procs
		val = proc.split(" ") //split proc
		if val[0] == "USER" then continue //ignore USER

		output = output + "\n" + "[" + val[0] + "] (" + val[1] + ") " + val[4] + " " + "CPU: [" + val[2] + "] " + "MEM: [" + val[3] + "]" //update output
	end for
	return print(format_columns(output) + "\n") //print output IN STYLE
end function

commands["shell"]["kill"] = {"name":"kill", "description":"Kill a process.", "args":"[PID]"}
commands["shell"]["kill"]["run"] = function(args)
	if args.len == 0 then return print("Usage: kill [PID]") //test if there is an arg
	PID = args[0].to_int //get PID from argument
	if typeof(PID) != "number" then return print("The PID must be a number.") //LIKE U CAN NOT PUT RANDOM STUFF IN
	computer = globals.current.obj.host_computer //get computer object
	output = computer.close_program(PID) //close PID
	if output == true then return print("Process " + PID + " closed"); //success
	if output then return print(output) //well u FAIL
	return print("Process " + PID + " not found") //bruh no such PID
end function

commands["shell"]["ls"] = {"name":"ls", "description":"List all files.", "args":"[path]"}
commands["shell"]["ls"]["run"] = function(args)
	computer = globals.current.obj.host_computer //get computer object
	folderObj = globals.current.folder //get current path
	if args.len == 1 then folderObj = computer.File(args[0])
	if not folderObj then return print("No such directory.")
    return libs.ls(folderObj)
end function

commands["shell"]["cd"] = {"name":"cd", "description":"Moves to a different directory.", "args":"[path]"}
commands["shell"]["cd"]["run"] = function(args)
	computer = globals.current.obj.host_computer //get computer object
	directory = globals.current.folder //get directory object
	if args.len > 0 then
		path = args[0] //get path
		if path == "." then return true
		if path == ".." then
			if directory.parent then
				globals.current.folder = directory.parent
				return globals.current.folder
			end if
			return print("You are already in the root directory.")
		end if
		if computer.File(path) then //if valid then
			directory = computer.File(path) //update current folder
		else if computer.File(directory.path + "/" + path) then //not valid, check as relative path
			directory = computer.File(directory.path + "/" + path) //update
		else if computer.File(directory.path + path) then //maybe it is "/"
			directory = computer.File(directory.path + path) //update
		else
			return print("No such directory.") //check for everything and failed, print error msg
		end if
	else
		if globals.current.user == "root" then directory = computer.File("/root") else directory = computer.File("/home/" + current.user)
	end if
	if not directory.is_folder then return print("No such directory.")
	globals.current.folder = directory
	return globals.current.folder
end function

commands["shell"]["clog"] = {"name":"clog", "description":"Corrupt log. Delete suspicious entries before execute.", "args":""}
commands["shell"]["clog"]["run"] = function(args)
	return libs.corruptLog(globals.current.obj.host_computer) //get computer
end function

commands["shell"]["shell"] = {"name":"shell", "description":"Starts a normal shell.", "args":""}
commands["shell"]["shell"]["run"] = function(args)
	return current.obj.start_terminal
end function

commands["shell"]["local"] = {"name":"local", "description":"Go back to local shell.", "args":""}
commands["shell"]["local"]["run"] = function(args)
	return allCommands.local(args)
end function

commands["shell"]["up"] = {"name":"up", "description":"Uploads a file.", "args":"[local_file_path] [remote_path]"}
commands["shell"]["up"]["run"] = function(args)
	if args.len < 2 then return print("Usage: up [local_file_path] [remote_path].")
	pathFrom = args[0]
	pathTo = args[1]
	fileFrom = globals.local.computer.File(pathFrom) //get file
	folderTo = globals.current.obj.host_computer.File(pathTo) //get folder
	if not folderTo then return print("Remote directory not found.") //check if folder exists
	if not folderTo.is_folder then return print("Remote directory not found.") //check if folder exists
	if not fileFrom then return print("Local file not found: " + pathFrom) //not found print error msg
	print("Uploading file: " + fileFrom.name + " to: " + pathTo) //found print target path
	upload = globals.local.shell.scp(fileFrom.path, pathTo, globals.current.obj) //func call as upload
	if not typeof(upload) == "string" then return print("File uploaded successfully.") else return print(upload)
end function

commands["shell"]["dl"] = {"name":"dl", "description":"Downloads a file.", "args":"[remote_file_path] [local_path]"}
commands["shell"]["dl"]["run"] = function(args)
	if args.len < 2 then return print("Usage: dl [remote_file_path] [local_path].")
	pathFrom = args[0]
	pathTo = args[1]
	fileFrom = globals.current.obj.host_computer.File(pathTo)//get file
	folderTo = globals.local.computer.File(pathFrom) //get folder
	if not folderTo then return print("Local directory not found.") //check if folder exists
	if not folderTo.is_folder then return print("Local directory not found.") //check if folder exists
	if not fileFrom then return print("Remote file not found: " + pathFrom) //not found print error msg
	print("Downloading file: " + fileFrom.name + " to: " + pathTo) //found print target path
	download = globals.current.obj.scp(fileFrom.path, pathTo, globals.local.shell) //func call as download
	if not typeof(download) == "string" then return print("File uploaded successfully.") else return print(download)
end function

commands["shell"]["cat"] = {"name":"cat", "description":"Shows the contents of a text file.", "args":"[file]"}
commands["shell"]["cat"]["run"] = function(args)
	if args.len == 0 then return null
	computer = globals.current.obj.host_computer //get computer
	pathFile = args[0] //get path
	file = computer.File(pathFile) //get file with path
	if not typeof(file) == "file" then file = computer.File(current.folder.path + "/" + pathFile) //not found try relative path
	if not typeof(file) == "file" then return print("file not found: " + pathFile) //still not found print error msg
	if file.is_binary then return print("can't open " + file.path + ". Binary file") //file is bin print error msg
	if not file.has_permission("r") then return print("permission denied") //no perm print error msg
	return print(file.get_content) //print file content
end function

commands["shell"]["rm"] = {"name":"rm", "description":"Delete any file if you have the appropriate permissions.", "args":"[file]"}
commands["shell"]["rm"]["run"] = function(args)
	if args.len == 0 then return print("No file specified.")
	pathFile = args[0]
	file = current.obj.host_computer.File(pathFile)
	if not file then return print("File not found: " + pathFile)
	if not file.has_permission("w") then return print("Permission denied.") //check perm
	file.delete //delete file
	return print("File deleted.") //output
end function

commands["shell"]["hash"] = {"name":"hash", "description":"Reverse hash. Split multiple lines with commas.", "args":"[hash]"}
commands["shell"]["hash"]["run"] = function(args)
	return allCommands.hash(args)
end function

commands["shell"]["passwd"] = {"name":"passwd", "description":"Changes the password of a user.", "args":"[username]"}
commands["shell"]["passwd"]["run"] = function(args)
	if args.len > 0 then user = args[0] else user = globals.current.user
	computer = globals.current.obj.host_computer
	inputMsg = "Changing password for user " + user +".\nNew password:" //set msg
	inputPass = user_input(inputMsg, true) //show msg and wait for an input
	output = computer.change_password(user, inputPass) //store func call
	if output == true then return print("Password modified OK.")
	return print(output)
end function

commands["shell"]["launch"] = {"name":"launch", "description":"Сommand launch via shell.launch().", "args": "[path_to_file] [(opt) args]"}
commands["shell"]["launch"]["run"] = function(args)
	return current.obj.launch(args[0], args[1:].join(" "))
end function

commands["shell"]["clear"] = {"name":"clear", "description":"Delete any text from the terminal.", "args":""}
commands["shell"]["clear"]["run"] = function(args)
	return clear_screen //clear the screen
end function

commands["computer"] = {}

commands["computer"]["help"] = {"name":"help", "description":"List all commands.", "args":""}
commands["computer"]["help"]["run"] = function(args) //func that runs
	output = "\n" + "Computer Commands:" + "\n" //first line that needs to be print
	for command in commands.computer //loop thru each command from Commands
		commandData = command.value //store command info in a var
		output = output + "		" + commandData.name + " " + commandData.args.trim + " -> " + commandData.description+"\n" //store info in output ready to be print
	end for
	return print(output) //PRINT IT OUT
end function

commands["computer"]["nmap"] = {"name":"nmap", "description":"Scans an ip/domain for ports and local ips.", "args":"[ip/domain]"}
commands["computer"]["nmap"]["run"] = function(args)
	return allCommands.nmap(args)
end function

commands["computer"]["re"] = {"name":"re", "description":"Remote attack.", "args":"[ip] [port] [(opt) injectArg]"}
commands["computer"]["re"]["run"] = function(args)
	return allCommands.re(args)
end function

commands["computer"]["lo"] = {"name": "lo","description": "local attack. Must run this script from target terminal.","args": "[lib_path] [(opt) injectArg]"}
commands["computer"]["lo"]["run"] = function(args)
	if not globals.current.publicIp == globals.local.publicIp then return print("You must be on the machine executing this program to use this command.")
	if not globals.current.lanIp == globals.local.lanIp then return print("You must be on the machine executing this program to use this command.")
	if args.len > 0 then
		targetPath = args[0]
		if args.len > 1 then injectArg = args[1] else injectArg = null
		targetFile = globals.current.obj.host_computer.File("/lib/" + targetPath + ".so") //get file object
		if not targetFile then return print("No such file or directory") //test if there is this file
		metaLib = metaxploit.load("/lib/" + targetPath + ".so") //load lib with path and this is what makes it unable to use on remote
		results = libs.attack(metaLib) //get results
		if results.len == 0 then return print("No exploit found!") //no exploit found
		for result in results
			print((results.indexOf(result) + 1) + "." + result.user + ":" + typeof(result.obj) + " " + result.addr + " " + result.vuln)
		end for
		if results.len <= 9 then selectObj = user_input("select an object with number >", false, true).to_int else selectObj = user_input("select an object with number >").to_int //ask user for object number
		if typeof(selectObj) == "number" and selectObj <= results.len then
			selectObj = selectObj - 1
			globals.current.obj = results[selectObj].obj
			globals.current.user = results[selectObj].user
			globals.current.router = globals.local.router
			if typeof(results[selectObj].obj) == "file" then
				while results[selectObj].obj.parent
					results[selectObj].obj = results[selectObj].obj.parent
				end while
				globals.current.folder = results[selectObj].obj
			end if
			if typeof(results[selectObj].obj) == "computer" then globals.current.folder = results[selectObj].obj.File("/")
			if typeof(results[selectObj].obj) == "shell" then globals.current.folder = results[selectObj].obj.host_computer.File("/")
		end if
	end if
end function

commands["computer"]["mre"] = {"name":"mre", "description":"Remote attack without scan.", "args":"[ip] [port] [(opt) injectArg]"}
commands["computer"]["mre"]["run"] = function(args)
	return allCommands.mre(args)
end function

commands["computer"]["mlo"] = {"name":"mlo", "description":"Local attack without scan.", "args":"[libname] [memory] [value] [(opt) injectArg]"}
commands["computer"]["mlo"]["run"] = function(args)
	if args.len > 2 then
		if not globals.current.publicIp == globals.local.publicIp then return print("You must be on the machine executing this program to use this command.")
		if not globals.current.lanIp == globals.local.lanIp then return print("You must be on the machine executing this program to use this command.")
		targetPath = args[0] //store target path
		targetFile = globals.current.obj.File("/lib/" + targetPath + ".so") //get file
		if not targetFile then return print("Lib not found.") //test file existance
		memory = args[1] //store memory
		value = args[2] //store value
		if args.len > 3 then injectArg = args[3] else injectArg = null //if there is an arg, use it
		metaLib = metaxploit.load(targetPath) //load lib
		if injectArg then result = metaLib.overflow(memory, value, injectArg) else result = metaLib.overflow(memory, value) //run the exploit
		if typeof(result) != "shell" and typeof(result) != "computer" and typeof(result) != "file" then return print("Error: exploit failed") //exploit failed
		if typeof(result) == "shell" then folder = result.host_computer.File("/")
		if typeof(result) == "computer" then folder = result.File("/")
		if typeof(result) == "file" then
			while result.parent
				result = result.parent
			end while
			folder = result
		end if
		user = checkAccess(folder)
		YorN = user_input("Exploit succeeded! Press any key to continue, press n to escape.\n" + perm + ":" + typeof(result) + " " + memory + " " + value, false ,true) //print exploit success
		if YorN.lower == "n" then return null //escape
		globals.current.obj = result //set current object
		globals.current.folder = folder //set current folder
		globals.current.user = user //set current user
		globals.current.router = globals.local.router //set current router
	end if
end function

commands["computer"]["ps"] = {"name":"ps", "description":"Shows the active processes of the operating system.", "args":""}
commands["computer"]["ps"]["run"] = function(args)
	computer = globals.current.obj //get computer object
	procs = computer.show_procs //get all the processes
	procs = procs.split("\n") //split em
	output = "" //declare output
	for proc in procs //loop thru procs
		val = proc.split(" ") //split proc
		if val[0] == "USER" then continue //ignore USER

		output = output + "\n" + "[" + val[0] + "] (" + val[1] + ") " + val[4] + " " + "CPU: [" + val[2] + "] " + "MEM: [" + val[3] + "]" //update output
	end for
	return print(format_columns(output) + "\n") //print output IN STYLE
end function

commands["computer"]["kill"] = {"name":"kill", "description":"Kill a process.", "args":"[PID]"}
commands["computer"]["kill"]["run"] = function(args)
	if args.len == 0 then return print("Usage: kill [PID]") //test if there is an arg
	PID = args[0].to_int //get PID from argument
	if typeof(PID) != "number" then return print("The PID must be a number.") //LIKE U CAN NOT PUT RANDOM STUFF IN
	computer = globals.current.obj //get computer object
	output = computer.close_program(PID) //close PID
	if output == true then return print("Process " + PID + " closed"); //success
	if output then return print(output) //well u FAIL
	return print("Process " + PID + " not found") //bruh no such PID
end function

commands["computer"]["ls"] = {"name":"ls", "description":"List all files.", "args":"[path]"}
commands["computer"]["ls"]["run"] = function(args)
	computer = globals.current.obj //get computer object
	folderObj = globals.current.folder //get current path
	if args.len == 1 then folderObj = computer.File(args[0])
	if not folderObj then return print("No such directory.")
    return libs.ls(folderObj)
end function

commands["computer"]["cd"] = {"name":"cd", "description":"Moves to a different directory.", "args":"[path]"}
commands["computer"]["cd"]["run"] = function(args)
	computer = globals.current.obj //get computer object
	directory = globals.current.folder //get directory object
	if args.len > 0 then
		path = args[0] //get path
		if path == "." then return true
		if path == ".." then
			if directory.parent then
				globals.current.folder = directory.parent
				return globals.current.folder
			end if
			return print("You are already in the root directory.")
		end if
		if computer.File(path) then //if valid then
			directory = computer.File(path) //update current folder
		else if computer.File(directory.path + "/" + path) then //not valid, check as relative path
			directory = computer.File(directory.path + "/" + path) //update
		else if computer.File(directory.path + path) then //maybe it is "/"
			directory = computer.File(directory.path + path) //update
		else
			return print("No such directory.") //check for everything and failed, print error msg
		end if
	else
		if globals.current.user == "root" then directory = computer.File("/root") else directory = computer.File("/home/" + current.user)
	end if
	if not directory.is_folder then return print("No such directory.")
	globals.current.folder = directory
	return globals.current.folder
end function

commands["computer"]["clog"] = {"name":"clog", "description":"Corrupt log. Delete suspicious entries before execute.", "args":""}
commands["computer"]["clog"]["run"] = function(args)
	return libs.corruptLog(globals.current.obj) //get computer
end function

commands["computer"]["local"] = {"name":"local", "description":"Go back to local shell.", "args":""}
commands["computer"]["local"]["run"] = function(args)
	return allCommands.local(args)
end function

commands["computer"]["cat"] = {"name":"cat", "description":"Shows the contents of a text file.", "args":"[file]"}
commands["computer"]["cat"]["run"] = function(args)
	if args.len == 0 then return null
	computer = globals.current.obj //get computer
	pathFile = args[0] //get path
	file = computer.File(pathFile) //get file with path
	if not typeof(file) == "file" then file = computer.File(current.folder.path + "/" + pathFile) //not found try relative path
	if not typeof(file) == "file" then return print("file not found: " + pathFile) //still not found print error msg
	if file.is_binary then return print("can't open " + file.path + ". Binary file") //file is bin print error msg
	if not file.has_permission("r") then return print("permission denied") //no perm print error msg
	return print(file.get_content) //print file content
end function

commands["computer"]["rm"] = {"name":"rm", "description":"Delete any file if you have the appropriate permissions.", "args":"[file]"}
commands["computer"]["rm"]["run"] = function(args)
	if args.len == 0 then return print("No file specified.")
	pathFile = args[0]
	file = current.obj.File(pathFile)
	if not file then return print("File not found: " + pathFile)
	if not file.has_permission("w") then return print("Permission denied.") //check perm
	file.delete //delete file
	return print("File deleted.") //output
end function

commands["computer"]["hash"] = {"name":"hash", "description":"Reverse hash. Split multiple lines with commas.", "args":"[hash]"}
commands["computer"]["hash"]["run"] = function(args)
	return allCommands.hash(args)
end function

commands["computer"]["passwd"] = {"name":"passwd", "description":"Changes the password of a user.", "args":"[username]"}
commands["computer"]["passwd"]["run"] = function(args)
	if args.len > 0 then user = args[0] else user = globals.current.user
	computer = globals.current.obj
	inputMsg = "Changing password for user " + user +".\nNew password:" //set msg
	inputPass = user_input(inputMsg, true) //show msg and wait for an input
	output = computer.change_password(user, inputPass) //store func call
	if output == true then return print("Password modified OK.")
	return print(output)
end function

commands["computer"]["clear"] = {"name":"clear", "description":"Delete any text from the terminal.", "args":""}
commands["computer"]["clear"]["run"] = function(args)
	return clear_screen //clear the screen
end function

commands["file"] = {}

commands["file"]["help"] = {"name":"help", "description":"List all commands.", "args":""}
commands["file"]["help"]["run"] = function(args) //func that runs
	output = "\n" + "File Commands:" + "\n" //first line that needs to be print
	for command in commands.file //loop thru each command from Commands
		commandData = command.value //store command info in a var
		output = output + "		" + commandData.name + " " + commandData.args.trim + " -> " + commandData.description+"\n" //store info in output ready to be print
	end for
	return print(output) //PRINT IT OUT
end function

commands["file"]["nmap"] = {"name":"nmap", "description":"Scans an ip/domain for ports and local ips.", "args":"[ip/domain]"}
commands["file"]["nmap"]["run"] = function(args)
	return allCommands.nmap(args)
end function

commands["file"]["re"] = {"name":"re", "description":"Remote attack.", "args":"[ip] [port] [(opt) injectArg]"}
commands["file"]["re"]["run"] = function(args)
	return allCommands.re(args)
end function

commands["file"]["lo"] = {"name": "lo","description": "local attack. Must run this script from target terminal.","args": "[libname] [(opt) injectArg]"}
commands["file"]["lo"]["run"] = function(args)
	if not globals.current.publicIp == globals.local.publicIp then return print("You must be on the machine executing this program to use this command.")
	if not globals.current.lanIp == globals.local.lanIp then return print("You must be on the machine executing this program to use this command.")
	fileObj = globals.current.obj //get file object
	if args.len > 0 then
		targetPath = args[0]
		if args.len > 1 then injectArg = args[1] else injectArg = null
		while fileObj.parent
			fileObj = fileObj.parent
		end while
		for folder in fileObj.get_folders
			if not folder.name == "lib" then continue
			targetFile = null
			for file in folder.get_files
				if not file.name == targetPath + ".so" then continue
				targetFile = file
			end for
			if not targetFile then return print("Lib not found.")
			break
		end for	//get all folders
		metaLib = metaxploit.load("/lib/" + targetPath + ".so") //load lib with path and this is what makes it unable to use on remote
		results = libs.attack(metaLib) //get results
		if results.len == 0 then return print("No exploit found!") //no exploit found
		for result in results
			print((results.indexOf(result) + 1) + "." + result.user + ":" + typeof(result.obj) + " " + result.addr + " " + result.vuln)
		end for
		if results.len <= 9 then selectObj = user_input("select an object with number >", false, true).to_int else selectObj = user_input("select an object with number >").to_int //ask user for object number
		if typeof(selectObj) == "number" and selectObj <= results.len then
			selectObj = selectObj - 1
			globals.current.obj = results[selectObj].obj
			globals.current.user = results[selectObj].user
			globals.current.router = globals.local.router
			if typeof(results[selectObj].obj) == "file" then
				while results[selectObj].obj.parent
					results[selectObj].obj = results[selectObj].obj.parent
				end while
				globals.current.folder = results[selectObj].obj
			end if
			if typeof(results[selectObj].obj) == "computer" then globals.current.folder = results[selectObj].obj.File("/")
			if typeof(results[selectObj].obj) == "shell" then globals.current.folder = results[selectObj].obj.host_computer.File("/")
		end if
	end if
end function

commands["file"]["mre"] = {"name":"mre", "description":"Remote attack without scan.", "args":"[ip] [port] [(opt) injectArg]"}
commands["file"]["mre"]["run"] = function(args)
	return allCommands.mre(args)
end function

commands["file"]["mlo"] = {"name":"mlo", "description":"Local attack without scan.", "args":"[libname] [memory] [value] [(opt) injectArg]"}
commands["file"]["mlo"]["run"] = function(args)
	fileObj = globals.current.obj //get file object
	if args.len > 2 then
		if not globals.current.publicIp == globals.local.publicIp then return print("You must be on the machine executing this program to use this command.")
		if not globals.current.lanIp == globals.local.lanIp then return print("You must be on the machine executing this program to use this command.")
		targetPath = args[0] //store target path
		while fileObj.parent
			fileObj = fileObj.parent
		end while
		for folder in fileObj.get_folders
			if not folder.name == "lib" then continue
			targetFile = null
			for file in folder.get_files
				if not file.name == targetPath + ".so" then continue
				targetFile = file
			end for
			if not targetFile then return print("Lib not found.")
			break
		end for	//get all folders
		memory = args[1] //store memory
		value = args[2] //store value
		if args.len > 3 then injectArg = args[3] else injectArg = null //if there is an arg, use it
		metaLib = metaxploit.load(targetPath) //load lib
		if injectArg then result = metaLib.overflow(memory, value, injectArg) else result = metaLib.overflow(memory, value) //run the exploit
		if typeof(result) != "shell" and typeof(result) != "computer" and typeof(result) != "file" then return print("Error: exploit failed") //exploit failed
		if typeof(result) == "shell" then folder = result.host_computer.File("/")
		if typeof(result) == "computer" then folder = result.File("/")
		if typeof(result) == "file" then
			while result.parent
				result = result.parent
			end while
			folder = result
		end if
		user = checkAccess(folder)
		YorN = user_input("Exploit succeeded! Press any key to continue, press n to escape.\n" + perm + ":" + typeof(result) + " " + memory + " " + value, false ,true) //print exploit success
		if YorN.lower == "n" then return null //escape
		globals.current.obj = result //set current object
		globals.current.folder = folder //set current folder
		globals.current.user = user //set current user
		globals.current.router = globals.local.router //set current router
	end if
end function

commands["file"]["ls"] = {"name":"ls", "description":"List all files.", "args":"[path]"}
commands["file"]["ls"]["run"] = function(args)
	currentFolder = globals.current.folder
    if args.len > 0 then
		targetPath = args[0]
		if targetPath[-1] == "/" and targetPath.len > 1 then targetPath = targetPath[:-1]
        if targetPath[0] == "/" then
            while currentFolder.parent
                currentFolder = currentFolder.parent
            end while
            if targetPath.len == 1 then return libs.ls(currentFolder)
            targetPath = targetPath[1:]
            pathList = targetPath.split("/")
			if pathList.len == 0 then pathList.push(targetPath)
            folderTemp = libs.getFile(pathList, currentFolder)
            if not folderTemp then return print("No such directory.")
			if not folderTemp.is_folder then return print("No such directory.")
			return libs.ls(folderTemp)
        end if
        pathList = targetPath.split("/")
		if pathList.len == 0 then pathList.push(targetPath)
        folderTemp = libs.getFile(pathList, currentFolder)
        if not folderTemp then return print("No such directory.")
        if not folderTemp.is_folder then return print("No such directory.")
		return libs.ls(folderTemp)
    end if
    return libs.ls(currentFolder)
end function

commands["file"]["cd"] = {"name":"cd", "description":"Moves to a different directory.", "args":"[path]"}
commands["file"]["cd"]["run"] = function(args)
    currentFolder = globals.current.folder
    if args.len > 0 then
		targetPath = args[0]
        if targetPath == "." then return true
        if targetPath == ".." then
            if currentFolder.parent then
                globals.current.folder = currentFolder.parent
                return globals.current.folder
            end if
            return true
        end if
		if targetPath[-1] == "/" and targetPath.len > 1 then targetPath = targetPath[:-1]
        if targetPath[0] == "/" then
            while currentFolder.parent
                currentFolder = currentFolder.parent
            end while
            if targetPath.len == 1 then
                globals.current.folder = currentFolder
                return true
            end if
            targetPath = targetPath[1:]
            pathList = targetPath.split("/")
			if pathList.len == 0 then pathList.push(targetPath)
            folderTemp = libs.getFile(pathList, currentFolder)
            if not folderTemp then return print("No such directory.")
			if not folderTemp.is_folder then return print("No such directory.")
			globals.current.folder = folderTemp
			return globals.current.folder
        end if
		pathList = targetPath.split("/")
		if pathList.len == 0 then pathList.push(targetPath)
		folderTemp = libs.getFile(pathList, currentFolder)
		if not folderTemp then return print("No such directory.")
		if not folderTemp.is_folder then return print("No such directory.")
		globals.current.folder = folderTemp
		return globals.current.folder
    end if
	while currentFolder.parent
		currentFolder = currentFolder.parent
	end while
	if globals.current.user == "root" then folderTemp = libs.getFile(["root"], currentFolder) else folderTemp = libs.getFile(["home", globals.current.user], currentFolder)
	if not folderTemp then return print("No such directory.")
	if folderTemp.is_folder then
		globals.current.folder = folderTemp
		return globals.current.folder
	end if
	return print("No such directory.")
end function

commands["file"]["local"] = {"name":"local", "description":"Go back to local shell.", "args":""}
commands["file"]["local"]["run"] = function(args)
	return allCommands.local(args)
end function

commands["file"]["cat"] = {"name":"cat", "description":"Shows the contents of a text file.", "args":"[file]"}
commands["file"]["cat"]["run"] = function(args)
	if args.len == 0 then return print("No file specified.")
	currentFolder = globals.current.folder
	pathFile = args[0] //get path
	file = libs.pathGetFile(pathFile, currentFolder)
	if not file then return print("No such File.")
	if file.is_binary then return print("Can't open " + file.path + ". Binary file.")
	if file.is_folder then return print("No such File.")
	if not file.has_permission("r") then return print("permission denied") //no perm print error msg
	return print(file.get_content) //print file content
end function

commands["file"]["rm"] = {"name":"rm", "description":"Delete any file if you have the appropriate permissions.", "args":"[file]"}
commands["file"]["rm"]["run"] = function(args)
	if args.len == 0 then return print("No file specified.")
	pathFile = args[0]
	currentFolder = globals.current.folder
	file = pathGetFile(pathFile, currentFolder)
	if not file then return print("File not found: " + pathFile)
	if not file.has_permission("w") then return print("Permission denied.") //check perm
	file.delete //delete file
	return print("File deleted.") //output
end function

commands["file"]["hash"] = {"name":"hash", "description":"Reverse hash. Split multiple lines with commas.", "args":"[hash]"}
commands["file"]["hash"]["run"] = function(args)
	return allCommands.hash(args)
end function

commands["file"]["clear"] = {"name":"clear", "description":"Delete any text from the terminal.", "args":""}
commands["file"]["clear"]["run"] = function(args)
	return clear_screen //clear the screen
end function

execute = function(input)
        cmd = input.split(" ") //split the input into an array of words
        cmdName = cmd[0] //get the first word as the command name
        args = cmd[1:] //get the rest of the words as the arguments
        if not commands[current.objType].hasIndex(cmdName.lower) then return print("Error: Command not found!") //print error
        command = commands[current.objType][cmdName.lower] //get the command object
        if args.len > 0 then //if there are arguments
            if args[0] == "-h" or args[0] == "--help" then
                return print("Usage :" + command.name + " " + command.args.trim + " -> " + command.description + "\n") //print usage
            end if
        end if
        command.run(args) //run the command
        return null
end function

main = function()
	clear_screen
	while true
		print("<color=white>-</color><color=yellow>(</color>" + current.user + "<color=white>:</color><color=grey>" + current.objType + "</color><color=#ffbfbf>@</color>" + current.publicIp + "<color=white>~</color>" + current.lanIp + "<color=yellow>)</color><color=white>-</color>[" + current.folder.path + "]")
		if current.user == "root" then
			input = user_input("<color=white>-</color><color=red>#</color> ")
		else
			input = user_input("<color=white>-</color><color=yellow>$</color> ")
		end if
		execute(input)
	end while
end function
main
