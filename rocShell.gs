globals.metaxploit = include_lib("/lib/metaxploit.so")
if not metaxploit then
	metaxploit = include_lib(current_path + "/metaxploit.so")
	if not metaxploit then exit("Error: missing lib metaxploit.so")
end if
globals.cryptools = include_lib("/lib/crypto.so")
if not cryptools then
	cryptools = include_lib(current_path + "/crypto.so")
	if not cryptools then exit("Error: missing lib crypto.so")
end if

globals.localShell = get_shell
globals.localComputer = globals.localShell.host_computer
globals.localRouter = get_router
globals.localFolder = current_path
globals.localUser = active_user
globals.localLanIp = globals.localComputer.local_ip
globals.localPublicIp = globals.localRouter.public_ip

globals.currentObj = globals.localShell
globals.currentRouter = globals.localRouter
globals.currentFolder = globals.localFolder
globals.currentUser = globals.localUser

globals.currentObjType = function()
	return typeof(globals.currentObj)
end function
globals.currentComp = function()
	if globals.currentObjType == "shell" then return globals.currentObj.host_computer else return globals.currentObj
end function
globals.currentPublicIp = function()
	return globals.currentRouter.public_ip
end function
globals.currentLanIp = function()
	return globals.currentComp.local_ip
end function

Commands = {}

Commands["help"] = {"Name": "help","Description": "List all commands.","Args": "","Shell":false}
Commands["help"]["Run"] = function(args)
	output = "\n" + "Commands:" + "\n"
	for Command in Commands
		CommandData = Command.value
		if CommandData.Shell == 1 and globals.currentObjType == "computer" then continue
		output = output + "		" + CommandData.Name + " " + CommandData.Args.trim + " -> " + CommandData.Description+"\n"
	end for
	return print(output)
end function

Commands["re"] = {"Name": "re","Description": "Remote attack.","Args": "[ip] [port] [(opt) injectArg]","Shell":false}
Commands["re"]["Run"] = function(args)
	if args.len > 1 then
		targetIp = args[0]
		if not is_valid_ip(targetIp) then
			if is_valid_ip(nslookup(targetIp)) then
				targetIp = nslookup(targetIp)
			else
				return print("IP not found!")
			end if
		end if
		targetPort = args[1].to_int
		if typeof(targetPort) != "number" then return print("Port invalid.")
		if args.len > 2 then injectArg = args[2] else injectArg = null
		
		netSession = metaxploit.net_use(targetIp, targetPort)
		if typeof(netSession) != "NetSession" then return null
		metaLib = netSession.dump_lib
		
		memorys = metaxploit.scan(metaLib)
		
		results = []
		for memory in memorys
			addresses = metaxploit.scan_address(metaLib, memory).split("Unsafe check:")
			for address in addresses
				if address == addresses[0] then continue
				
				value = address[address.indexOf("<b>")+3:address.indexOf("</b>")]
				value = value.replace("\n", "")
				if injectArg then result = metaLib.overflow(memory, value, injectArg) else result = metaLib.overflow(memory, value)
				if typeof(result) != "shell" and typeof(result) != "computer" then continue
				if typeof(result) == "shell" then computer = result.host_computer else computer = result

				permTest = computer.File("/root")
				perm = null
				if permTest.has_permission("w") then
					perm = "root"
				else if permTest.has_permission("r") then
					perm = "user"
				else
					perm = "guest"
				end if
				resultMap = {"perm": perm, "obj": result, "addr": memory, "vuln": value}
				results.push(resultMap)
			end for
		end for
		for result in results
			print((results.indexOf(result) + 1) + "." + result.perm + ":" + typeof(result.obj) + " " + result.addr + " " + result.vuln)
		end for
		selectObj = user_input("select an object with number >").to_int
		if typeof(selectObj) == "number" and selectObj <= results.len then
			selectObj = selectObj - 1
			globals.currentObj = results[selectObj].obj
			globals.currentRouter = get_router(targetIp)
			globals.currentFolder = "/"
			globals.currentUser = results[selectObj].perm
		end if
	end if
end function

Commands["lo"] = {"Name": "lo","Description": "local attack. Must run this script from target terminal.","Args": "[lib_path] [(opt) injectArg]","Shell":false}
Commands["lo"]["Run"] = function(args)
	if (globals.currentLanIp != globals.localLanIp) or (globals.currentPublicIp != globals.localPublicIp) then return print("This command only works locally.")
	if args.len > 0 then
		targetPath = args[0]
		if args.len > 1 then injectArg = args[1] else injectArg = null
		targetFile = currentComp.File(targetPath)
		if not targetFile then return print("No such file or directory")
		metaLib = metaxploit.load(targetPath)
		memorys = metaxploit.scan(metaLib)
		results = []
		for memory in memorys
			addresses = metaxploit.scan_address(metaLib, memory).split("Unsafe check:")
			for address in addresses
				if address == addresses[0] then continue
				
				value = address[address.indexOf("<b>")+3:address.indexOf("</b>")]
				value = value.replace("\n", "")
				if injectArg then result = metaLib.overflow(memory, value, injectArg) else result = metaLib.overflow(memory, value)
				if typeof(result) != "shell" and typeof(result) != "computer" then continue
				if typeof(result) == "shell" then computer = result.host_computer else computer = result
				
				permTest = computer.File("/root")
				perm = null
				if permTest.has_permission("w") then
					perm = "root"
				else if permTest.has_permission("r") then
					perm = "user"
				else
					perm = "guest"
				end if
				resultMap = {"perm": perm, "obj": result, "addr": memory, "vuln": value}
				results.push(resultMap)
			end for
		end for
		for result in results
			print((results.indexOf(result) + 1) + "." + result.perm + ":" + typeof(result.obj) + " " + result.addr + " " + result.vuln)
		end for
		selectObj = user_input("select an object with number >").to_int
		if typeof(selectObj) == "number" and selectObj <= results.len then
			selectObj = selectObj - 1
			globals.currentObj = results[selectObj].obj
			globals.currentFolder = "/"
			globals.currentUser = results[selectObj].perm
			globals.currentRouter = globals.localRouter
		end if
	end if
end function

Commands["ps"] = {"Name": "ps","Description": "Shows the active processes of the operating system.","Args": "","Shell":false}
Commands["ps"]["Run"] = function(args)
	computer = globals.currentComp

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

Commands["kill"] = {"Name": "kill","Description": "Kills a process","Args": "[PID]","Shell":false}
Commands["kill"]["Run"] = function(args)
	if args.len > 0 then
		PID = args[0].to_int
		if typeof(PID) != "number" then return print("The PID must be a number\n" + command_info("kill_usage"))
		if currentObjType == "shell" then computer = globals.currentObj.host_computer else computer = globals.currentObj
		output = computer.close_program(PID)
		if output == true then return print("Process " + PID + " closed");
		if output then return print(output)
		return print("Process " + PID + " not found")
	end if
end function

Commands["ls"] = {"Name": "ls","Description": "List all files.","Args": "[(opt) path]","Shell":false}
Commands["ls"]["Run"] = function(args)
	if currentObjType == "shell" then computer = globals.currentObj.host_computer else computer = globals.currentObj
	folderPath = globals.currentFolder
	fileSize = function(bytes)
		bytes = bytes.to_int
		i=0
		units = ["B","KB","MB","GB","TB","PT"]
		while bytes > 1024
			bytes=bytes/1024
			i=i+1
		end while
		return round(bytes,2) + units[i]
	end function
	if args.len == 1 then
		folderPath = args[0]
	end if
	
	folder = computer.File(folderPath)
	if folder == null then
		return print("No such file or directory")
	else
		subFiles = folder.get_folders + folder.get_files
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
			if subFile.has_permission("w") then WRX = WRX+"w" else WRX = WRX+"-"
			if subFile.has_permission("r") then WRX = WRX+"r" else WRX = WRX+"-"
			if subFile.has_permission("x") then WRX = WRX+"x" else WRX = WRX+"-"

			output = output + "\n" + subFile + ">" + nameFile + " [" + type + "] [" + WRX + "] [" + fileSize(size) + "] [" + permission + "] [" + owner + "] [" + group + "]" 
		end for
		
		return print(format_columns(output))
	end if
end function

Commands["cd"] = {"Name": "cd","Description": "Moves to a different directory.","Args": "[path]","Shell":false}
Commands["cd"]["Run"] = function(args)
	computer = globals.currentComp
	if args.len > 0 then
		if computer.File(args[0]) then
			globals.currentFolder = computer.File(args[0]).path
		else if computer.File(globals.currentFolder + "/" + args[0]) then
			globals.currentFolder = computer.File(globals.currentFolder + "/"+args[0]).path
		else if computer.File(globals.currentFolder + args[0]) then
			globals.currentFolder = computer.File(globals.currentFolder + args[0]).path
		else
			return print("No such file or directory")
		end if
	end if
	return globals.currentFolder
end function

Commands["cd.."] = {"Name": "cd..","Description": "Moves to parent folder.","Args": "","Shell":false}
Commands["cd.."]["Run"] = function(args)
	computer = globals.currentComp
	globals.currentFolder = parent_path(globals.currentFolder)
	return globals.currentFolder
end function

Commands["shell"] = {"Name": "shell","Description": "Starts a normal shell.","Args": "","Shell":true}
Commands["shell"]["Run"] = function(args)
	return globals.currentObj.start_terminal()
end function

Commands["up"] = {"Name": "up","Description": "Uploads a file.","Args": "[path]","Shell":true}
Commands["up"]["Run"] = function(args)
	if args.len > 0 then
		pathFile = args[0]

		file = globals.localComputer.File(pathFile)
		if file == null then return print("file not found: " + pathFile)

		print("Uploading file to: " + globals.currentFolder + "/" + file.name + "\n")
		x = globals.localShell.scp(file.path, globals.currentFolder, globals.currentObj)
		if(x == 1) then
			return print("File uploaded successfully.")
		else
			return print("Error: " + x + " did not upload.")
		end if
	else
		return print("Error: null did not upload.")
	end if
end function

Commands["dl"] = {"Name": "dl","Description": "Downloads a file.","Args": "[path]","Shell":true}
Commands["dl"]["Run"] = function(args)
	if args.len > 0 then
		pathFile = args[0]

		file = globals.currentObj.host_computer.File(pathFile)
		if file == null then return print("file not found: " + pathFile)

		print("Downloading file to: " + home_dir + "/Downloads/" + file.name + "\n")
		x = globals.currentObj.scp(file.path, home_dir + "/Downloads/", globals.localShell)
		if(x == 1) then
			return print("File downloaded successfully.")
		else
			return print("Error: " + x + " did not download.")
		end if
	else
		return print("Error: null did not download.")
	end if
end function

Commands["cat"] = {"Name": "cat","Description": "Shows the contents of a text file.","Args": "[file]","Shell":false}
Commands["cat"]["Run"] = function(args)
	if args.len > 0 then
		computer = globals.currentComp
		pathFile = args[0]
		file = computer.File(pathFile)
		if file == null then file = computer.File(currentFolder+"/"+pathFile)
		if file == null then return print("file not found: "+pathFile)
		if file.is_binary then return print("can't open "+file.path+". Binary file")
		if not file.has_permission("r") then return print("permission denied")

		return print(file.get_content)
	end if
end function

Commands["rm"] = {"Name": "rm","Description": "Delete any file if you have the appropriate permissions.","Args": "[file]","Shell":false}
Commands["rm"]["Run"] = function(args)
	if args.len > 0 then
		computer = globals.currentComp
		pathFile = args[0]
		file = computer.File(pathFile)
		if file == null then return print("file not found: "+pathFile)
		if not file.has_permission("w") then return print("permission denied")
		file.delete
		return print("File deleted.")
	end if
end function

Commands["hash"] = {"Name": "hash","Description": "Cracks hash. Split multiple lines with commas.","Args": "[hash]","Shell":false}
Commands["hash"]["Run"] = function(args)
	if args.len > 0 then
		hashes = args[0].split(",")
		if hashes.len == 0 then hashes.push(args[0])
		for hash in hashes
			userPass = hash.split(":")
			password = cryptools.decipher(userPass[1])
			print(userPass[0] + ":" + password)
		end for
	end if
end function

Commands["passwd"] = {"Name": "passwd","Description": "Changes the password of a user","Args": "[username]","Shell":false}
Commands["passwd"]["Run"] = function(args)
	if args.len > 0 then
		computer = globals.currentComp

		inputMsg = "Changing password for user " + args[0] +".\nNew password:"
		inputPass = user_input(inputMsg, true)

		output = computer.change_password(args[0], inputPass)
		if output == true then return print("password modified OK")
		if output then return print(output)
		return print("password not modified")
	end if
end function

Commands["nmap"] = {"Name": "nmap","Description": "Scans an ip/domain for ports and local ips.","Args": "[ip/domain]","Shell":false}
Commands["nmap"]["Run"] = function(args)
	if args.len > 0 then
		targetIp = args[0]
		port = null
		ipAddr = null
		if not is_valid_ip(targetIp) then
			if is_valid_ip(nslookup(targetIp)) then
				targetIp = nslookup(targetIp)
			else
				return print("IP not found!")
			end if
		end if
		ipAddr = targetIp
		if is_lan_ip(ipAddr) then
			router = globals.currentRouter
			netSession = metaxploit.net_use(router.public_ip)
			routerLib = netSession.dump_lib
			lanPorts = router.device_ports(ipAddr)
			publicPorts = router.used_ports
			
			print("\n<b>" + "Local Machine at " + ipAddr)
			if lanPorts.len == 0 then print("| | --> <i>" + "No local ports detected.</b>")
			for lanPort in lanPorts
				s = "| |"
				if lanPort.is_closed then
					s = s+"-X-> "
				else
					s = s+"---> "
				end if
				s = s + ":" + lanPort.port_number + " "
				s = s + router.port_info(lanPort)
				for publicPort in publicPorts
					iPort = router.ping_port(publicPort.port_number)
					if iPort.port_number == lanPort.port_number and iPort.get_lan_ip == ipAddr then
						s = s + "-->" + " External Address: " + router.public_ip + "" + ":" + publicPort.port_number
					end if
				end for
				print(s)
			end for
			
			print("|\n|---> <b>" + router.essid_name + "</b> (" + router.bssid_name + ")")
			print("      " + "Public IP: <b>" + router.public_ip + "</b>  " + "Private IP: <b>" + router.local_ip + "</b>")

			whoisLines = whois(router.public_ip).split(char(10))
			for whoisLine in whoisLines
				if whoisLine.len > 1 then
					cols = whoisLine.split(":")
					print("      <b>"+ cols[0] + ":</b> " + cols[1:].join(""))
				end if
			end for

			print("      " + routerLib.lib_name + " is at version: " + routerLib.version)
			if not router.kernel_version then
				print("Warning: " + "kernel_router.so not found")
			else
				print("      kernel_router.so is at version: " + router.kernel_version)
			end if
		else
			router = get_router(ipAddr)
			routerLib = metaxploit.net_use(router.public_ip)
			netSession = metaxploit.net_use(router.public_ip)
			routerLib = netSession.dump_lib
			publicPorts = router.used_ports

			if router.essid_name == "" then
				essid_name = "<i>No ESSID</i>"
			else
				essid_name = router.essid_name
			end if
			
			print("\n<b>" + essid_name + "</b> (" + router.bssid_name + ")")
			print("Public IP: <b>" + router.public_ip + "</b>  Private IP: <b>" + router.local_ip + "</b>")
			
			whoisLines = whois(router.public_ip).split(char(10))
			for whoisLine in whoisLines
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
				print(" |  |"+arrows+" :" + publicPort.port_number + router.port_info(publicPort).split(" ")[0] + router.port_info(publicPort).split(" ")[1] +arrows2 + publicPort.get_lan_ip)
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
				print("kernel_router.so : v" + router.kernel_version)
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
		end if
	end if
end function



Commands["clear"] = {"Name": "clear","Description": "Delete any text from the terminal.","Args": "","Shell":false}
Commands["clear"]["Run"] = function(args)
	return clear_screen
end function

execCmd = function(input)
	cmds = input.split(";")
	if cmds.len == 0 then cmds.push(input)
	for cmd in cmds
		args = cmd.split(" ")
		if args.len == 0 then args.push(cmd)
		cmdName = args[0].lower
		args.pull

		if Commands.hasIndex(cmdName) then
			command = Commands[cmdName]
			if command.Shell == 1 and globals.currentObjType == "computer" then
				print("A shell is required for this command." + "\n")
				continue
			end if
			if args.len > 0 then
				if args[0] == "-h" or args[0] == "--help" then
				print("Usage :" + command.Name + " " + command.Args.trim + " -> " + command.Description + "\n")
				continue
				end if
			end if
			command.Run(args)
		else
			print("Error: Command not found!")
		end if

	end for
	return null
end function

clear_screen

menu = function()
	rocShell = function()
		input = user_input(globals.currentUser + ":" + globals.currentObjType + "@" + globals.currentPublicIp + "~" + globals.currentLanIp + ":~" + globals.currentFolder + "\n" + ">")
		execCmd(input)
		rocShell
	end function
	rocShell
end function

menu