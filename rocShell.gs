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
//GET THOSE LIBS

globals.localShell = get_shell
globals.localComputer = globals.localShell.host_computer
globals.localRouter = get_router
globals.localFolder = current_path
globals.localUser = active_user
globals.localLanIp = globals.localComputer.local_ip
globals.localPublicIp = globals.localRouter.public_ip
//declare some "consts"

globals.currentObj = globals.localShell
globals.currentRouter = globals.localRouter
globals.currentFolder = globals.localFolder
globals.currentUser = globals.localUser
//init some vars

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
//funcs that return info

Commands = {} //all the commands are here

Commands["help"] = {"Name": "help","Description": "List all commands.","Args": "","Shell":false} //info
Commands["help"]["Run"] = function(args) //func that runs
	output = "\n" + "Commands:" + "\n" //first line that needs to be print
	for Command in Commands //loop thru each command from Commands
		CommandData = Command.value //store command info in a var
		if CommandData.Shell == 1 and globals.currentObjType == "computer" then continue //if we cant exec this cmd, we dont print it
		output = output + "		" + CommandData.Name + " " + CommandData.Args.trim + " -> " + CommandData.Description+"\n" //store info in output ready to be print
	end for
	return print(output) //PRINT IT OUT
end function

Commands["re"] = {"Name": "re","Description": "Remote attack.","Args": "[ip] [port] [(opt) injectArg]","Shell":false}
Commands["re"]["Run"] = function(args)
	if args.len > 1 then //only run if there is at least 2 arguments
		targetIp = args[0] //store target ip
		if not is_valid_ip(targetIp) then //if not valid, maybe it is a domain
			if is_valid_ip(nslookup(targetIp)) then //nice it is a domain
				targetIp = nslookup(targetIp) //then set target ip to the ip behide the domain
			else //OOPS
				return print("IP not found!") //you are fd
			end if
		end if
		targetPort = args[1].to_int //store the port as integer
		if typeof(targetPort) != "number" then return print("Port invalid.") //dont put random args PLS
		if args.len > 2 then injectArg = args[2] else injectArg = null //if there is an arg[2], use it
		
		netSession = metaxploit.net_use(targetIp, targetPort) //get net session using target ip and port
		if typeof(netSession) != "NetSession" then return null //did not get the net session, sth is wrong
		metaLib = netSession.dump_lib //get the lib from net session
		
		memorys = metaxploit.scan(metaLib) //scan for memory
		
		results = [] //declare results list
		for memory in memorys //loop thru memorys
			addresses = metaxploit.scan_address(metaLib, memory).split("Unsafe check:") //scan for exploit, store it
			for address in addresses //loop thru addresses
				if address == addresses[0] then continue //ignore first line
				
				value = address[address.indexOf("<b>")+3:address.indexOf("</b>")] //get value from address, store it
				value = value.replace("\n", "") //get rid of line break
				if injectArg then result = metaLib.overflow(memory, value, injectArg) else result = metaLib.overflow(memory, value) //run the exploit
				if typeof(result) != "shell" and typeof(result) != "computer" then continue //WE IGNORE ALL THE FILES, WE DONT DO THAT HERE
				if typeof(result) == "shell" then computer = result.host_computer else computer = result //get the computer object for perm testing

				permTest = computer.File("/root") //test perm with path "/root"
				perm = null //declare perm
				if permTest.has_permission("w") then //nice it is root we are in
					perm = "root"
				else if permTest.has_permission("r") then //well not so bad
					perm = "user"
				else
					perm = "guest" //at least we got something
				end if
				resultMap = {"perm": perm, "obj": result, "addr": memory, "vuln": value} //store result as a map
				results.push(resultMap) //push the map in results list
			end for
		end for
		for result in results //loop to print result
			print((results.indexOf(result) + 1) + "." + result.perm + ":" + typeof(result.obj) + " " + result.addr + " " + result.vuln) //print it with number
		end for
		selectObj = user_input("select an object with number >").to_int //let user dicide which one to use
		if typeof(selectObj) == "number" and selectObj <= results.len then //TRY NOT TO THROW RANDOM STUFF IN
			selectObj = selectObj - 1 //minus 1 makes the number index
			globals.currentObj = results[selectObj].obj //update object
			if not is_lan_ip(targetIp) then globals.currentRouter = get_router(targetIp)//update router
			globals.currentFolder = "/" //update path
			globals.currentUser = results[selectObj].perm //update username
		end if
	end if
end function

Commands["lo"] = {"Name": "lo","Description": "local attack. Must run this script from target terminal.","Args": "[lib_path] [(opt) injectArg]","Shell":false}
Commands["lo"]["Run"] = function(args)
	if (globals.currentLanIp != globals.localLanIp) or (globals.currentPublicIp != globals.localPublicIp) then return print("This command only works locally.") //no local no run
	if args.len > 0 then
		targetPath = args[0]
		if args.len > 1 then injectArg = args[1] else injectArg = null
		targetFile = currentComp.File(targetPath) //get file object
		if not targetFile then return print("No such file or directory") //test if there is this file
		metaLib = metaxploit.load(targetPath) //load lib with path and this is what makes it unable to use on remote
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
	computer = globals.currentComp //get computer object

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

Commands["kill"] = {"Name": "kill","Description": "Kills a process","Args": "[PID]","Shell":false}
Commands["kill"]["Run"] = function(args)
	if args.len > 0 then
		PID = args[0].to_int //get PID from argument
		if typeof(PID) != "number" then return print("The PID must be a number\n" + command_info("kill_usage")) //LIKE U CAN NOT PUT RANDOM STUFF IN
		computer = globals.currentComp //get computer object
		output = computer.close_program(PID) //close PID
		if output == true then return print("Process " + PID + " closed"); //success
		if output then return print(output) //well u FAIL
		return print("Process " + PID + " not found") //bruh no such PID
	end if
end function

Commands["ls"] = {"Name": "ls","Description": "List all files.","Args": "[(opt) path]","Shell":false}
Commands["ls"]["Run"] = function(args)
	computer = globals.currentComp //get computer object
	folderPath = globals.currentFolder //get current path
	fileSize = function(bytes) //translate byte to kb and mb
		bytes = bytes.to_int
		i=0
		units = ["B","KB","MB","GB","TB","PT"]
		while bytes > 1024
			bytes=bytes/1024
			i=i+1
		end while
		return round(bytes,2) + units[i]
	end function
	if args.len == 1 then //if there is an arg use it as path
		folderPath = args[0]
	end if
	
	folder = computer.File(folderPath) //get file object
	if folder == null then
		return print("No such file or directory")
	else
		subFiles = folder.get_folders + folder.get_files //get all files and folders under the object
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
			if subFile.has_permission("w") then WRX = WRX+"w" else WRX = WRX+"-" //set wrx as perms
			if subFile.has_permission("r") then WRX = WRX+"r" else WRX = WRX+"-"
			if subFile.has_permission("x") then WRX = WRX+"x" else WRX = WRX+"-"

			output = output + "\n" + subFile + ">" + nameFile + " [" + type + "] [" + WRX + "] [" + fileSize(size) + "] [" + permission + "] [" + owner + "] [" + group + "]" //update output
		end for
		print(format_columns(output)) //print output
		return print("\n") //new line
	end if
end function

Commands["cd"] = {"Name": "cd","Description": "Moves to a different directory.","Args": "[path]","Shell":false}
Commands["cd"]["Run"] = function(args)
	computer = globals.currentComp
	if args.len > 0 then
		if computer.File(args[0]) then //if valid then
			globals.currentFolder = computer.File(args[0]).path //update currentFolder
		else if computer.File(globals.currentFolder + "/" + args[0]) then //not valid, check as relative path
			globals.currentFolder = computer.File(globals.currentFolder + "/"+args[0]).path //update
		else if computer.File(globals.currentFolder + args[0]) then //maybe it is "/"
			globals.currentFolder = computer.File(globals.currentFolder + args[0]).path //update
		else
			return print("No such file or directory") //check for everything and failed, print error msg
		end if
	else
		if (globals.currentLanIp == globals.localLanIp) and (globals.currentPublicIp == globals.localPublicIp) and globals.currentUser == globals.localUser then
			globals.currentFolder = home_dir //update currentFolder to home_dir
		end if
	end if
	return globals.currentFolder //useless line but I want my funcs to return sth
end function

Commands["cd.."] = {"Name": "cd..","Description": "Moves to parent folder.","Args": "","Shell":false}
Commands["cd.."]["Run"] = function(args)
	computer = globals.currentComp //get computer
	globals.currentFolder = parent_path(globals.currentFolder) //update currentFolder to its parent_path
	return globals.currentFolder //useless I guess
end function

Commands["shell"] = {"Name": "shell","Description": "Starts a normal shell.","Args": "","Shell":true} //Shell true so it doesnt run on computer object
Commands["shell"]["Run"] = function(args)
	return globals.currentObj.start_terminal() //just shell.start_terminal
end function

Commands["up"] = {"Name": "up","Description": "Uploads a file.","Args": "[path]","Shell":true}
Commands["up"]["Run"] = function(args)
	if args.len > 0 then
		pathFile = args[0]

		file = globals.localComputer.File(pathFile) //get file
		if file == null then return print("file not found: " + pathFile) //not found print error msg

		print("Uploading file to: " + globals.currentFolder + "/" + file.name + "\n") //found print target path
		x = globals.localShell.scp(file.path, globals.currentFolder, globals.currentObj) //store func call in x
		if(x == 1) then //success
			return print("File uploaded successfully.") //print success msg
		else //fail
			return print("Error: " + x + " did not upload.") //print fail msg
		end if
	else
		return print("Error: null did not upload.") //I wrote this line for those dont have an arg, and I wrote it like it did try upload file "null"
	end if
end function

Commands["dl"] = {"Name": "dl","Description": "Downloads a file.","Args": "[path]","Shell":true} //upload but uno reverse card
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
		computer = globals.currentComp //get computer
		pathFile = args[0] //get path
		file = computer.File(pathFile) //get file with path
		if file == null then file = computer.File(currentFolder+"/"+pathFile) //not found try relative path
		if file == null then return print("file not found: "+pathFile) //still not found print error msg
		if file.is_binary then return print("can't open "+file.path+". Binary file") //file is bin print error msg
		if not file.has_permission("r") then return print("permission denied") //no perm print error msg

		return print(file.get_content) //print file content
	end if
end function

Commands["rm"] = {"Name": "rm","Description": "Delete any file if you have the appropriate permissions.","Args": "[file]","Shell":false}
Commands["rm"]["Run"] = function(args)
	if args.len > 0 then
		computer = globals.currentComp
		pathFile = args[0]
		file = computer.File(pathFile)
		if file == null then return print("file not found: "+pathFile)
		if not file.has_permission("w") then return print("permission denied") //check perm
		file.delete //delete file
		return print("File deleted.") //output
	end if
end function

Commands["hash"] = {"Name": "hash","Description": "Cracks hash. Split multiple lines with commas.","Args": "[hash]","Shell":false}
Commands["hash"]["Run"] = function(args)
	if args.len > 0 then
		hashes = args[0].split(",") //split multiple hash
		if hashes.len == 0 then hashes.push(args[0]) //no comma then push hash in
		for hash in hashes //loop thru each hash
			userPass = hash.split(":") //split user and pass
			password = cryptools.decipher(userPass[1]) //decipher pass
			print(userPass[0] + ":" + password) //output
		end for
	end if
end function

Commands["passwd"] = {"Name": "passwd","Description": "Changes the password of a user","Args": "[username]","Shell":false}
Commands["passwd"]["Run"] = function(args)
	if args.len > 0 then
		computer = globals.currentComp

		inputMsg = "Changing password for user " + args[0] +".\nNew password:" //set msg
		inputPass = user_input(inputMsg, true) //show msg and wait for an input

		output = computer.change_password(args[0], inputPass) //store func call
		if output == true then return print("password modified OK")
		if output then return print(output)
		return print("password not modified")
	end if
end function

Commands["nmap"] = {"Name": "nmap","Description": "Scans an ip/domain for ports and local ips.","Args": "[ip/domain]","Shell":false}
Commands["nmap"]["Run"] = function(args)
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
			router = globals.currentRouter //get router
			netSession = metaxploit.net_use(router.public_ip) //get net session
			routerLib = netSession.dump_lib //get router lib
			lanPorts = router.device_ports(ipAddr) //get local ports
			publicPorts = router.used_ports //get public ports
			
			print("\n<b>" + "Local Machine at " + ipAddr) //print first line
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
					if iPort.port_number == lanPort.port_number and iPort.get_lan_ip == ipAddr then
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
		else //if ip is not local
			router = get_router(ipAddr) //get router
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
		end if
	end if
end function



Commands["clear"] = {"Name": "clear","Description": "Delete any text from the terminal.","Args": "","Shell":false}
Commands["clear"]["Run"] = function(args)
	return clear_screen //clear the screen
end function

execCmd = function(input) //executes a command
	cmd = input.split(" ") //split the input into an array of words
	cmdName = cmd[0] //get the first word as the command name
	args = cmd[1:] //get the rest of the words as the arguments
	if Commands.hasIndex(cmdName) then //if the command exists
		command = Commands[cmdName] //get the command
		if command.Shell == 1 and globals.currentObjType == "computer" then //if the command requires a shell and the current object is a computer
			return print("A shell is required for this command." + "\n") //print error
		end if
		if args.len > 0 then //if there are arguments
			if args[0] == "-h" or args[0] == "--help" then
			return print("Usage :" + command.Name + " " + command.Args.trim + " -> " + command.Description + "\n") //print usage
			end if
		end if
		command.Run(args) //run the command
	else
		return print("Error: Command not found!") //print error
	end if
	return null
end function

clear_screen //clear the screen

menu = function() //menu function
	rocShell = function() //rocShell function
		input = user_input(globals.currentUser + ":" + globals.currentObjType + "@" + globals.currentPublicIp + "~" + globals.currentLanIp + ":~" + globals.currentFolder + "\n" + ">") //show info on screen and get input
		execCmd(input) //execute the command
		rocShell //loop
	end function
	rocShell //call rocShell
end function

menu //call menu