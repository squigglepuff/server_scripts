#!/usr/bin/python

'''
    ExiBot
    an exim queue bot to help maintain the exim queues on shared boxes.
    
    This bot serves a simply purpose: it logs in to userboxes for shared and checks their exim queue if their queue is over 1500 messages.
    It will then output it's findings for the userbox to a file on localhost so they can be pulled by a simply Python web server for local boxes to view.
'''

import re, sys, socket, time
import paramiko
import getpass
from datetime import date

dt = date.today() # Simply used to grab the DateTime for setting up the log.
logPath = "log/exibot-runtime-"+dt.strftime("%Y:%m:%d")+".log" # File path to log file.
verbose = 0 # Do we need to be verbose?
debug = 0 # Do we want debug messages?
logEnt = [] # This list contains all the entries that will be dumped to the log.
output = [] # This list contains the std output to be dumped when running.
addrIds = [] # This list contains spammer addresses.
authIds = [] # This is a list of auth_ids for frozen message grep'ing.
boxList = [] # This is a list of boxes that the user has either specified in "boxes.bad" or given manually.
spammerInfo = [] # This list contains the finished notes to be dumped into the file.
grabIds = False # Are we going to be grabbing IDs in DumpStdout?
grabSingle = False # Are we going to be grabbing a ID in DumpStdout?
grabDump = False # Are we going to be grabbing an email header/body/log dump in DumpStdout?
grabAuth = False # Are we needing to grab auth_ids
exiID = "" # A single exim email ID to be dumped.
exiDump = "" # The exim header/body/log dump.
boxName = "box401" # Our current userbox to scan.
note = "= SPAMMING =\n# NOT SCANNED #\n\nThis user appears to have a compromised email address. I have cleared the spam messages from the exim queue but please go over the CAN SPAM ACT and sending rules with them along with having them secure all email address's, scanning their network/devices for malware, and securing all sending forms.\n\nIF THESE ARE MARKETING-TYPE EMAILS: Inform the customer that our servers are NOT geared for that and recommend that they look into a service such as Constant Contact or MailChimp for mailing lists.\n\n> DETAILS <\n" # The note to head our findings.
exibotFoot = "\n\n@.@ ExiBot Found You! @.@\n"  # The footer of the note.

'''
    Log function
    
    This function simply takes an input line, colorizes it for output to stdout on the controlling terminal and then appends the line to the log lines to be dumped.
    
    @param[in] line:string - This is the line to be logged. Line-feeds are needed in this line as they are not auto-appended.
    @return void
'''
def Log(line):
    if "FATAL:" in line:
        sys.stdout.write("\033[1;31m"+str(line))
        logEnt.append(line)
    elif "ERROR:" in line:
        sys.stdout.write("\033[31m"+str(line))
        logEnt.append(line)
    elif "WARN:" in line:
        sys.stdout.write("\033[33m"+str(line))
        logEnt.append(line)
    elif "INFO:" in line:
        sys.stdout.write("\033[32m"+str(line))
        logEnt.append(line)
    elif "DEBUG:" in line:
        if 1 == debug:
            sys.stdout.write("\033[35m"+str(line))
            logEnt.append(line)
        else:
            pass
    else:
        sys.stdout.write(line)
        logEnt.append(line)
    
    sys.stdout.write("\033[0m")

'''
    WriteLog function
    
    This function writes the current log buffer out to the disk. It will also flush the buffer thereby freeing memory.
    
    @param[in] void
    @return void
'''
def WriteLog():
    try:
        hFile = open(logPath, "w+")
    except:
        sys.stderr.write("ERROR: Unable to open "+logPath+"\n")
    
    if not hFile:
        sys.stderr.write("ERROR: Unable to open "+logPath+"\n")
    else:
        hFile.write("\n==== Log Opened @ "+str(int(time.time()))+" ====\n")
        
        for idx in range(0, len(logEnt)):
            hFile.write(str(logEnt[idx]))
        
        hFile.write("==== Log Closed @ "+str(int(time.time()))+" ====\n")
        
        hFile.close()

'''
    String to Hexadecimal function
    
    This function takes an input string and converts each character to it's equivilent hexadecimal value. Each character is auto-separated by spaces.
    
    @param[in] line:string - This is the string/line to be converted.
    @return string - This is the converted hexadecimal string.
'''
def strtohex(string):
    rtn = ""
    for idx in range(0, len(string)):
        rtn += hex(ord(string[idx])) + " ";
    
    return rtn

'''
    Dump Stdout function
    
    This function reads from the sessions (socket-style) buffer and parses it. The function will ignore lines that are only whitespace/line-feeds along with also auto-removing carriage-returns. The function will also, due to it's inherit design, tokenize lines by splitting them at the line-feed character as to prevent incredibly messy output/logging.
    This function looks for two distinct things: prompt and sudo passwd prompt. The first is designated by "[grunt.*" and "[(b|h|f|j)-u-$user.*". If the function captures this line, it returns 0 telling the calling function "I've finished." The second, sudo, is designated by "^[sudo].*", if the function captures this, it'll auto input the user's sudo password as provided at the start of the application.
    The last piece of the function then does some additional parsing on the lines based off of the current wanted data. 99% of the time, this data will be simply cmd output and the function does no additional parsing and simply logs it. Otherwise, it'll pull out email addresses, a single exim ID, or the email dump and fill the appropriate global variables.
    
    @param[in] session:Channel - This is the active SSH session.
    @param[in] log:List - This is the output list that'll be dumped to the user.
    @return int - 0 means "I've finished successfully, at prompt and ready to continue"
                  1 means "I've finished successfully, but don't continue, hit me again."
'''
def DumpStdout(session, log):
    # We need to def. this global variables so other scopes can see them when we fill them.
    global addrIds
    global authIds
    global exiID
    global exiDump
    
    try:
        # We need to set the timeout of the session to 1 second so that way we don't block forever if something goes wrong.
        Log("DEBUG: Setting timeout to 1\n")
        session.settimeout(1)
        
        # Attempt to recieve more data.
        Log("DEBUG: Receiving data\n")
        data = session.recv(8192)
        
        # Split the string on line-feed.
        Log("DEBUG: Splitting data on \\n characters\n")
        tokens = data.split('\n')
        
        # Iterate through the tokens, parsing each line as needed.
        for idx in range(0, len(tokens)):
            # Assign the token to a variable and cut out carriage-returns.
            tok = str(tokens[idx])
            tok = tok.replace("\r", "")
            
            # Line-feed or whitespace?
            if re.match('^( |\n)*$', tok) or len(tok) < 1:
                Log("DEBUG: Hit line-feed/whitespace/empty, skip.\n")
                continue
            
            if 1 == verbose:
                Log("INFO: "+tok+"\n")
            
            # Are we @ prompt?
            if re.match('^\[grunt-.*', tok) or re.match('^\[[a-z]-u-tmervin.*', tok):
                Log("DEBUG: Got prompt, return.\n")
                return 0
            elif re.match('^\[sudo\].*', tok): # Does it need our sudo pass?
                Log("DEBUG: Asking for sudo pass.\n")
                session.send(sudoPasswd)
                Log("DEBUG: Sending sudo pass...\n")
                session.send('\n')
                Log("DEBUG: Entered SUDO password for tmervin\n")
            elif re.match('^Are you sure you want to continue connecting (yes/no)?.*', tok): # Is it asking about host authenticity?
                Log("DEBUG: Sending \"yes\"\n")
                session.send('yes\n')
            else: # Nope to all of the above, parse normally.
                if re.match('^<.*', tok) and grabIds:
                    addrIds.append(tok)
                elif grabSingle:
                    exiID = tok
                    Log("DEBUG: exiID => \""+exiID+"\"\n")
                elif grabDump:
                    exiDump += tok + "\n"
                elif grabAuth:
                    authIds.append(tok)
                    
                log.append(tok)
    except socket.timeout:
        Log("DEBUG: Socket timeout\n")
        pass
    except:
        Log("WARN: Session expire\n")
        pass
        
    return 1
    
'''
    Run Command function
    
    This function sends a command up to the active session and "runs" it by also sending a line-feed (basically hitting "Enter").
    
    @param[in] session:Channel - This is the active shell session.
    @param[in] cmd:string - This is the command to be run.
    @return void
'''
def RunCmd(session, cmd):
    try:
        Log("DEBUG: Running: \""+cmd+"\"\n")
        session.send(cmd+'\n')
    except paramiko.ssh_exception.SSHException as ssherr:
        print ssherr

'''
    Gather Spammer Info function
    
    This function does a number of things. It's primary function is to grab the needed information for a cPM note about the spamming address. This means it performs a number of tasks:
        1) Does a count to show that this address is indeed filling the queue.
        2) Grabs a single exim ID from this address.
        3) Dumps said exim ID's headers, body, and logs out so we may view them.
        4) Finally, once all is done, dumps the messages off the queue.
        
    This function also handles frozen messages. These messages are a bit trickier and so the function's initial behavior may seem a bit odd:
        1) Pulls a count of frozen messages.
        2) Greps through all the message headers looking for "auth_id".
        3) Dumps a single ID's headers, body, and logs for the highest hitting auth_id.
        4) Dumps the frozen messages off the queue.
    We grep for the auth_id as exim doesn't keep track of the frozen message's senders (since the sender is normally qmail or postfix from our own proxy).
    This helps us in catching actual spammers.
        
    @param[in] session:Channel - This is the active SSH session.
    @param[in] log:List - This is the output log that will be dumped to the user.
    @param[in] ids:List - This is the list of found "spammer" addresses.
    @return void
'''
def GatherSpammerInfo(session, log, ids):
    global grabSingle
    global grabDump
    global grabAuth
    
    # We need to go through the list.
    for idx in range(0, len(ids)):
        info = ""
        addr = str(ids[idx])
        tail = len(addr)-1
        addr = addr[1:tail]
        
        if addr == "":
            # Simply show that this address has a LOT of email in the queue.
            RunCmd(session, 'sudo exiqgrep -izf')
            Log("DEBUG: Dumping stdin for PTY\n")
            while 1 == DumpStdout(session, log):
                pass
            
            # Start the info line.
            outLen = len(log)-1
            info = log[outLen]
            
            # Now we need to grep through them for an auth_id.
            grabAuth = True
            RunCmd(session, "sudo sh -c 'for id in $(exiqgrep -iz); do exim -Mvh \"$id\" | grep -i \"^\-auth_id.*\" | cut -d \" \" -f2; done' | sort | uniq -c | sort -n | awk '{if($1 > 750){ print $2 }}'")
            
            Log("DEBUG: Dumping stdin for PTY\n")
            while 1 == DumpStdout(session, log):
                pass
            grabAuth = False
                
            # Go through the auth_ids and dump each message.
            for authIdx in range(0, len(authIds)):
                # Now, grab an ID for the offending address.
                grabSingle = True
                RunCmd(session, "sudo sh -c 'for id in $(exiqgrep -iz); do exim -Mvh \"$id\" | grep -i \"^\-auth_id.*\" | grep -i \""+authIds[authIdx]+"\" >/dev/null; if [[ $? == 0 ]]; then echo \"$id\"; break; fi done'")
            
                Log("DEBUG: Dumping stdin for PTY\n")
                while 1 == DumpStdout(session, log):
                    pass
                grabSingle = False
                
                # Dump the offending email.
                grabDump = True
                RunCmd(session, 'sudo exim -Mvh "'+exiID+'" && sudo exim -Mvb "'+exiID+'" && sudo exim -Mvl "'+exiID+'"')
                Log("DEBUG: Dumping stdin for PTY\n")
                while 1 == DumpStdout(session, log):
                    pass
                grabDump = False
                
                # Append to the spammers info list.
                info += "\nDumping ID => "+exiID+"\n"
                info += "> Dump of "+exiID+" <\n"+exiDump+"\n"
                spammerInfo.append(info)
            
            # Dump all the frozen messages as we're done with 'em.
            RunCmd(session, "sudo sh -c 'exiqgrep -iz | xargs -i exim -Mrm \"{}\"'")
            Log("DEBUG: Dumping stdin for PTY\n")
            while 1 == DumpStdout(session, log):
                pass
        else:
            # Simply show that this address has a LOT of email in the queue.
            RunCmd(session, 'sudo exiqgrep -icf '+addr)
            Log("DEBUG: Dumping stdin for PTY\n")
            while 1 == DumpStdout(session, log):
                pass
            
            # Start the info line.
            outLen = len(log)-1
            info = log[outLen]
            
            # For these, grab a message ID from the offending ID.
            grabSingle = True
            RunCmd(session, 'sudo exiqgrep -if '+addr+' | head -n 500 | tail -n 1');
            Log("DEBUG: Dumping stdin for PTY\n")
            while 1 == DumpStdout(session, log):
                pass
            grabSingle = False
            
            outLen = len(log)-1
            exiID = log[outLen]
            Log("DEBUG: exiID => \""+exiID+"\"\n")

            grabDump = True
            RunCmd(session, 'sudo exim -Mvh "'+exiID+'" && sudo exim -Mvb "'+exiID+'" && sudo exim -Mvl "'+exiID+'"')
            Log("DEBUG: Dumping stdin for PTY\n")
            while 1 == DumpStdout(session, log):
                pass
            grabDump = False
            
            info += "\nDumping ID => "+exiID+"\n"
            info += "> Dump of "+exiID+" <\n"+exiDump+"\n"
            spammerInfo.append(info)
            
            # Pop the messages off the queue.
            RunCmd(session, "sudo sh -c 'exiqgrep -if "+addr+" | xargs -i exim -Mrm \"{}\"'")
            Log("DEBUG: Dumping stdin for PTY\n")
            while 1 == DumpStdout(session, log):
                pass
            
        # Write the spammer info.
        hFile = open("spammers/"+boxName, "a+")
            
        if not hFile:
            sys.stderr.write("ERROR: Unable to open spammers/"+boxName+"\n")
        else:
            for idx in range(0, len(spammerInfo)):
                hFile.write("\n\n")
                hFile.write(note)
                hFile.write(info)
                hFile.write(exibotFoot)    
            hFile.close()
'''
    Get Boxes function
    
    This function opens "boxes.bad" and reads each box out of it and appends them to boxList so they can be logged into and have work performed on them.
    IF boxes.bad doesn't exist or is empty, we need to query the user for a box list separated by spaces.
    
    @param[in] void
    @return void
'''
def GetBoxes():
    global boxList
    askUser = False # Do we need to query the user for a box list?
    hBoxes = None
    lnRead = ""
    
    try:
        hBoxes = open("boxes.bad", "r")
    except:
        askUser = True
    
    if not hBoxes:
        # We need to query the user for a box list!
        askUser = True
    else:
        # Attempt to read in a box list.
        lnRead = hBoxes.readline()
        
        if lnRead == "":
            askUser = True
        else:
            hBoxes.close()
    
    if askUser:
        while lnRead == "":
            lnRead = str(raw_input("Unable to grab box list from boxes.bad! Please enter a list of boxes separated by spaces:\n"))
    
    # Separate the boxes and dump 'em into boxList.
    boxList = lnRead.split(" ")
    
    # Done.
        

# Parse cmd-line args.
for idx in range(0, len(sys.argv)):
    if sys.argv[idx] == "-v":
        verbose = 1
    if sys.argv[idx] == "-debug":
        debug = 1

# Grab the box list.
GetBoxes()

# Setup the login system for SSH as we need to bounce off of the jumpbox into the userbox.
# Spawn a new SSH Client for us to connect up through.
Log("DEBUG: Setting up SSH Client\n")
client = paramiko.client.SSHClient()

# This grabs all the system host keys that are currently loaded in the SSH daemon.
Log("DEBUG: Loading host keys\n")
client.load_system_host_keys()

# Connect up to the jumpbox over port 22 using SSHv2.
Log("DEBUG: Connecting to grunt:22\n")
client.connect('grunt', 22, getpass.getuser())
try:
    # Spawn an SSHv2 session on the jumpbox so we may interact with the host.
    Log("DEBUG: Spawning session\n")
    session = client.get_transport().open_session()
except paramiko.ssh_exception.SSHException as ssherr:
    print ssherr
    
# We need to forward our authentication agent so we can "proxy" from grunt into a userbox.
try:
    Log("DEBUG: Forwarding agent\n")
    paramiko.agent.AgentRequestHandler(session)
except paramiko.ssh_exception.SSHException as ssherr:
    print ssherr

# We now need to spawn a PTY and invoke a shell so we have full interactivity on the jumpbox
try:
    # Default to a "vt100" terminal type that is 80 chars wide and 60 chars tall with a resolution of 640x480 pixels.
    Log("DEBUG: Spawning PTY\n")
    session.get_pty('vt100', 80, 60, 640, 480)
    Log("DEBUG: Invoking shell\n")
    session.invoke_shell()
except paramiko.ssh_exception.SSHException as ssherr:
    print ssherr

# Dump STDOUT from the Psuedo-Terminal.
Log("DEBUG: Dumping stdout for PTY\n")
while 1 == DumpStdout(session, output):
    pass

# Now we can start logging into boxes and cleaning the exim queues.
for bxIdx in range(0, len(boxList)):
    boxName = boxList[bxIdx];
    
    if not re.match('^(box|host|fast|just)[0-9]{1,4}$', boxName):
        # Skip this instance and warn about it!
        Log("WARN: Got a box that doesn't make sense! Box was: \""+boxName+"\"")
        continue
    else:
        # First grab the sudo passwd from the user for the box-type.
        Log("DEBUG: Grabbing Password\n")

        # This set's the window title to something that KeePassX can use.
        wndTitle = "-u-"+getpass.getuser()+" ["+boxName+"] ExiBot"
        
        if re.match('^(box|rsb)[0-9]{1,4}$', boxName):
            # Bluehost box.
            wndTitle = "b"+wndTitle
        elif re.match('^fast[0-9]{1,4}$', boxName):
            # FastDomain box.
            wndTitle = "f"+wndTitle
        elif re.match('^host[0-9]{1,4}$', boxName):
            # HostMonster box.
            wndTitle = "h"+wndTitle
        elif re.match('^(just|rsj)[0-9]{1,4}$', boxName):
            # Justhost box.
            wndTitle = "j"+wndTitle
        else:
            # Unknown box, don't know how it made it through sanitization, but whatever.
            wndTitle = "shared.ul-"+getpass.getuser()+" ["+boxName+"] ExiBot"
        
        sys.stdout.write("\033]2;"+wndTitle+"\007")
        sudoPasswd = getpass.getpass()
        Log("DEBUG: Got password\n")

        # Run the needed SSH command to login to the needed userbox.
        RunCmd(session, 'ssh tmervin@'+boxName)

        # Dump STDOUT from the Psuedo-Terminal.
        Log("DEBUG: Dumping stdout for PTY\n")
        while 1 == DumpStdout(session, output):
            pass

        # Run an "exim -bpc" to make sure that the queue is all green.
        RunCmd(session, "sudo exim -bpc")

        # Dump STDOUT from the Psuedo-Terminal.
        Log("DEBUG: Dumping stdout for PTY\n")
        while 1 == DumpStdout(session, output):
            pass

        # Analyze the output of exim -bpc and see if it's > 1000
        outLen = len(output)-1
        if int(output[outLen]) > 1000:
            Log("INFO: Found a queue over 1000! Queue: "+str(output[outLen])+"\n")
            Log("INFO: Searching for spammers...\n");
            grabIds = True
            
            # Grab the email address's filling the queue.
            RunCmd(session, "sudo exiqgrep -b | cut -d \" \" -f3 | sort | uniq -c | sort -n | awk '{if($1 >= 1000){ print $2 }}'")
            
            # Dump STDOUT from the Psuedo-Terminal.
            Log("DEBUG: Dumping stdout for PTY\n")
            while 1 == DumpStdout(session, output):
                pass
            
            # Dump the spammer addresses.
            for idx in range(0, len(addrIds)):
                Log("INFO: Looks like "+str(addrIds[idx])+" has more than 1000 messages in the queue! D:\n")
            
            grabIds = False
            
            # Gather info on our spammers.
            GatherSpammerInfo(session, output, addrIds)
            
            # DONE
            
        # Logout from the userbox.
        RunCmd(session, 'logout')

        # Dump STDOUT from the Psuedo-Terminal.
        Log("DEBUG: Dumping stdout for PTY\n")
        while 1 == DumpStdout(session, output):
            pass

        # Dump out the log.
        for idx in range(0, len(output)):
            Log(str(output[idx])+"\n")

        # Write the runtime log.
        WriteLog()

# Logout from the grunt.
RunCmd(session, 'logout')
Log("DEBUG: Closing client.\n")
client.close()
