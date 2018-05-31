import subprocess
import os
import re
from cmd import Cmd
from sys import platform

SHODANAPIKEY = ''

class MyPrompt(Cmd):

    def do_whois(self, args):
        """Whois lookup based on domain name or ip"""
        if len(args) == 0:
            print "You must enter a domain name or ip address"
        else:
            print ("""

            ******************************************************
            Obtaining Who is information for %s
            ******************************************************

            """) % args
            is_ip = re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", args)
            if is_ip:
                os.system('nmap --script whois-ip ' + args)
            else:
                os.system('nmap --script whois-domain ' + args)


    def do_ssl(self, args):
        """Runs a number of nmap scripts for SSL info"""
        if len(args) == 0:
            print "You must enter an ip address and port to scan (Example: ssl 127.0.0.1 443)"
        else:
            # os.system('nmap --script  -p 443 ' + args)
            print ("""
            
            ******************
            Obtaining SSL Cert
            ******************
            
            """)
            ssl = 'nmap --script ssl-cert '
            host = args[0]
            port = ' -p ' + args[1]
            all = ssl + port + host
            os.system(all)
            print ("""

            ***********************************
            Checking for internal ip disclosure
            ***********************************

                        """)
            ssl = 'nmap --script ssl-cert-intaddr '
            host = args[0]
            port = ' -p ' + args[1]
            all = ssl + port + host
            os.system(all)
            print ("""

            ******************************
            Checking if SSLv2 is supported
            ******************************

                        """)
            ssl = 'nmap --script=sslv2 '
            host = args[0]
            port = ' -p ' + args[1]
            all = ssl + port + host
            os.system(all)
            os.system('nmap --script  -p 443 ' + args)
            print ("""

            ***********************
            Enumerating SSL ciphers 
            ***********************
            
                        """)
            ssl = 'nmap --script=ssl-enum-ciphers '
            host = args[0]
            port = ' -p ' + args[1]
            all = ssl + port + host
            os.system(all)
            print ("""

            *****************************
            Checking for problematic keys
            *****************************
            
                        """)
            ssl = 'nmap --script=ssl-known-key '
            host = args[0]
            port = ' -p ' + args[1]
            all = ssl + port + host
            os.system(all)
            print ("""

            ********************************
            Checking for weak Diffie-Hellman
            ********************************

                        """)
            ssl = 'nmap --script=ssl-dh-params '
            host = args[0]
            port = ' -p ' + args[1]
            all = ssl + port + host
            os.system(all)
            print ("""

            *******************************
            Checking for CCS Injection Vuln
            *******************************
            
                        """)
            ssl = 'nmap --script=ssl-ccs-injection '
            host = args[0]
            port = ' -p ' + args[1]
            all = ssl + port + host
            os.system(all)
            print ("""

            ************************
            Checking for POODLE vuln
            ************************
            
                        """)
            ssl = 'nmap --script=ssl-poodle '
            host = args[0]
            port = ' -p ' + args[1]
            all = ssl + port + host
            os.system(all)
            print ("""

            ****************************
            Checking for Heartbleed vuln
            ****************************

                        """)
            ssl = 'nmap --script=ssl-heartbleed'
            host = args[0]
            port = ' -p ' + args[1]
            all = ssl + port + host
            os.system(all)
            os.system('nmap --script  -p 443 ' + args)
            print ("""

            *****************************
            Checking for Drown SSLv2 vuln
            *****************************

                        """)
            ssl = 'nmap --script=sslv2-drown '
            host = args[0]
            port = ' -p ' + args[1]
            all = ssl + port + host
            os.system(all)
            print ("""

            ************************************
            Checking for F5 Ticketbleed bug vuln
            ************************************

                        """)
            ssl = 'nmap --script=tls-ticketbleed '
            host = args[0]
            port = ' -p ' + args[1]
            all = ssl + port + host
            os.system(all)

    def do_shodan(self, args):
        """Run ip address against shodan database"""
        if len(args) == 0:
            print "You must enter an ip address (Example: firewalk 127.0.0.1)"
        else:
            print ("""
    
            *************************
            Running ip against shodan
            *************************
    
                        """)
            os.system("nmap --script shodan-api --script-args 'shodan-api.target=" + args + ",shodan-api.apikey=" + SHODANAPIKEY + "'")

    def do_firewalk(self, args):
        """Use nmap firewalk script against target ip"""
        if len(args) == 0:
            print "You must enter an ip address (Example: firewalk 127.0.0.1)"
        else:
            print ("""
    
                        *************************
                        Executing firewalk script
                        *************************
    
                                    """)
            os.system('nmap --script firewalk --traceroute ' + args)

    def do_quit(self, args):
        """Quits the program."""
        print "Quitting."
        raise SystemExit

if __name__ == '__main__':
    if platform == "linux" or platform == "linux2":
        if os.geteuid() != 0:
            print('You must run this script as root!!!')
            exit()
        else:
            os.system('clear')
    elif platform == "darwin":
        if os.geteuid() != 0:
            print('You must run this script as root!!!')
            exit()
        else:
            os.system('clear')
    elif platform == "win32":
        os.system('cls')
    prompt = MyPrompt()
    prompt.prompt = 'achilles>> '
    prompt.cmdloop('Starting achilles...\n\nUsage: <command> <argument>\n\nExample: ssl 127.0.0.1\n\nType help to start\n')
