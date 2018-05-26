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
            print "You must enter an ip address (Example: ssl 127.0.0.1)"
        else:
            # os.system('nmap --script  -p 443 ' + args)
            print ("""
            
            ******************
            Obtaining SSL Cert
            ******************
            
            """)
            os.system('nmap --script ssl-cert -p 443 ' + args)
            print ("""

            ***********************************
            Checking for internal ip disclosure
            ***********************************

                        """)
            os.system('nmap --script ssl-cert-intaddr -p 443 ' + args)
            print ("""

            ******************************
            Checking if SSLv2 is supported
            ******************************

                        """)
            os.system('nmap --script sslv2 -p 443 ' + args)
            print ("""

            ***********************
            Enumerating SSL ciphers 
            ***********************
            
                        """)
            os.system('nmap --script ssl-enum-ciphers -p 443 ' + args)
            print ("""

            *****************************
            Checking for problematic keys
            *****************************
            
                        """)
            os.system('nmap --script ssl-known-key -p 443 ' + args)
            print ("""

            ********************************
            Checking for weak Diffie-Hellman
            ********************************

                        """)
            os.system('nmap --script ssl-dh-params -p 443 ' + args)
            print ("""

            *******************************
            Checking for CCS Injection Vuln
            *******************************
            
                        """)
            os.system('nmap --script ssl-ccs-injection -p 443 ' + args)
            print ("""

            ************************
            Checking for POODLE vuln
            ************************
            
                        """)
            os.system('nmap --script ssl-poodle -p 443 ' + args)
            print ("""

            ****************************
            Checking for Heartbleed vuln
            ****************************

                        """)
            os.system('nmap --script ssl-heartbleed -p 443 ' + args)
            print ("""

            *****************************
            Checking for Drown SSLv2 vuln
            *****************************

                        """)
            os.system('nmap --script sslv2-drown -p 443 ' + args)
            print ("""

            ************************************
            Checking for F5 Ticketbleed bug vuln
            ************************************

                        """)
            os.system('nmap --script tls-ticketbleed -p 443 ' + args)

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
    if os.geteuid() != 0:
        print('You must run this script as root!!!')
        exit()
    if platform == "linux" or platform == "linux2":
        os.system('clear')
    elif platform == "darwin":
        os.system('clear')
    elif platform == "win32":
        os.system('cls')
    prompt = MyPrompt()
    prompt.prompt = 'achilles>> '
    prompt.cmdloop('Starting prompt...')