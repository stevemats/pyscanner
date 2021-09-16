#!/usr/bin/env python3

import socket, time, sys, optparse, os, threading
# import thread
import ast
from concurrent import futures
try:
    from colorama import Fore,Back,Style,init
except ImportError:
    print ("colorama isn\'t installed, installing now...")
    os.system('python -m pip install --user colorama')
    print ('colorama has been installed, restarting PyScanner..')


init()

total_ports = []
closed_ports = []
open_ports = {}
common_list = False
udp_scan = False
error = []


def banner():
    print ("\n\n"+ Fore.WHITE + Style.DIM +"")
    print(""" \t\t 
            .------..------..------..------..------..------..------..------..------.
            |P.--. ||Y.--. ||S.--. ||C.--. ||A.--. ||N.--. ||N.--. ||E.--. ||R.--. |
            | :/\: || (\/) || :/\: || :/\: || (\/) || :(): || :(): || (\/) || :(): |
            | (__) || :\/: || :\/: || :\/: || :\/: || ()() || ()() || :\/: || ()() |
            | '--'P|| '--'Y|| '--'S|| '--'C|| '--'A|| '--'N|| '--'N|| '--'E|| '--'R|
            `------'`------'`------'`------'`------'`------'`------'`------'`------'
    """)
    print ("\t\t" + Fore.RED + Style.BRIGHT +"               PyScanner By: St3v3 Matindi\n\n"+ Fore.WHITE + Style.DIM +"")
    print ("[#] Developed By Steve Matindi")
    print ("\n[!] legal disclaimer: Usage of PyScanner for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developer assume no liability and are not responsible for any misuse or damage caused by this program\n\n")


def main():
    options = {}
    parser = optparse.OptionParser("\n\n%prog -t <target host> -s <start port> -e <end port>\n%prog -t <target_host> -c <common-ports>\n%prog -t <target_host> -c <common-ports> --threads <threads>\n%prog -t <target_host> -s <start_port> -e <end_port>")
    parser.add_option('-t', dest='target_host', type='string', help='specify target host')
    parser.add_option('-s', dest='start_port', type='int', help='specify start port\n')
    parser.add_option('-e', dest='end_port', type='int', help='specify end port\n')
    parser.add_option('--threads', dest='threads', type='int', default=100, help='specify no. of threads [default=100]\n')
    parser.add_option("-c", '--common-ports', action="store_true", dest="common_port", default=False, help='scan with common ports')


    (options, args) = parser.parse_args()
    target_host = options.target_host
    start_port = options.start_port
    end_port = options.end_port
    common_port = options.common_port
    threads_no = options.threads

    program_name = sys.argv[0]

    if(target_host == None):
        banner()
        try:
            print (""+ Fore.GREEN + Style.DIM +"Usage : %s [options]" % program_name.split("\\")[2])
            print ("Check : %s --help for help" % program_name.split("\\")[2]  + Fore.WHITE + Style.DIM +"")
        except:
            print (""+ Fore.GREEN + Style.DIM + "Usage : %s [options]" % program_name)
            print ("Check : %s --help for help" % program_name + Fore.WHITE + Style.DIM +"")
        exit(0)
    if threads_no > 800:
        banner()
        print (""+ Fore.RED + Style.BRIGHT +"Error: Threads must be less than 800, default no. of threads= 100"+ Fore.WHITE + Style.DIM +"")
        exit()
    if (common_port == False):

        threads = []
        start = time.time()
        readable_start = time.ctime()
        banner()
        print ("Scanning started at %s \n\n" %readable_start)
        try:
            with futures.ThreadPoolExecutor(threads_no) as executor:
                fs = [executor.submit(check_port, target_host, n) for n in range(start_port, end_port+1)]
                futures.wait(fs)
        except KeyboardInterrupt:
            print ("" + Fore.RED + Style.BRIGHT +"\nCTRL^C Pressed, quitting the program.."+ Fore.WHITE + Style.DIM +"")
            exit()
        except Exception as e:
            print ("" + Fore.RED + Style.BRIGHT +"Unknown error occured" + e + Fore.WHITE + Style.DIM +"")
            exit()
        end = time.time()
        readable_end = time.ctime()
        total = end-start
        count = int(len(open_ports))
        sorted_open_port_list = sorted(open_ports)
        if len(total_ports) != len(closed_ports):
            print ("" + Fore.RED + Style.BRIGHT +"Not Showing %d closed ports\n\n\n" % int(len(closed_ports)) + Fore.WHITE + Style.DIM +"")
            print ("" + Fore.GREEN + Style.BRIGHT +"PORT \t\t STATE \t\t SERVICE\n"+ Fore.WHITE + Style.DIM +"")
            print ("" + Fore.RED + Style.BRIGHT +"-----------------------------------------\n"+ Fore.WHITE + Style.DIM +"")
        else:
            print ("" + Fore.RED + Style.BRIGHT +"\nNot Showing %d closed ports" % int(len(closed_ports)) + Fore.WHITE + Style.DIM +"")
        for n in sorted_open_port_list:
            if n < 1000:
                if open_ports[n] == 'open':
                    print ("%d/tcp\t\t open\t\t %s\n" % (n, service(n)))
                elif open_ports[n] == 'filtered':
                    print (("%d/tcp\t\t filtered\t\t %s\n" % (n, service(n))))
            else:
                if open_ports[n] == 'open':
                    print ("%d/tcp\t open\t\t %s\n" % (n, service(n)))
                elif open_ports[n] == 'filtered':
                    print ("%d/tcp\t\t filtered\t\t %s\n" % (n, service(n)))
        print ("\n\nTotal no. of scanned ports: "+ Fore.RED + Style.BRIGHT +"%d" % int(len(total_ports)) + Fore.WHITE + Style.DIM +"")
        print ("Total no. of closed ports: "+ Fore.RED + Style.BRIGHT +"%d" % int(len(closed_ports)) + Fore.WHITE + Style.DIM +"")
        print ("\nScanning completed at %s.\nTotal time taken is %s seconds" % (readable_end, total))
    elif (common_port == True):

        #reading from ports.txt list
        common_port_list = list(open('ports.txt'))

        threads = []
        start = time.time()
        readable_start = time.ctime()
        banner(())
        print ("You choosed to scan for common port list. Scanning started at %s \n\n" %readable_start)
        try:
            with futures.ThreadPoolExecutor(threads) as executor:
                fs = [executor.submit(check_port, target_host, n) for n in common_port_list]
                futures.wait(fs)
        except KeyboardInterrupt:
            print ("\nCTRL^C Pressed, quitting the program")
            exit()
        except Exception as e:
            print ("Unknown error occured", e)
            exit()
        end = time.time()
        readable_end = time.ctime()
        total = end-start
        count = int(len(open_ports))
        sorted_open_port_list = sorted(open_ports)
        if len(total_ports) != len(closed_ports):
            print ("" + Fore.RED + Style.BRIGHT +"Not Showing %d closed ports\n\n\n" % int(len(closed_ports)) + Fore.WHITE + Style.DIM +"")
            print ("" + Fore.GREEN + Style.BRIGHT +"PORT \t\t STATE \t\t SERVICE\n"+ Fore.WHITE + Style.DIM +"")
            print ("" + Fore.RED + Style.BRIGHT +"-----------------------------------------\n"+ Fore.WHITE + Style.DIM +"")
        else:
            print ("" + Fore.RED + Style.BRIGHT +"\nNot Showing %d closed ports" % int(len(closed_ports)) + Fore.WHITE + Style.DIM +"")
        for n in sorted_open_port_list:
            for n in sorted_open_port_list:
                if n < 1000:
                    if open_ports[n] == 'open':
                        print ("%d/tcp\t\t open\t\t %s\n" % (n, service(n)))
                    elif open_ports[n] == 'filtered':
                        print ("%d/tcp\t\t filtered\t\t %s\n" % (n, service(n)))
                else:
                    if open_ports[n] == 'open':
                        print ("%d/tcp\t open\t\t %s\n" % (n, service(n)))
                    elif open_ports[n] == 'filtered':
                        print ("%d/tcp\t filtered\t\t %s\n" % (n, service(n)))
        print ("\n\nTotal no. of scanned ports: "+ Fore.RED + Style.BRIGHT +"%d" % int(len(total_ports)) + Fore.WHITE + Style.DIM +"")
        print ("Total no. of closed ports: "+ Fore.RED + Style.BRIGHT +"%d" % int(len(closed_ports)) + Fore.WHITE + Style.DIM +"")
        print ("\nScanning completed at %s.\nTotal time taken is %s seconds" % (readable_end, total))


# Not using getservbyport method ,due to not having good port dictionary.
def service(port):
    srvice_ports = open("service_list.txt", "r") 
    contents = srvice_ports.read()
    service_list = ast.literal_eval(contents) #reconstruct data as dict.
    srvice_ports.close()

    try:
        return service_list[port]
    except:
        return "unknown"

def check_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        result = sock.connect_ex((ip, port))
    except KeyboardInterrupt:
        print ("" + Fore.RED + Style.BRIGHT +"\nError: You pressed Ctrl+C, Stopping Program.\n"+ Fore.WHITE + Style.DIM +"")
        error.append("\nYou pressed Ctrl+C, Stopping Program.\n")
        exit()
    except socket.gaierror as e:
        print ('' + Fore.RED + Style.BRIGHT +'Error: Hostname could not be resolved.\nCheck if host is really up. Exiting..\n'+ e + Fore.WHITE + Style.DIM +"")
        error.append('Hostname could not be resolved.\nCheck if host is really up. Exiting..\n')
        exit()
    except socket.error as e:
        print ("" + Fore.RED + Style.BRIGHT +"Error: Couldn't connect to server\n"+ Fore.WHITE + Style.DIM +"")
        error.append("Couldn't connect to server\n")
        exit()
    except Exception as e:
        print ("" + Fore.RED + Style.BRIGHT +"Error: Unknown error occured"+ Fore.WHITE + Style.DIM +"" + e + Fore.WHITE + Style.DIM +"")
        error.append("Unknown error occured")
        exit()
    if result == 0:
        open_ports[port] = 'open'
        total_ports.append(port)
    elif result == 10061:
        closed_ports.append(port)
        total_ports.append(port)
    elif result == 10035:
        open_ports[port] = 'filtered'
        total_ports.append(port)
    sock.close()


if __name__ == '__main__':
    if sys.platform == 'linux-i386' or sys.platform == 'linux2' or sys.platform == 'darwin':
        SysCls = 'clear'
        os.system(SysCls)
    elif sys.platform == 'win32' or sys.platform == 'dos' or sys.platform[0:5] == 'ms-dos':
        SysCls = 'cls'
        os.system(SysCls)
    else:
        pass

    main()