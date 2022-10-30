#!/usr/bin/python3

#      author: mind2hex
# description: simple web fuzzer

import argparse 
import requests
import validators
import threading
import socket
import re
from time import sleep

def banner():
    ascii_text = """
               _     ______                      
              | |   |  ____|                     
 __      _____| |__ | |__ _   _ ___________ _ __ 
 \ \ /\ / / _ \ '_ \|  __| | | |_  /_  / _ \ '__|
  \ V  V /  __/ |_) | |  | |_| |/ / / /  __/ |   
   \_/\_/ \___|_.__/|_|   \__,_/___/___\___|_|   
                                                 
    """

    print(ascii_text)



    

def parse_arguments():
    # general args
    magic_word = "#FUZZ#"
    parser = argparse.ArgumentParser(prog="./webFuzzer.py",
                                     description="a simple python multithreading web fuzzer",
                                     epilog="https://github.com/mind2hex/")
    parser.add_argument("url", help=f"specify target url. example[http://localhost/{magic_word}]")
    parser.add_argument("-X", "--http-method", metavar="METHOD", choices=["GET", "POST"], default="GET",
                        help="specify an HTTP for the request method")
    parser.add_argument("-p", "--port", default=80, metavar="<n>", type=int,
                        help="specify target port")
    parser.add_argument("-w", "--wordlist", metavar="/path", required=True, type=argparse.FileType('r', encoding='latin-1'),
                        help="specify wordlist")
    parser.add_argument("-b", "--body-data", nargs="?", metavar="data=value",
                        help=f"specify body data to send using post method. example[arg1={magic_word}]")

    # timming args
    timming = parser.add_argument_group("timming")
    timming.add_argument("-t", "--threads", metavar="<n>", type=int,
                        help="specify threads [default 1]", default=1)
    timming.add_argument("-T", "--timeout", metavar="<n>",
                        help="timeout per request in seconds [default 10]", default=10)

    # debugging args
    debug = parser.add_argument_group("debugging")
    debug.add_argument("-v", "--verbose", action="store_true",
                       help="show verbose message")
    debug.add_argument("-d", "--debug", action="store_true",
                       help="show debugging message")
    debug.add_argument("-o", "--output", type=argparse.FileType('w'),
                       help="save output to a file")

    # filter args
    filters = parser.add_argument_group("filters")
    show_filters = filters.add_mutually_exclusive_group()
    show_filters.add_argument("--ss-filter", metavar="nnn,nnn...", 
                              help="only show responses with the specified comma separated status codes. ")
    show_filters.add_argument("--sc-filter", metavar="nnn,nnn...",
                              help="only show responses with the specified comma separated content lenghts. example[nnn,nnnn,n...]")
    show_filters.add_argument("--sw-filter", metavar="ws1,ws2...",
                              help="only show responses with the specified comma separated web servers. example[apache,nginx...]")
    show_filters.add_argument("--sr-filter", metavar="pattern-regex",
                              help="only show responses with the specified response body matching pattern...")

    hide_filters = filters.add_mutually_exclusive_group()
    hide_filters.add_argument("--hs-filter", metavar="nnn,nnn...",
                              help="hide responses with the specified comma separated status codes.")
    hide_filters.add_argument("--hc-filter", metavar="nnn,nnn...",
                              help="hide responses with the specified comma separated content lenghts. example[nnn,nnnn,n...]")
    hide_filters.add_argument("--hw-filter", metavar="ws1,ws2...",
                              help="hide responses with the specified comma separated web servers. example[apache,nginx...]")
    hide_filters.add_argument("--hr-filter", metavar="pattern-regex", 
                              help="hide responses with the specified pattern...")    

    parsed_arguments = parser.parse_args()
    parsed_arguments.magic_word = magic_word

    return parsed_arguments

def validating_arguments(args, wordlist):
    MAX_THREADS = 60
    
    # validating url format
    if (validators.url(args.url) != True):
        raise Exception(f"invalid url: {args.url}")

    # validating magic_word inside GET request    
    if ((args.http_method == "GET") and (args.magic_word not in args.url)):
        raise Exception(f"magic word {args.magic_word} not in the url: {args.url}")

    # validating magic_word inside POST request    
    if (args.http_method == "POST"): 
        state = False
        for data in parsed_arguments.body_data:
            if magic_word in data:
                state = True
                break

        if state == False:
            raise Exception(f"magic word not in body data...")

    # validating port number
    if (args.port not in range(1, 65535)):
        raise Exception(f"Invalid port number: {parsed_arguments.port}")

    # validating maximum threads
    if (args.threads > MAX_THREADS):
        raise Exception(f"the threads exceed the thread limit. If you want your cpu to explode, modify the MAX_THREADS variable")

    # validating threads and wordlist len
    if (args.threads > len(wordlist)):
        raise Exception(f"too many threads for so few words... are u nuts?")

    
    # validating ss_filter (show status code filter)
    if (args.ss_filter != None):
        args.ss_filter = args.ss_filter.split(',')
        for status_code in args.ss_filter:
            if status_code.isdigit == False:
                raise Exception(f" incorrect ss_filter value {status_code}")

    # validating sc_filter (show content length filter)
    if (args.sc_filter != None):
        args.sc_filter = args.sc_filter.split(',')
        for content_length in args.sc_filter:
            if content_length.isdigit == False:
                raise Exception(f" incorrect sc_filter value {content_length}")

    # validating sw_filter (show content length filter)
    if (args.sw_filter != None):
        args.sw_filter = args.sw_filter.split(',')
        
    # validating hs-filter (hide status code filter)
    if (args.hs_filter != None):
        args.hs_filter = args.hs_filter.split(',')
        for status_code in args.hs_filter:
            if status_code.isdigit == False:
                raise Exception(f" incorrect hs_filter value {status_code}")

    # validating sc-filter (hide content length filter)
    if (args.hc_filter != None):
        args.hc_filter = args.hc_filter.split(',')
        for content_length in args.hc_filter:
            if content_length.isdigit == False:
                raise Exception(f" incorrect hc_filter value {content_length}")


        

def fuzzing_GET(args, wordlist:list):
    global run_event
    # iterating wordlist
    for word in wordlist:
        # checking if threads should still running
        if run_event.is_set() == False:
            break
        
        new_url = args.url.replace(args.magic_word, word)
        try:
            req = requests.request("GET", new_url, timeout=int(args.timeout))
        except requests.ConnectTimeout:
            print("[!] Connection Time Out: %-100s"%(new_url))
            continue
        except socket.error:
            print("[!] Error stablishing connection, finishing program...")
            run_event.clear()
            exit(0)
            
            
        req.headers.setdefault("Content-Length", "UNK")
        req.headers.setdefault("Server",         "UNK")

        status_code = req.status_code
        content_len = req.headers["Content-Length"]
        server      = req.headers["Server"]


        # Only SHOW filters
        if (args.ss_filter != None):
            if str(status_code) in args.ss_filter:
                print("%-70s\t%-3s\t%-10s\t%-10s"%(new_url, status_code, content_len, server))
                continue

        elif (args.sc_filter != None):
            if content_len != "UNK":
                if str(content_len) in args.sc_filter:
                    print("%-70s\t%-3s\t%-10s\t%-10s"%(new_url, status_code, content_len, server))
                    continue

        elif (args.sw_filter != None):
            if server in args.sw_filter:
                print("%-70s\t%-3s\t%-10s\t%-10s"%(new_url, status_code, content_len, server))
                continue                

        elif (args.sr_filter != None):
            aux = re.search(args.sr_filter, req.content.decode("latin-1"))
            if aux != None:
                print("%-70s\t%-3s\t%-10s\t%-10s"%(new_url, status_code, content_len, server))
                continue

        # Hide filters
        elif (args.hs_filter != None):
            if str(status_code) not in args.hs_filter:
                print("%-70s\t%-3s\t%-10s\t%-10s"%(new_url, status_code, content_len, server))
                continue

        elif (args.hc_filter != None):
            if content_len != "UNK":
                if str(content_len) not in args.hc_filter:
                    print("%-70s\t%-3s\t%-10s\t%-10s"%(new_url, status_code, content_len, server))
                    continue

        elif (args.hw_filter != None):
            if server not in args.hw_filter:
                print("%-70s\t%-3s\t%-10s\t%-10s"%(new_url, status_code, content_len, server))
                continue                

        elif (args.hr_filter != None):
            aux = re.search(args.hr_filter, req.content.decode("latin-1"))
            if aux == None:
                print("%-70s\t%-3s\t%-10s\t%-10s"%(new_url, status_code, content_len, server))
                continue            

        print("%-70s\t%-3s\t%-10s\t%-10s"%(new_url, status_code, content_len, server), end="\r")
    
    return 0


def show_config(args):
    print("==========================================")
    print("[!] General...")
    print(f"             URL: {args.url}")
    print(f"     HTTP METHOD: {args.http_method}")
    if (args.http_method == "POST"):
        for data in args.body_data:
            print(f"\tBODY DATA: {args.http_method}")
            
    print(f"            PORT: {args.port}")
    print(f"        WORDLIST: {args.wordlist.name}")
    print()
    print("[!] Timming...")
    print(f"         THREADS: {args.threads}")
    print(f"         TIMEOUT: {args.timeout}")
    print()
    print("[!] Debugging...")
    print(f"         VERBOSE: {args.verbose}")
    print(f"           DEBUG: {args.debug}")
    print(f"          OUTPUT: {args.output}")
    print()
    print("[!] Filters...")
    print(f"         SHOW SC: {args.ss_filter}") # status code
    print(f"         SHOW CL: {args.sc_filter}") # content length
    print(f"         SHOW WS: {args.sw_filter}") # web server
    print(f"         SHOW RE: {args.sr_filter}") # regex    
    print(f"         HIDE SC: {args.hs_filter}") # status code
    print(f"         HIDE CL: {args.hc_filter}") # content length
    print(f"         HIDE WS: {args.hw_filter}") # web server
    print(f"         HIDE RE: {args.hr_filter}") # regex    
    print("==========================================\n")    

    
def split_wordlist(wordlist, threads):
    """ This function just split the wordlist in equal size chunks for every thread """
    result = []
    wordlist_len = len(wordlist)
    wordlist_chunks = wordlist_len // threads
    aux_0, aux_1 = 0, wordlist_chunks
    while aux_1 <= wordlist_len:
        result.append(wordlist[aux_0:aux_1])
        aux_0 = aux_1
        aux_1 += wordlist_chunks

    return result


def verbose(state, msg):
    if state == True:
        print("[!] verbose:", msg)

        
def main():
    banner()
    
    # parsing arguments...
    parsed_arguments = parse_arguments()

    wordlist = parsed_arguments.wordlist.read().split('\n')

    # validating arguments...
    validating_arguments(parsed_arguments, wordlist)

    # splitting wordlist in chunks for every thread
    wordlist = split_wordlist(wordlist, parsed_arguments.threads)
    
    # web fuzzer method GET
    if parsed_arguments.http_method == "GET":
        show_config(parsed_arguments)
        sleep(2)

        # header...
        print("%-70s\t%-3s\t%-10s\t%-10s"%("URL", "SC", "content_len", "server"))
        # initializating run_event to stop threads when required
        global run_event
        run_event = threading.Event()
        run_event.set()
        
        # inserting threads in a list
        thread_list = []
        for thread in range(0, parsed_arguments.threads):
            thread_list.append(threading.Thread(target=fuzzing_GET, args=(parsed_arguments, wordlist[thread])))

        # starting threads
        for thread in thread_list:
            thread.start()
            
        try:
            # if a thread clean run_event, that means a error has happened
            # for that reason, all threads must stop and the program should stop
            while run_event.is_set() and threading.active_count() > 1:
                sleep(1)
                
            # finishing threads
            for thread in thread_list:
                thread.join()
            print("[!] program successfully finished ")
            
        except KeyboardInterrupt:
            # to stop threads, run_event should be clear()
            run_event.clear()

            # stopping individual threads
            for thread in thread_list:
                thread.join()
                
            print("[!] threads successfully closed ")
            print("[!] KeyboardInterrupt: Program finished by user...")

    # web fuzz para metodo POST [aun en desarrollo]
    """
    fuzzing_POST("https://google.com/",
                {"Host":"google.com",
                 "User-Agent": "^FUZZ^"},
                ["index.html", "testing", "robots.txt", "humans.txt", "security.txt"])
    """

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n\n[!] Keyboard interrupt :: FInishing the program ")
        exit(0)
