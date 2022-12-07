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
    text = """
               _     ______                      
              | |   |  ____|                     
 __      _____| |__ | |__ _   _ ___________ _ __ 
 \ \ /\ / / _ \ '_ \|  __| | | |_  /_  / _ \ '__|
  \ V  V /  __/ |_) | |  | |_| |/ / / /  __/ |   
   \_/\_/ \___|_.__/|_|   \__,_/___/___\___|_|   
                                                 
    author: mind2hex
    version: 1.0
    """
    print(text)

def parse_arguments():
    # general args
    magic_word = "#FUZZ#"
    parser = argparse.ArgumentParser(prog="./webFuzzer.py",
                                     usage="./webFuzzer.py [options] {-w wordlist} url",
                                     description="a simple python multithreading web fuzzer",
                                     epilog="https://github.com/mind2hex/")
    parser.add_argument("--usage", action="store_true", 
                        help="show usage examples")
    parser.add_argument("url", help=f"specify target url. example[http://localhost/{magic_word}]")
    parser.add_argument("--http-method", metavar="M", choices=["GET", "POST"], default="GET",
                        help="specify an HTTP for the request method    default[GET]")
    parser.add_argument("--port", default=80, metavar="<n>", type=int,
                        help="specify target port")
    parser.add_argument("--wordlist", metavar="/path", required=True, type=argparse.FileType('r', encoding='latin-1'),
                        help="specify wordlist")
    parser.add_argument("--body-data", metavar="key=val", default="NONE",
                        help=f"specify body data to send using post method. example[username=admin;password={magic_word}]")
    parser.add_argument("--proxies", metavar="url", default="NONE",
                        help="specify coma separated proxies url's ")

    # timming args
    timming = parser.add_argument_group("timming")
    timming.add_argument("--threads", metavar="<n>", type=int,
                        help="specify threads [default 1]", default=1)
    timming.add_argument("--timeout", metavar="<n>",
                        help="timeout per request in seconds [default 10]", default=10)

    # debugging args
    debug = parser.add_argument_group("debugging")
    debug.add_argument("--verbose", action="store_true",
                       help="show verbose message")
    debug.add_argument("--debug", action="store_true",
                       help="show debugging message")
    debug.add_argument("--output", metavar="file", type=argparse.FileType('w'),
                       help="save output to a file")

    # filter args
    filters = parser.add_argument_group("filters")
    show_filters = filters.add_mutually_exclusive_group()
    show_filters.add_argument("--ss-filter", metavar="nnn,nnn...", default="NONE",
                              help="only show responses with the specified comma separated status codes. ")
    show_filters.add_argument("--sc-filter", metavar="nnn,nnn...", default="NONE",
                              help="only show responses with the specified comma separated content lenghts. example[nnn,nnnn,n...]")
    show_filters.add_argument("--sw-filter", metavar="ws1,ws2...", default="NONE",
                              help="only show responses with the specified comma separated web servers. example[apache,nginx...]")
    show_filters.add_argument("--sr-filter", metavar="pattern-regex", default="NONE",
                              help="only show responses with the specified response body matching pattern...")

    hide_filters = filters.add_mutually_exclusive_group()
    hide_filters.add_argument("--hs-filter", metavar="nnn,nnn...", default="NONE",
                              help="hide responses with the specified comma separated status codes.")
    hide_filters.add_argument("--hc-filter", metavar="nnn,nnn...", default="NONE",
                              help="hide responses with the specified comma separated content lenghts. example[nnn,nnnn,n...]")
    hide_filters.add_argument("--hw-filter", metavar="ws1,ws2...", default="NONE",
                              help="hide responses with the specified comma separated web servers. example[apache,nginx...]")
    hide_filters.add_argument("--hr-filter", metavar="pattern-regex", default="NONE",
                              help="hide responses with the specified pattern...")    

    

    parsed_arguments               = parser.parse_args()

    parsed_arguments.magic_word    = magic_word

    parsed_arguments.wordlist_path = parsed_arguments.wordlist.name
    parsed_arguments.wordlist      = parsed_arguments.wordlist.read().split('\n')
    
    parsed_arguments.body_data     = parsed_arguments.body_data.split("&")
    for i in range(len(parsed_arguments.body_data)):
        parsed_arguments.body_data[i] = parsed_arguments.body_data[i].split("=")

    parsed_arguments.proxies       = parsed_arguments.proxies.split(",")

    parsed_arguments.ss_filter     = parsed_arguments.ss_filter.split(",")
    parsed_arguments.sc_filter     = parsed_arguments.sc_filter.split(",")
    parsed_arguments.sw_filter     = parsed_arguments.sw_filter.split(",")
    parsed_arguments.hs_filter     = parsed_arguments.hs_filter.split(",")
    parsed_arguments.hc_filter     = parsed_arguments.hc_filter.split(",")
    parsed_arguments.hw_filter     = parsed_arguments.hw_filter.split(",")    

    return parsed_arguments

def validating_arguments(args):
    MAX_THREADS = 60
    
    # validating url format
    if (validators.url(args.url) != True):
        raise Exception(f"invalid url: {args.url}")

    # validating magic_word inside GET request    
    if ((args.http_method == "GET") and (args.magic_word not in args.url)):
        raise Exception(f"magic word {args.magic_word} not in the url: {args.url}")
    elif (args.http_method == "POST"):
        # validating magic_word inside POST request    
        state = False
        if (args.http_method == "POST"): 
            for data in args.body_data:

                if len(data) == 1 or len(data[0]) == 0:
                    raise Exception("Invalid body data")

                for i in data:
                    if args.magic_word in i:
                        state = True
        if state == False:
            raise Exception(f"magic word not in body data...")
    
    # validating port number
    if (args.port not in range(1, 65535)):
        raise Exception(f"Invalid port number: {args.port}")

    # validating maximum threads
    if (args.threads > MAX_THREADS):
        raise Exception(f"the threads exceed the thread limit. If you want your cpu to explode, modify the MAX_THREADS variable")

    # validating threads and wordlist len
    if (args.threads > len(args.wordlist)):
        raise Exception(f"too many threads for so few words...")

    # validating ss_filter (show status code filter)
    if (args.ss_filter[0] != "NONE"):
        for status_code in args.ss_filter:
            if status_code.isdigit == False:
                raise Exception(f" incorrect ss_filter value {status_code}")

    # validating sc_filter (show content length filter)
    if (args.sc_filter[0] != "NONE"):
        for content_length in args.sc_filter:
            if content_length.isdigit == False:
                raise Exception(f" incorrect sc_filter value {content_length}")

    # validating sw_filter (show web server filter)
    # enter web server validations here if needed
        
    # validating hs-filter (hide status code filter)
    if (args.hs_filter[0] != "NONE"):
        for status_code in args.hs_filter:
            if status_code.isdigit == False:
                raise Exception(f" incorrect hs_filter value {status_code}")

    # validating sc-filter (hide content length filter)
    if (args.hc_filter[0] != "NONE"):
        for content_length in args.hc_filter:
            if content_length.isdigit == False:
                raise Exception(f" incorrect hc_filter value {content_length}")

    # validating hw_filter (hide web server filter)
    # enter web server validations here if needed                

        
def fuzzing_GET(args, wordlist:list):
    class Namespace():
        pass

    filters = Namespace()

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

        # in case server didnt send back content length and server info            
        req.headers.setdefault("Content-Length", "UNK")
        req.headers.setdefault("Server",         "UNK")

        if (args.ss_filter[0] != "NONE" or args.sc_filter[0] != "NONE" or args.sw_filter[0] != "NONE" or args.sr_filter != "NONE"):
            filters.sc = args.ss_filter
            filters.cl = args.sc_filter
            filters.ws = args.sw_filter
            filters.re = args.sr_filter

            if response_filter(filters, req) == True:
                print("%-70s\t%-3s\t%-10s\t%-10s"%(new_url, req.status_code, req.headers["Content-Length"], req.headers["Server"]))
                continue               

        if (args.hs_filter[0] != "NONE" or args.hc_filter[0] != "NONE" or args.hw_filter[0] != "NONE" or args.hr_filter != "NONE"):
            filters.sc = args.hs_filter
            filters.cl = args.hc_filter
            filters.ws = args.hw_filter
            filters.re = args.hr_filter

            if response_filter(filters, req) == False:
                print("%-70s\t%-3s\t%-10s\t%-10s"%(new_url, req.status_code, req.headers["Content-Length"], req.headers["Server"]))
                continue                               
        
        print("%-70s\t%-3s\t%-10s\t%-10s"%(new_url, req.status_code, req.headers["Content-Length"], req.headers["Server"]), end="\r")
    
    return 0

def list2dict(lista:list):
    d = dict()
    for i in lista:
        d[i[0]] = i[1]
    
    return d

def list2string(lista:list):
    string = ""
    for i in lista:
        string += "=".join(i)
        string += "&"

    return string.strip("&")

def fuzzing_POST(args, wordlist:list):
    class Namespace():
        pass

    filters = Namespace()

    global run_event
    # iterating wordlist
    for word in wordlist:
        # checking if threads should still running
        if run_event.is_set() == False:
            break
        
        # replacing magic word in body data
        raw_data = list()
        for i in range(len(args.body_data)):
            raw_data.append(args.body_data[i].copy())
            for j in range(len(raw_data[i])):
                if args.magic_word in raw_data[i][j]:
                    raw_data[i][j] = raw_data[i][j].replace(args.magic_word, word)

        body_data = list2dict(raw_data)

        try:
            req = requests.request(method="POST", url=args.url, data=body_data, timeout=int(args.timeout), allow_redirects=False)
        except requests.ConnectTimeout:
            print("[!] Connection Time Out: %-100s"%(args.url))
            continue
        except socket.error:
            print("[!] Error stablishing connection, finishing program...")
            run_event.clear()
            exit(0)

        # in case server didnt send back content length and server info            
        req.headers.setdefault("Content-Length", "UNK")
        req.headers.setdefault("Server",         "UNK")

        if (args.ss_filter[0] != "NONE" or args.sc_filter[0] != "NONE" or args.sw_filter[0] != "NONE" or args.sr_filter != "NONE"):
            filters.sc = args.ss_filter
            filters.cl = args.sc_filter
            filters.ws = args.sw_filter
            filters.re = args.sr_filter

            if response_filter(filters, req) == True:
                print("%-70s\t%-3s\t%-10s\t%-10s"%(list2string(raw_data), req.status_code, req.headers["Content-Length"], req.headers["Server"]))
                continue               

        if (args.hs_filter[0] != "NONE" or args.hc_filter[0] != "NONE" or args.hw_filter[0] != "NONE" or args.hr_filter != "NONE"):
            filters.sc = args.hs_filter
            filters.cl = args.hc_filter
            filters.ws = args.hw_filter
            filters.re = args.hr_filter

            if response_filter(filters, req) == False:
                print("%-70s\t%-3s\t%-10s\t%-10s"%(list2string(raw_data), req.status_code, req.headers["Content-Length"], req.headers["Server"]))
                continue                               
        
        print("%-70s\t%-3s\t%-10s\t%-10s"%(list2string(raw_data), req.status_code, req.headers["Content-Length"], req.headers["Server"]), end="\r")

    return 0    

def response_filter(filters, response):
    filter_status = False
    # show filters
    if (filters.sc[0] != "NONE"):
        # show matching status code filter
        if str(response.status_code) in filters.sc:
            filter_status = True

    elif (filters.cl[0] != "NONE"):
        # show matching content length filter
        if response.headers["Content-Length"] != "UNK":
            if str(response.content_len) in filters.cl:
                filter_status = True

    elif (filters.ws[0] != "NONE"):
        # show matching web server name filter 
        if response.headers["Server"] in filters.ws:
            filter_status = True

    elif (filters.re != "NONE"):
        # show matching pattern filter
        # searching matching patterns in response headers
        matching = False
        for header in response.headers.keys():
            if re.search(filters.re, response.headers[header]) != None:
                matching = True
                break

        if matching == True:
            filter_status = True
        else:
            aux = re.search(filters.re, response.content.decode("latin-1"))
            if aux != None:
                filter_status = True

    return filter_status

def show_config(args):
    print("==========================================")
    print("[!] General...")
    print(f"             URL: {args.url}")
    print(f"     HTTP METHOD: {args.http_method}")
    if (args.http_method == "POST"):
        print(f"           BODY DATA: {list2string(args.body_data)}")
            
    print(f"            PORT: {args.port}")
    print(f"        WORDLIST: {args.wordlist_path}")
    if (args.proxies != "NONE"):
        for proxy in args.proxies:
            print(f"           PROXY: {proxy}")
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
    aux_0 = 0
    aux_1 = wordlist_chunks

    while aux_1 <= wordlist_len:
        result.append(wordlist[aux_0:aux_1])
        aux_0 = aux_1
        aux_1 += wordlist_chunks

    return result


def verbose(state, msg):
    if state == True:
        print("[!] verbose:", msg)


def GET(args):

    # header...
    print("%-70s\t%-3s\t%-10s\t%-10s"%("URL", "SC", "content_len", "server"))

    # initializating run_event to stop threads when required
    global run_event
    run_event = threading.Event()
    run_event.set()
    
    # inserting threads in a list
    thread_list = []
    for thread in range(0, args.threads):
        thread_list.append(threading.Thread(target=fuzzing_GET, args=(args, args.wordlist[thread])))

    # starting threads
    for thread in thread_list:
        thread.start()
        
    exit_msg = ""
    try:
        # if a thread clean run_event variable, that means a error has happened
        # for that reason, all threads must stop and the program itself should stop too
        while run_event.is_set() and threading.active_count() > 1:
            sleep(1)

        exit_msg = "[!] program successfully finished "
        
    except KeyboardInterrupt:
        # to stop threads, run_event should be clear()
        run_event.clear()
            
        exit_msg = "[!] threads successfully closed \n"
        exit_msg += "[!] KeyboardInterrupt: Program finished by user..."

    finally:
        # finishing threads
        for thread in thread_list:
            thread.join()

        print(exit_msg)


def POST(args):
    # header...
    print("%-70s\t%-3s\t%-10s\t%-10s"%("BODY DATA", "SC", "content_len", "server"))

    # initializating run_event to stop threads when required
    global run_event
    run_event = threading.Event()
    run_event.set()
    
    # inserting threads in a list
    thread_list = []
    for thread in range(0, args.threads):
        thread_list.append(threading.Thread(target=fuzzing_POST, args=(args, args.wordlist[thread])))

    # starting threads
    for thread in thread_list:
        thread.start()
        
    exit_msg = ""
    try:
        # if a thread clean run_event variable, that means a error has happened
        # for that reason, all threads must stop and the program itself should stop too
        while run_event.is_set() and threading.active_count() > 1:
            sleep(1)

        exit_msg = "[!] program successfully finished "
        
    except KeyboardInterrupt:
        # to stop threads, run_event should be clear()
        run_event.clear()
            
        exit_msg = "[!] threads successfully closed \n"
        exit_msg += "[!] KeyboardInterrupt: Program finished by user..."

    finally:
        # finishing threads
        for thread in thread_list:
            thread.join()

        print(exit_msg)    

        
def main():
    banner()
    
    # parsing arguments...
    parsed_arguments = parse_arguments()

    # validating arguments...
    validating_arguments(parsed_arguments)

    # splitting wordlist in chunks for every thread
    parsed_arguments.wordlist = split_wordlist(parsed_arguments.wordlist, parsed_arguments.threads)

    # show user specified CLI args
    show_config(parsed_arguments)    
    sleep(2)

    # web fuzzer method GET
    if parsed_arguments.http_method == "GET":
        GET(parsed_arguments)

    elif parsed_arguments.http_method == "POST":
        POST(parsed_arguments)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n\n[!] Keyboard interrupt :: FInishing the program ")
        exit(0)


# agregar opcion para proxies
# agregar opcion para headers
# agregar opcion para cookies

