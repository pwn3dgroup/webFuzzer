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
from sys import argv
from urllib.parse import parse_qs
from urllib.parse import urlparse
from urllib.parse import quote
from ast import literal_eval
from random import choice as random_choice

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

class ParseKwargs(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, dict())
        for value in values:
            key, value = value.split('=')
            getattr(namespace, self.dest)[key] = value    



def parse_arguments():
    # general args
    magic_word = "FUZZ"
    parser = argparse.ArgumentParser(prog="./webFuzzer.py",
                                     usage="./webFuzzer.py [options] {-w wordlist} url",
                                     description="a simple python multithreading web fuzzer",
                                     epilog="https://github.com/mind2hex/")
    parser.add_argument("-u", "--url", metavar="", required=True, help=f"target url. example[http://localhost/{magic_word}]")
    parser.add_argument("--usage", action="store_true", help="show usage examples")
    parser.add_argument("-B", "--body-data", metavar="", default={},
                        help=f"specify body data to send using post method. ex: 'username=admin&password={magic_word}'")
    parser.add_argument("-C", "--cookies", metavar="",  default={}, nargs='*', action=ParseKwargs,
                        help="specify cookies in url param format. ex: 'Cookie1=lol&Cookie2=lol'")
    parser.add_argument("-H", "--headers", metavar="", default={}, nargs='*', action=ParseKwargs,
                        help="specify http headers in url param format. ex: 'Header1=lol&Header2=lol'")    
    parser.add_argument("-M", "--http-method", metavar="", choices=["GET", "POST"], default="GET",
                        help="specify http method to use. [GET|POST] default[GET]")
    parser.add_argument("-P", "--proxies", metavar="", default={},
                        help="specify proxies. ex: 'http;http://myproxies1:8080,https;http://myproxies2:8000'")    
    parser.add_argument("-w", "--wordlist", metavar="", required=True, type=argparse.FileType('r', encoding='latin-1'),
                        help="specify wordlist to use.")
    parser.add_argument("-f", "--follow", action="store_true", default=False,
                        help="follow redirections")
    parser.add_argument("--random-UA", action="store_true", help="randomize user-agent")
    parser.add_argument("--user-agent", metavar="", default="webFuzzer", help="specify user agent")

    # performance args
    performance = parser.add_argument_group("performance options")
    performance.add_argument("--threads", metavar="<n>", type=int, default=1, help="specify how many threads [default 1]" )
    performance.add_argument("--timeout", metavar="<n>", type=int, default=10, help="specify time to wait per request response in seconds [default 10]")
    performance.add_argument("--timewait", metavar="<n>", type=int, default=0, help="specify time to wait between sending requests in seconds [default 0]")
    performance.add_argument("--retries", metavar="<n>", type=int, default=0, help="specify retries per connections if connection fail")

    # debugging args
    debug = parser.add_argument_group("debugging options")
    debug.add_argument("-v", "--verbose", action="store_true", help="show verbose messages")
    debug.add_argument("-d", "--debug", action="store_true", help="show debugging messages")
    debug.add_argument("-o", "--output", metavar="", type=argparse.FileType('w'), help="save output to a file")
                       
    # filter args
    filters = parser.add_argument_group("filter options")
    show_filters = filters.add_mutually_exclusive_group()
    show_filters.add_argument("-ss", "--ss-filter", metavar="", default="", help="show responses with the specified status codes. ex: '200,300,404'")
    show_filters.add_argument("-sc", "--sc-filter", metavar="", default="", help="show responses with the specified content lenghts. ex: '1234,4321'")
    show_filters.add_argument("-sw", "--sw-filter", metavar="", default="", help="show responses with the specified web servers. ex: 'apache,fakewebserver")
    show_filters.add_argument("-sr", "--sr-filter", metavar="", default="", help="show responses matching the specified pattern. ex: 'authentication failed'")

    hide_filters = filters.add_mutually_exclusive_group()
    hide_filters.add_argument("-hs", "--hs-filter", metavar="", default="", help="hide responses with the specified status codes. ex: '300,400'")
    hide_filters.add_argument("-hc", "--hc-filter", metavar="", default="", help="hide responses with the specified content lenghts. ex: '1234,4321'")
    hide_filters.add_argument("-hw", "--hw-filter", metavar="", default="", help="hide responses with the specified  web servers. ex: 'apache,nginx'")
    hide_filters.add_argument("-hr", "--hr-filter", metavar="", default="", help="hide responses matching the specified pattern. ex: 'authentication failed'")    

    if ("--usage" in argv):
        usage()

    

    parsed_arguments               = parser.parse_args()
    parsed_arguments.url           = urlparse(parsed_arguments.url)
    parsed_arguments.magic_word    = magic_word
    parsed_arguments.wordlist_path    = parsed_arguments.wordlist.name
    parsed_arguments.body_data     = parse_qs(parsed_arguments.body_data)

    if len(parsed_arguments.proxies) != 0:
        try:
            parsed_arguments.proxies = parsed_arguments.proxies.split(",")
            for i in range(len(parsed_arguments.proxies)):
                parsed_arguments.proxies[i] = parsed_arguments.proxies[i].split(";")
            parsed_arguments.proxies = dict(parsed_arguments.proxies)
        except:
            raise Exception(" Invalid proxies ")

    parsed_arguments.ss_filter     = parsed_arguments.ss_filter.split(",")
    parsed_arguments.sc_filter     = parsed_arguments.sc_filter.split(",")
    parsed_arguments.sw_filter     = parsed_arguments.sw_filter.split(",")
    parsed_arguments.hs_filter     = parsed_arguments.hs_filter.split(",")
    parsed_arguments.hc_filter     = parsed_arguments.hc_filter.split(",")
    parsed_arguments.hw_filter     = parsed_arguments.hw_filter.split(",")

    parsed_arguments.UserAgent_wordlist = ['Mozilla/1.22 (compatible; MSIE 2.0d; Windows NT)', 
                     'Mozilla/2.0 (compatible; MSIE 3.02; Update a; Windows NT)', 
                     'Mozilla/4.0 (compatible; MSIE 4.01; Windows NT)',
                     'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 4.0)', 
                     'Mozilla/4.79 [en] (WinNT; U)', 
                     'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:0.9.2) Gecko/20010726 Netscape6/6.1', 
                     'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.0.4) Gecko/2008102920 Firefox/3.0.4', 
                     'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022)', 
                     'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.19) Gecko/20081204 SeaMonkey/1.1.14', 
                     'Mozilla/5.0 (SymbianOS/9.2; U; Series60/3.1 NokiaE90-1/210.34.75 Profile/MIDP-2.0 Configuration/CLDC-1.1 ) AppleWebKit/413 (KHTML, like Gecko) Safari/413', 
                     'Mozilla/5.0 (iPhone; U; CPU iPhone OS 2_2 like Mac OS X; en-us) AppleWebKit/525.18.1 (KHTML, like Gecko) Version/3.1.1 Mobile/5G77 Safari/525.20', 
                     'Mozilla/5.0 (Linux; U; Android 1.5; en-gb; HTC Magic Build/CRB17) AppleWebKit/528.5+ (KHTML, like Gecko) Version/3.1.2 Mobile Safari/525.20.1', 
                     'Opera/9.27 (Windows NT 5.1; U; en)', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.27.1 (KHTML, like Gecko) Version/3.2.1 Safari/525.27.1', 
                     'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)', 
                     'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.4.154.25 Safari/525.19', 
                     'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.48 Safari/525.19', 
                     'Wget/1.8.2', 'Mozilla/5.0 (PLAYSTATION 3; 1.00)', 
                     'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; (R1 1.6))', 
                     'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.1) Gecko/20061204 Firefox/2.0.0.1', 
                     'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.9.0.10) Gecko/2009042316 Firefox/3.0.10 (.NET CLR 3.5.30729) JBroFuzz/1.4', 
                     'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)', 
                     'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20050923 CentOS/1.0.7-1.4.1.centos4 Firefox/1.0.7', 
                     'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; SLCC1; .NET CLR 2.0.50727)', 
                     'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.9.0.5) Gecko/2008120122 Firefox/3.0.5', 
                     'Mozilla/5.0 (X11; U; SunOS i86pc; en-US; rv:1.7) Gecko/20070606', 'Mozilla/5.0 (X11; U; SunOS i86pc; en-US; rv:1.8.1.14) Gecko/20080520 Firefox/2.0.0.14', 
                     'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; en-US; rv:1.9.0.5) Gecko/2008120121 Firefox/3.0.5']        

    return parsed_arguments

def usage():
    """ Only show ussage messages """
    target   = "https://google.com/"
    magic    = "@FUZZ@"
    wordlist = "wordlist.txt"
    proxies    = "http;http://localhost:8080,https;http://localhost:8000"
    
    print("### direcroty enumeration")
    print(f"$ ./webFuzzer.py -ss 200 -w {wordlist} {target}{magic}\n")
    print("### parameter testing ")
    print(f"$ ./webFuzzer.py -ss 200 -w {wordlist} {target}script.php?param1={magic}\n")
    print("### Fuzzing post body data ")
    print(f"$ ./webFuzzer.py -M POST -hr 'alert=1' -w {wordlist} -B 'username=admin&password={magic}' {target}login\n")
    print("### using proxies ")
    print(f"$ ./webFuzzer.py -P {proxies} -w {wordlist} {target}{magic}\n")
    exit(0)

def initial_checks(args):
    """ Initial checks before proceeds with the program execution"""
    # testing target connection
    try:
        requests.get(args.url.geturl(), timeout=5)
    except requests.exceptions.ConnectionError:
        print(f"[X] Failed to establish a new connection to {args.url}")
        exit(-1)

def validate_arguments(args):
    # validating url format
    validate_url(args.url.geturl())

    # checking magic_word inside GET request
    if ((args.http_method == "GET") and (args.magic_word not in args.url.geturl())):
        raise Exception(f"magic word {args.magic_word} not in the url: {args.url}")

    # checking magic_word inside POST request
    if (args.http_method == "POST"):
        if len(args.body_data) == 0:
            raise Exception("No body data specified...")

        # checking magic word in body data first
        state = False
        bd = str(args.body_data)
        if args.magic_word in bd:
            state = True
        
        # if magic word not in body data, then search in url
        if state == False:
            if args.magic_word not in args.url.geturl():
                raise Exception(f" magic word {args.magic_word} not specified in body data neither url")

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

def validate_url(url):
    if (validators.url(url) != True):
        raise Exception(f"invalid url: {url}")    

def fuzzing(args):
    class Namespace():
        pass

    filters = Namespace()

    global run_event
    # iterating wordlist

    word = " "
    while word != '':
        word = args.wordlist.readline()
        word = quote(word.strip())

        # checking if threads should still running
        if run_event.is_set() == False:
            break
        
        # replacing magic word from url
        new_url = args.url.geturl().replace(args.magic_word, word)

        # replacing magic word from headers
        headers = str(args.headers)
        headers = headers.replace(args.magic_word, word)
        headers = literal_eval(headers)

        headers.setdefault("User-Agent", args.user_agent)

        if (args.random_UA == True):
            headers["User-Agent"] = random_choice(args.UserAgent_wordlist)

        # replacing magic word from cookies
        cookies = str(args.cookies)
        cookies = cookies.replace(args.magic_word, word)
        cookies = literal_eval(cookies)

        # replacing magic word from body data
        body_data = str(args.body_data)
        body_data = body_data.replace(args.magic_word, word)
        body_data = literal_eval(body_data)

        try:
            if args.http_method == "GET":
                req = requests.request("GET", new_url, timeout=int(args.timeout),
                                       allow_redirects=args.follow, proxies=args.proxies,
                                       cookies=cookies, headers=headers)
            elif args.http_method == "POST":
                req = requests.request(method="POST", url=new_url, data=body_data,
                                       timeout=int(args.timeout), allow_redirects=args.follow, proxies=args.proxies,
                                       cookies=cookies, headers=headers)
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
                if args.http_method == "GET":
                    print("%-100s\t%-3s\t%-10s\t%-10s"%(new_url, req.status_code, req.headers["Content-Length"], req.headers["Server"]))
                elif args.http_method == "POST":
                    print("%-100s\t%-3s\t%-10s\t%-10s"%(str(body_data), req.status_code, req.headers["Content-Length"], req.headers["Server"]))
                continue               

        if (args.hs_filter[0] != "NONE" or args.hc_filter[0] != "NONE" or args.hw_filter[0] != "NONE" or args.hr_filter != "NONE"):
            filters.sc = args.hs_filter
            filters.cl = args.hc_filter
            filters.ws = args.hw_filter
            filters.re = args.hr_filter

            if response_filter(filters, req) == False:
                if args.http_method == "GET":
                    print("%-100s\t%-3s\t%-10s\t%-10s"%(new_url, req.status_code, req.headers["Content-Length"], req.headers["Server"]))
                elif args.http_method == "POST":
                    print("%-100s\t%-3s\t%-10s\t%-10s"%(str(body_data), req.status_code, req.headers["Content-Length"], req.headers["Server"]))
                continue                               
        
        if args.http_method == "GET":
            print("%-100s\t%-3s\t%-10s\t%-10s"%(new_url, req.status_code, req.headers["Content-Length"], req.headers["Server"]), end="\r")
        elif args.http_method == "POST":
            print("%-100s\t%-3s\t%-10s\t%-10s"%(str(body_data), req.status_code, req.headers["Content-Length"], req.headers["Server"]), end="\r")            
    
    return 0    


def response_filter(filters, response):
    filter_status = False
    # show filters
    if (len(filters.sc[0]) > 0):
        # show matching status code filter
        if str(response.status_code) in filters.sc:
            filter_status = True

    elif (len(filters.cl[0]) > 0):
        # show matching content length filter
        if response.headers["Content-Length"] != "UNK":
            if str(response.headers["Content-Length"]) in filters.cl:
                filter_status = True

    elif (len(filters.ws[0]) > 0):
        # show matching web server name filter 
        if response.headers["Server"] in filters.ws:
            filter_status = True

    elif (len(filters.re) > 0):
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
    print(f"          TARGET: {args.url.geturl()}")
    print(f"     HTTP METHOD: {args.http_method}")
    if (args.http_method == "POST"):
        print(f"           BODY DATA: {args.body_data}")
    if (len(args.cookies) > 0):
        print(f"             COOKIES: {args.cookies}")
    if (len(args.headers) > 0):
        print(f"             HEADERS: {args.headers}")
    if (len(args.proxies) > 0):
        print(f"             PROXIES: {args.proxies}")
    print(f"      USER AGENT: {args.user_agent}")
    print(f" RAND USER AGENT: {args.random_UA}")
    print(f"FOLLOW REDIRECTS: {args.follow}")
    print(f"        WORDLIST: {args.wordlist_path}")
    print()
    print("[!] Performance...")
    print(f"         THREADS: {args.threads}")
    print(f"         TIMEOUT: {args.timeout}")
    print(f"        TIMEWAIT: {args.timewait}")
    print(f"         RETRIES: {args.retries}")    
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

def verbose(state, msg):
    if state == True:
        print("[!] verbose:", msg)

def GET(args):
    # header...
    print("%-100s\t%-3s\t%-10s\t%-10s"%("URL", "SC", "content_len", "server"))

    # initializating run_event to stop threads when required
    global run_event
    run_event = threading.Event()
    run_event.set()

    # inserting threads in a list
    thread_list = []
    
    for thread in range(0, args.threads):
        thread_list.append(threading.Thread(target=fuzzing, args=[args]))

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
    print("%-100s\t%-3s\t%-10s\t%-10s"%("BODY DATA", "SC", "content_len", "server"))

    # initializating run_event to stop threads when required
    global run_event
    run_event = threading.Event()
    run_event.set()

    # inserting threads in a list
    thread_list = []
    for thread in range(0, args.threads):
        thread_list.append(threading.Thread(target=fuzzing, args=[args]))

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

    # program initial checks
    initial_checks(parsed_arguments)

    # validating arguments...
    validate_arguments(parsed_arguments)


    # show user specified CLI args
    show_config(parsed_arguments)    
    sleep(2)

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

# refactorizar algunas funciones
# opcion para especificar la cantidad maxima de reintentos por conexion
# modificar programa para hacer fuzzing a cookies y headers
# agregar opcion para aleatorizar user-agent
# agregar opcion para basic auth 
