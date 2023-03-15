#!/usr/bin/python3
#      author: mind2hex
# description: simple web fuzzer

import argparse 
import requests
import threading
import socket
import re
from time import sleep
from sys import argv
from urllib.parse import urlparse
from urllib.parse import quote
from ast import literal_eval
from random import choice as random_choice
from django.core.validators import URLValidator
from alive_progress import alive_bar
from itertools import count


def banner():
    author="mind2hex"
    version="1.0"
    print(f"""
               _     ______                      
              | |   |  ____|                     
 __      _____| |__ | |__ _   _ ___________ _ __ 
 \ \ /\ / / _ \ '_ \|  __| | | |_  /_  / _ \ '__|
  \ V  V /  __/ |_) | |  | |_| |/ / / /  __/ |   
   \_/\_/ \___|_.__/|_|   \__,_/___/___\___|_|   
                                                 
    author:  {bcolors.HEADER}{author}{bcolors.ENDC}
    version: {bcolors.HEADER}{version}{bcolors.ENDC}
    """)
    

class DictParser(argparse.Action):
    """this class is used to convert an argument directly into a dict using the format key=value&key=value"""
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, dict())
        try:
            for query in values.split("&"):
                key, val = query.split('=')
                getattr(namespace, self.dest)[key] = val    
        except:
            show_error(f"uanble to parse {values} due to incorrect format ", "DictParser")


class ProxyParser(argparse.Action):
    """this class is used to convert an argument directly into a dict using the format key;value,key=value"""
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, dict())
        try:
            for query in values.split(","):
                key, val = query.split(';')
                getattr(namespace, self.dest)[key] = val    
        except:
            show_error(f"uanble to parse {values} due to incorrect format ", "ProxyParser")

class bcolors:
    HEADER  = '\033[95m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL    = '\033[91m'
    ENDC    = '\033[0m'


def parse_arguments():
    """ return parsed arguments """

    magic_word = "FUZZ"
    parser = argparse.ArgumentParser(prog="./webFuzzer.py", 
                                     usage="./webFuzzer.py [options] -u {url} -w {wordlist}",
                                     description="a simple python multithreading web fuzzer", 
                                     epilog="https://github.com/mind2hex/")
    
    # general args
    parser.add_argument("-u", "--url",         metavar="", required=True, help=f"target url. ex --> http://localhost/{magic_word}")
    parser.add_argument("-w", "--wordlist",    metavar="", required=True, type=argparse.FileType('r', encoding='latin-1'), help="wordlist")
    parser.add_argument("-b", "--body-data",   metavar="", help=f"body data to send using POST method. ex --> 'username=admin&password={magic_word}'")
    parser.add_argument("-C", "--cookies",     metavar="", default={}, action=DictParser,  help="set cookies.      ex --> 'Cookie1=lol&Cookie2=lol'")
    parser.add_argument("-H", "--headers",     metavar="", default={}, action=DictParser,  help="set HTTP headers. ex --> 'Header1=lol&Header2=lol'")    
    parser.add_argument("-P", "--proxies",     metavar="", default={}, action=ProxyParser, help="set proxies.      ex --> 'http;http://proxy1:8080,https;http://proxy2:8000'") 
    parser.add_argument("-U", "--user-agent",  metavar="", default="yoMama", help="specify user agent")
    parser.add_argument("-X", "--http-method", metavar="", choices=["GET", "POST"], default="GET", help="HTTP method to use. [GET|POST]")
    parser.add_argument("-f", "--follow",    action="store_true", default=False, help="follow redirections")
    parser.add_argument("--rand-user-agent", action="store_true", help="randomize user-agent")
    parser.add_argument("--usage",           action="store_true", help="show usage examples")    
    parser.add_argument("--ignore-errors",   action="store_true", help="ignore connection errors, useful to enumerate fuzz subdomains")
    
    # performance args
    performance = parser.add_argument_group("performance options")
    performance.add_argument("--threads",  metavar="<n>", type=int, default=1,  help="threads [default 1]" )
    performance.add_argument("--timeout",  metavar="<n>", type=int, default=10, help="time to wait for response in seconds [default 10]")
    performance.add_argument("--timewait", metavar="<n>", type=int, default=0,  help="time to wait between each requests in seconds [default 0]")
    performance.add_argument("--retries",  metavar="<n>", type=int, default=0,  help="retries per connections if connection fail [default 0]")

    # debugging args
    debug = parser.add_argument_group("debugging options")
    debug.add_argument("-v", "--verbose", action="store_true", help="show verbose messages")
    debug.add_argument("-d", "--debug",   action="store_true", help="show debugging messages")
    debug.add_argument("-o", "--output",  metavar="", type=argparse.FileType('w'), help="save output to a file")
    debug.add_argument("-q", "--quiet",   action="store_true", help="dont show config before execution")

    # show filter group args
    filters = parser.add_argument_group("filter options")
    show_filters = filters.add_mutually_exclusive_group()
    show_filters.add_argument("-ss", "--ss-filter", metavar="", default="None", help="show responses with the specified status codes. ex: '200,300,404'")
    show_filters.add_argument("-sc", "--sc-filter", metavar="", default="None", help="show responses with the specified content lenghts. ex: '1234,4321'")
    show_filters.add_argument("-sw", "--sw-filter", metavar="", default="None", help="show responses with the specified web servers. ex: 'apache,fakewebserver")
    show_filters.add_argument("-sr", "--sr-filter", metavar="", default="None", help="show responses matching the specified pattern. ex: 'authentication failed'")

    # hide filter group args
    hide_filters = filters.add_mutually_exclusive_group()
    hide_filters.add_argument("-hs", "--hs-filter", metavar="", default="None", help="hide responses with the specified status codes. ex: '300,400'")
    hide_filters.add_argument("-hc", "--hc-filter", metavar="", default="None", help="hide responses with the specified content lenghts. ex: '1234,4321'")
    hide_filters.add_argument("-hw", "--hw-filter", metavar="", default="None", help="hide responses with the specified  web servers. ex: 'apache,nginx'")
    hide_filters.add_argument("-hr", "--hr-filter", metavar="", default="None", help="hide responses matching the specified pattern. ex: 'authentication failed'")    

    parsed_arguments               = parser.parse_args()        
    parsed_arguments.magic_word    = magic_word

    # parsing wordlist and total requests
    parsed_arguments.wordlist_path = parsed_arguments.wordlist.name
    parsed_arguments.request_count = 0
    with open(parsed_arguments.wordlist_path, 'r', encoding="latin-1") as f:
        parsed_arguments.request_total = sum(1 for _ in f)        

    # parsing filters
    parsed_arguments.ss_filter     = parsed_arguments.ss_filter.split(",")
    parsed_arguments.sc_filter     = parsed_arguments.sc_filter.split(",")
    parsed_arguments.sw_filter     = parsed_arguments.sw_filter.split(",")
    parsed_arguments.hs_filter     = parsed_arguments.hs_filter.split(",")
    parsed_arguments.hc_filter     = parsed_arguments.hc_filter.split(",")
    parsed_arguments.hw_filter     = parsed_arguments.hw_filter.split(",")

    # parsing user agents
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
    magic    = "FUZZ"
    wordlist = "/path/wordlist.txt"
    proxies  = "http;http://localhost:8080,https;http://localhost:8000"

    print("### directory enumeration")
    print(f"$ ./webFuzzer.py -ss 200,300 -w {wordlist} -u {target}{magic}\n")
    print("### parameter testing ")
    print(f"$ ./webFuzzer.py -ss 200 -w {wordlist} -u {target}script.php?param1={magic}\n")
    print("### Fuzzing post body data [bruteforce attack]")
    print(f"$ ./webFuzzer.py -M POST -hr 'alert=1' -w {wordlist} -B 'username=admin&password={magic}' -u {target}login\n")
    print("### using proxies ")
    print(f"$ ./webFuzzer.py -P {proxies} -w {wordlist} -u {target}{magic}\n")
    print("### specifying user agent and cookie ")
    print(f"$ ./webFuzzer.py --user-agent FirefoxBOT -C cookie=monster&cookie2=monster2 -w {wordlist} -u {target}{magic}\n")

    exit(0)

def initial_checks(args):
    """ Initial checks before proceeds with the program execution"""

    # testing target connection
    try:
        requests.get(args.url, timeout=args.timeout)
    except requests.exceptions.ConnectionError:
        show_error(f"Failed to establish a new connection to {args.url}", "initial_checks()")
        
    # testing proxy connection
    if len(args.proxies) > 0:
        try:
            requests.get(args.url+"/proxy_test", timeout=args.timeout, proxies=args.proxies)
        except :
            show_error(f"Proxy server is not responding", "initial_checks()")

    # checking magic_word inside GET request
    if ((args.http_method == "GET") and (args.magic_word not in args.url)):
        show_error(f"magic word {args.magic_word} not in the url: {args.url}", "initial_checks()")

    # checking magic_word inside POST request
    if (args.http_method == "POST"):
        if len(args.body_data) == 0:
            show_error("No body data specified...", "initial_checks()")

        if ((args.magic_word not in args.url) and (args.magic_word not in args.body_data)):
            show_error("magic word {args.magic_word} not in the url neither body data", "initial_checks()")

def validate_arguments(args):
    """ validate_arguments checks that every argument is valid or in the correct format """
    
    validate_url(args.url)

    #validate_wordlist(args.wordlist_path)

    if args.http_method == "POST":
        validate_body_data(args.headers, args.body_data)

    #validate_cookies(args.cookies)

    #validate_headers(args.headers)

    #validate_user_agent(args.user_agent)

    #validate_threads(args.threads)

    #validate_timeout(args.timeout)

    #validate_timewait(args.timewait)

    #validate_retries(args.retries)

    #validate_output(args.output)

    #validate_filters(args.filters)

    #validate_proxies(args.proxies)

    """
    if len(parsed_arguments.proxies) != 0:
        try:
            parsed_arguments.proxies = parsed_arguments.proxies.split(",")
            for i in range(len(parsed_arguments.proxies)):
                parsed_arguments.proxies[i] = parsed_arguments.proxies[i].split(";")
            parsed_arguments.proxies = dict(parsed_arguments.proxies)
        except:
            raise Exception(" Invalid proxies ")
    """

    # validating ss_filter (show status code filter)
    if (args.ss_filter[0] != "None"):
        for status_code in args.ss_filter:
            if status_code.isdigit == False:
                raise Exception(f" incorrect ss_filter value {status_code}")

    # validating sc_filter (show content length filter)
    if (args.sc_filter[0] != "None"):
        for content_length in args.sc_filter:
            if content_length.isdigit == False:
                raise Exception(f" incorrect sc_filter value {content_length}")

    # validating hs-filter (hide status code filter)
    if (args.hs_filter[0] != "None"):
        for status_code in args.hs_filter:
            if status_code.isdigit == False:
                raise Exception(f" incorrect hs_filter value {status_code}")

    # validating sc-filter (hide content length filter)
    if (args.hc_filter[0] != "None"):
        for content_length in args.hc_filter:
            if content_length.isdigit == False:
                raise Exception(f" incorrect hc_filter value {content_length}")

def validate_url(url):
    """ validate url using URLValidator from django"""
    val = URLValidator()    
    try:
        val(url)
    except:
        show_error(f"Error while validating url --> {url}", "validate_url")

def validate_body_data(headers, body_data):
    pass
    
def show_error(msg, origin):
    print(f"\n {origin} --> {bcolors.FAIL}error{bcolors.ENDC}")
    print(f" [X] {bcolors.FAIL}{msg}{bcolors.ENDC}")
    exit(-1)

def show_config(args):
    print("==========================================")
    print("[!] General...")
    print(f"          TARGET: {args.url}")
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
    print(f" RAND USER AGENT: {args.rand_user_agent}")
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
    sleep(2)

def verbose(state, msg):
    if state == True:
        print("[!] verbose:", msg)    

def prog_bar(args):
    """ Progress bar"""

    # as prog_bar is executed as a thread, it uses global variable
    # run_event to know when it has to stop 
    global run_event

    # setting global variable bar because it will be called from other threads
    # every time bar is called, progress var increments is bar in 1 
    global bar

    # starting alive_bar
    with alive_bar(args.request_total, title=f"Progress", enrich_print=False) as bar:
        while args.request_count < args.request_total:
            # stop thread if run_event not set
            if run_event.is_set() == False:
                break
            
            sleep(0.1)

def fuzzing(args):
    """ 
    fuzzing do the next jobs
        - read line by line the specified wordlist (args.wordlist)
        - replaces every magic word (args.magic_word) in the HTTP request with the line read before
        - sends the HTTP request and filters output with status code, content length, server or matching patterns

    """
    class Namespace():
        pass

    filters = Namespace()

    global run_event, bar

    word = " "
    retry_counter = 0    
    
    while True:
        # iterating to next word only when retry_counter = 0 
        if retry_counter == 0:
            word = args.wordlist.readline()
            word = quote(word.strip())

        # checking if threads should still running
        if run_event.is_set() == False:
            break

        # checking if thread exceeded total requests
        if args.request_count >= args.request_total:
            break

        # ignoring empty lines
        if word == "":
            bar()
            args.request_count += 1
            continue
        
        # replacing magic word from url
        new_url = args.url.replace(args.magic_word, word)

        # replacing magic word from headers
        headers = str(args.headers)
        headers = headers.replace(args.magic_word, word)
        headers = literal_eval(headers)

        # setting user_agent if not specified
        headers.setdefault("User-Agent", args.user_agent)

        # random user agent
        if (args.rand_user_agent == True):
            headers["User-Agent"] = random_choice(args.UserAgent_wordlist)

        # replacing magic word from cookies
        cookies = str(args.cookies)
        cookies = cookies.replace(args.magic_word, word)
        cookies = literal_eval(cookies)

        # replacing magic word from body data
        if args.http_method == "POST":
            body_data = args.body_data
            body_data = body_data.replace(args.magic_word, word)

        # forming payload
        payload = ""
        if args.magic_word in args.url:
            payload = payload + new_url + " - "
        if args.magic_word in str(args.headers):
            payload = payload + str(headers) + " - "
        if args.magic_word in str(args.cookies):
            payload = payload + str(cookies) + " - "
        if args.magic_word in str(args.body_data):
            payload = payload + body_data + " - "



        try:
            if args.http_method == "GET":
                req = requests.get(new_url, timeout=int(args.timeout),
                                       allow_redirects=args.follow, proxies=args.proxies,
                                       cookies=cookies, headers=headers)
            elif args.http_method == "POST":
                req = requests.post(url=new_url, data=body_data,
                                       timeout=int(args.timeout), allow_redirects=args.follow, proxies=args.proxies,
                                       cookies=cookies, headers=headers)
        except (socket.error, requests.ConnectTimeout):

            if args.ignore_errors == True:
                args.request_count += 1
                bar()
                continue

            if (retry_counter < args.retries):
                retry_counter += 1
                print(f" {bcolors.WARNING}// Retrying connection PAYLOAD[{payload}] retries[{retry_counter}] {bcolors.ENDC}")
                continue

            run_event.clear()
            show_error(f"Error stablishing connection  PAYLOAD[{payload}]", "fuzzing")
            

        retry_counter = 0

        # in case server didnt send back content length and server info            
        req.headers.setdefault("Content-Length", "UNK")
        req.headers.setdefault("Server",         "UNK")

        # using show filters
        if (args.ss_filter[0] != "None" or args.sc_filter[0] != "None" or args.sw_filter[0] != "None" or args.sr_filter != "None"):
            filters.sc = args.ss_filter
            filters.cl = args.sc_filter
            filters.ws = args.sw_filter
            filters.re = args.sr_filter

            if response_filter(filters, req) == True:
                output_string =  f"{bcolors.OKGREEN}PAYLOAD{bcolors.ENDC}[%-100s]"%(payload[:100]) + " "
                output_string += f"{bcolors.OKGREEN}SC{bcolors.ENDC}[%-3s]"%(req.status_code) + " "
                output_string += f"{bcolors.OKGREEN}CL{bcolors.ENDC}[%-10s]"%(req.headers["Content-Length"]) + " "
                output_string += f"{bcolors.OKGREEN}SERVER{bcolors.ENDC}[%-10s]"%(req.headers["Server"]) + " "
                print(output_string)

                # write output to a file (log) if specified
                if args.output != None:
                    args.output.write(output_string)
                    
                continue               
        
        # using hide filters
        if (args.hs_filter[0] != "None" or args.hc_filter[0] != "None" or args.hw_filter[0] != "None" or args.hr_filter != "None"):
            filters.sc = args.hs_filter
            filters.cl = args.hc_filter
            filters.ws = args.hw_filter
            filters.re = args.hr_filter
            
            if response_filter(filters, req) == False:
                output_string =  f"{bcolors.OKGREEN}PAYLOAD{bcolors.ENDC}[{bcolors.HEADER}%-100s{bcolors.ENDC}]"%(payload[:100]) + " "
                output_string += f"{bcolors.OKGREEN}SC{bcolors.ENDC}[%-3s]"%(req.status_code) + " "
                output_string += f"{bcolors.OKGREEN}CL{bcolors.ENDC}[%-10s]"%(req.headers["Content-Length"]) + " "
                output_string += f"{bcolors.OKGREEN}SERVER{bcolors.ENDC}[%-10s]"%(req.headers["Server"]) + " "
                print(output_string)

                # write output to a file (log) if specified
                if args.output != None:
                    args.output.write(output_string)
                    
                continue                               
        
        bar()
        args.request_count += 1

        # timewait 
        sleep(args.timewait)
        

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



def thread_starter(args):
    """this functions prepare and execute (start) every thread """

    # initializating global var run_event to stop threads when required
    global run_event
    run_event = threading.Event()
    run_event.set()
    
    # creating thread lists
    thread_list = []
    # thread[0] is a specific thread for progress bar
    thread_list.append(threading.Thread(target=prog_bar, args=[args]))  
    for thread in range(0, args.threads):
        thread_list.append(threading.Thread(target=fuzzing, args=[args]))

    # starting threads
    for i in range(len(thread_list)):
        thread_list[i].start()

        # giving thread[0] some time to set up progress bar global variables
        # in order to avoid calls to undefined variables from other threads
        if i == 0:
            sleep(0.1)

    exit_msg = ""
    try:
        # if a thread clean run_event variable, that means a error has happened
        # for that reason, all threads must stop and the program itself should stop too
        while run_event.is_set() and threading.active_count() > 1:
            sleep(1)
        
        exit_msg = "[!] program finished "
        exit_code = 0
        
    except KeyboardInterrupt:
        # to stop threads, run_event should be clear()
        run_event.clear()
            
        exit_msg = "[!] threads successfully closed \n"
        exit_msg += "[!] KeyboardInterrupt: Program finished by user..."
        exit_code = -1

    finally:
        # finishing threads
        for thread in thread_list:
            thread.join()

    print(exit_msg)    
    return exit_code


def main():
    banner()

    if ("--usage" in argv):
        usage()
    
    parsed_arguments = parse_arguments()
    
    validate_arguments(parsed_arguments)    

    #initial_checks(parsed_arguments)

    if (parsed_arguments.quiet == False):
        show_config(parsed_arguments)    

    return(thread_starter(parsed_arguments))


if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt:
        show_error("User Keyboard Interrupt", "main")


##  FUNCIONALIDADES PARA AGREGAR
#   - Basic Auth 
#   - Codificadores para los payloads
#   - agregar opcion para ignorar errores debido a que por ejemplo si se quiere realizar un fuzzing de subdominios,
#     nos dara error siempre

##  ERRORES O BUGS PARA CORREGIR
#   - refactorizar algunas funciones                                                                                                                                                                                                         
#   - Si no se especifica retries, al primer fallo, o error de conexion, el programa va a terminarse                                                                                                                                          
#   - al comparar el resultado con otras herramientas como gobuster, webFuzzer muestra resultados diferentes.                                                                                                                                
#   - mejorar un poco el output                                                                                                                                                                                                              
#   - cuando se va a realizar un FUZZing de cookies usando el metodo GET sin especificar la palabra FUZZ en la url                                                                                                                           
#     el prorama                                                                                                                                                                                                                             
#   - Si estoy haciendo un fuzzing de cookies o header... como m****a me doy cuenta que payload se esta usando...                                                                                                                             
#     debo encontrar una forma de mostrar los cookies cuando estoy haciendo un fuzzing de cookies y lo                                                                                                                                 
#     mismo con los headers.                                                                                                                                                                                                                 
#   - actualizar usage()
#   - si la ventana reduce su tamano, el formato de salida se va a estropear.