#!/usr/bin/python3

import argparse 
import requests

def banner():
    print("[ BANNER ]")

def parse_arguments():
    parser = argparse.ArgumentParser(prog="./webFuzzer.py",
                                     description="a simple web fuzzer")
    parser.add_argument("-X", choices=["GET", "POST"], default="GET",
                        help="specify an HTTP for the request method")
    timing = parser.add_group()
    timing.add_argument("-t", "--threads",  help="specify threads")
    parser.add_argument("target")

    parsed_args = parser.parse_args()
    return parsed_args


def fuzzing_GET(url, wordlist:list):
    print("-----------------------------------------------------------------------------------")
    print("|%-40s|\t%-3s|\t%-10s|\t%-10s|"%(" Uniform Resource Locator [URL]", "S_C", "ContentLen", "WebServer "))
    print("|%-40s|%-9s|%-14s|%-15s|"%('-'*40, '-'*9, '-'*14, '-'*15))

    for word in wordlist:
        new_url = url.replace("^FUZZ^", word)
        req = requests.request("GET", new_url)
        
        req.headers.setdefault("Content-Length", "UNK")
        req.headers.setdefault("Server",         "UNK")


        content_len = req.headers["Content-Length"]
        server      = req.headers["Server"]

        print("|%-40s|\t%-3s|\t%-10s|\t%-10s|"%(new_url, req.status_code, content_len, server))
        
    print("-----------------------------------------------------------------------------------")

"""
def fuzzing_POST(url:str, body:dict, wordlist:list):
    for word in wordlist:
        for value in body.keys():
            new_body[value] = body[value].replace("^FUZZ^", word)
            req = requests.post(url, new_body)
            
            req.headers.setdefault("Content-Length", "UNK")
            req.headers.setdefault("Server",         "UNK")

            content_len = req.headers["Content-Length"]
            server      = req.headers["Server"]
            
            print("|%-40s|\t|%-50s|\t%-3s|\t%-10s|\t%-10s|"%(new_url, ,req.status_code, content_len, server))            
            
            print("%-30s\t%-3s\t%-10s\t%-10s"%(url, req.status_code, content_len, server))
"""    
        

def main():
    banner()
    #parsed_arguments = parse_arguments()
    #print(parsed_arguments)

    fuzzing_GET("http://192.168.0.1/?d=^FUZZ^", ["index.html", "testing", "robots.txt", "humans.txt", "security.txt"])
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
        print("[!] Keyboard interrupt :: FInishing the program ")
        exit(0)
    
