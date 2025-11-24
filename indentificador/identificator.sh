#!/bin/bash

RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
MAGENTA='\e[35m'
CYAN='\e[36m'
WHITE='\e[37m'
RESET='\e[0m'

url=$1

if [ -z "$1" ]; then
    echo -n "URL: "
    read -r url
fi

whois $url >whois.txt
grep -o -E '\w+@\w+\.\w{1,5}' whois.txt >emails.txt # obtener correos

if [ -s "emails.txt" ]; then # sacar los correos con leaks
    while IFS= read -r linea; do
        api_response=$(curl -s "https://api.xposedornot.com/v1/check-email/${linea}") # acceso a api

        if [[ $api_response =~ \"status\":\"success\" ]]; then
            email=$(echo "$api_response" | sed -E 's/.*\"email\":\"(\w+@\w+\.\w{1,3})\".*/\1/')
            breaches=$(echo "$api_response" | sed -E 's/.*\"breaches\":\[\[(.+)\]\].*/\1/; s/"//g; s/,/, /g')

            echo -e "\n${YELLOW}email:${RESET} $email"
            echo -e "${RED}breaches:${RESET} $breaches"
        fi
    done <"emails.txt"
fi

domain_status=$(grep -m 1 -o -E 'Domain Status: +\w+' whois.txt | cut -d ' ' -f 3) # comprobar estado del dominio
echo -e -n "\n${YELLOW}Domain Status: "
if [ $domain_status == "ok" ]; then
    echo -e -n ${GREEN}
else
    echo -e -n ${RED}
fi
echo -e "${domain_status}${RESET}" # muestra el estado de con un color específico

ns=$(grep -o -E "Name Server: +\S+" whois.txt | sed 's/Name Server: //') # sacar los ns
if [ -n "$ns" ]; then
    echo -e "\n${YELLOW}Name Server:\n${RESET}$ns"
fi

nmap -T5 -p 21,22,23,25,53,80,110,143,443,3389 $url >nmap.txt # nmap de los 10 puertos más usados

echo -e "\n${YELLOW}PORT     STATE    SERVICE${RESET}" # mostrar los puertos abiertos
grep open nmap.txt

# borrar los ficheros temporales que contenían la info
rm emails.txt
rm nmap.txt
rm whois.txt
