import argparse
import configparser
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse
from PIL import Image
import codecs
import mmh3
from shodan import Shodan
 
#search favicon according to 
#https://www.w3.org/2005/10/howto-favicon
#https://en.wikipedia.org/wiki/Favicon


parser = argparse.ArgumentParser(prog='faviconfrenzy', description='Search for the provided URL FavIcon, calculate the hash and send it to Shodan for analisys.')

parser.add_argument('-u', '--url',  type=str, nargs='?', help='URL to search for the FavIcon.', required=True )
parser.add_argument('-ak', '--addshodankey', dest='shodankey', type=str, nargs='?', help='Store or replace the Shodan key in config file.')
parser.add_argument('-t', '--topresults', type=int, nargs='?', default=10, help='Max numer of results to show, default is 10.')

parametros = parser.parse_args()

#load config file
config = configparser.ConfigParser()
config.read('faviconfrenzy.ini')


#load it and use it

if(parametros.shodankey):
    config['SHODAN'] = {'key':parametros.shodankey}
    with open('faviconfrenzy.ini', 'w') as configfile:
        config.write(configfile)
        print('\n[!] Shodan Key Stored succesfully')

if not(parametros.url):
    parser.print_help()
    print('\n[!] Shodan Key Stored succesfully')
    exit(0)

if not(config.has_option(section='SHODAN',option='key')): # and no shodan key in config
    print('\n[!] No Shodan Key provided nor stored')
    print('[!] whe are just gonna find the hash \n')
else:
    shodanKey = config['SHODAN']['key']

url = parametros.url 

headers = {
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0',
    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language':'es-CL,en-US;q=0.7,en;q=0.3',
    'Accept-Encoding':'gzip, deflate, br',
    'Connection':'keep-alive',
    'Upgrade-Insecure-Requests':'1'
}
def getfaviconhash(url):
    try:
        response = requests.get(url)
        favicon = codecs.encode(response.content,'base64')
        hash = mmh3.hash(favicon)
    except Exception as ex:
        print('getfaviconhash Error:', str(ex))
        hash = None
    return hash

def getFavIconPath(url):
    absoluteIconPath=None
    try:
        print('[!] Trying to get favicon from Header Link in HTML')
        page = requests.get(url=url, headers=headers)
        if page.status_code == 200:
            soup = BeautifulSoup(page.content, 'html.parser')
            link = soup.find('link',rel='icon')
            if (link):
                absoluteIconPath = urljoin(url, link['href'])
            else:
                print('[!] No icon link in HTML')
                print('[!] Trying to get favicon from root path ')
                u = urlparse(url)
                u = u._replace(path = 'favicon.ico')
                url = urlunparse(u)
                page = requests.get(url=url, headers=headers)
                if page.status_code == 200:
                    absoluteIconPath = url
                else:
                    print('[!] No favicon in root path')
                    print('[!] Trying to get favicon from /html_public/favicon.ico ')
                    u = urlparse(url)
                    u = u._replace(path = 'html_public/favicon.ico')
                    url = urlunparse(u)
                    page = requests.get(url=url, headers=headers)
                    if page.status_code == 200:
                        absoluteIconPath = url
                    else:
                        print('[!] No favicon in /html_public/favicon.ico')
    except Exception as ex:
        print('[!] getFavIconPath Error:', str(ex))
        absoluteIconPath = None
    return (absoluteIconPath)

def shodanQuery(hash, shodanKey):
    api = Shodan(shodanKey)
    if hash:
        query = 'http.favicon.hash:{}'.format(hash)
        count = api.count(query)['total']
        if count == 0:
            print('[!] No Shodan result')
        else:
            print(f'\n[+]Retrieving {parametros.topresults} results from {count} findings.')
            try:
                for count,hosts in enumerate(api.search_cursor(query), start=1):
                    print(f'\n  [{count}] Title: ', hosts['http']['title'])
                    print('     [+] Host   : ', hosts['http']['host'])
                    print('     [+] Ip     : ', hosts['ip_str'])
                    print('     [+] Isp    : ', hosts['isp'])
                    print('     [+] Port   : ', str(hosts['port']))
                    print('     [+] Org    : ', hosts['org'])
                    print('     [+] Domains: ', hosts['domains'])
                    if(len(hosts['http']['components'])>0):
                        print('     [+] Components :') 
                    for component in hosts['http']['components']:
                        print('       [+]' , component)
                    if (count >= parametros.topresults):
                        break
            except Exception as ex:
                print('[!] Shodan Error:', str(ex))
    else:
        print('[!] No icon found.')

print('\n[+] url:', url)
absoluteIconPath = getFavIconPath(url=url)
print('[+] FavIconPath:', absoluteIconPath)

if(absoluteIconPath):
    hash = getfaviconhash(absoluteIconPath)
    if(hash):
        print('[+] hash:', hash)
        if not(config.has_option(section='SHODAN',option='key')):
            print('[!] No Shodan Api key')
            print('[+] For manual search go to this URL: https://www.shodan.io/search?query=http.favicon.hash%3A',hash, sep='')
            exit()
        else:
            shodanQuery(hash, shodanKey)
else:
    print('[!] No favicon found, Sorry!')
