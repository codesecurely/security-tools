#!/usr/bin/python3

import sys
import argparse
import requests
import xml.etree.ElementTree as ET

def parse_xml_file(file):
        try:
                tree = ET.parse(file)
        except ET.ParseError as e:
                print ("Parse error({0}): {1}".format(e.errno, e.strerror))
                sys.exit(2)
        except IOError as e:
                print ("IO error({0}): {1}".format(e.errno, e.strerror))
                sys.exit(2)
        except:
                print ("Unexpected error:", sys.exc_info()[0])
                sys.exit(2)
        return tree

def get_ciphers_from_xml(root):
    ciphers = []
    for ssltest in root.findall('ssltest'):
        host = ssltest.get('host')
        port = ssltest.get('port')
        for c in ssltest.findall('cipher'):
            cipher = dict(id=c.get('id'), host=host, port=port, proto=c.get('sslversion'), cipher=c.get('cipher'))
            ciphers.append(cipher)
    return ciphers

def get_api_data():   
    with requests.get('https://ciphersuite.info/api/cs/') as response:
        data = response.json()
    strength_dict = {}
    for ciphersuite in data['ciphersuites']:
        for key, value in ciphersuite.items():
            id = value['hex_byte_1']+value['hex_byte_2'][2:4]
            strength_dict[id] = value['security']
    return strength_dict

def assess_ciphers(sslscan_xml, nosecure):
    strength_dict = get_api_data()
    services = {}
    for cipher in sslscan_xml:
        key = cipher['host']+':'+cipher['port']
        services[key] = []
    for cipher in sslscan_xml:
        services[cipher['host']+':'+cipher['port']].append([cipher['id'], cipher['proto'], cipher['cipher']])
    for service, ciphers in services.items():
        print(service)
        for c in ciphers:
            c.append(strength_dict[c[0]])
            if nosecure and (c[3] == "recommended" or c[3] == "secure"):
                continue;
            print(' '.join(c[1:3]))
        print()


def main(argv):
        parser = argparse.ArgumentParser(description="Parse sslscan XML output file and print results per host")
        parser.add_argument('--inputfile', required=True, help="sslscan XML file")
        parser.add_argument('--nosecure', default=False, action='store_true', help="(optional, False default) do not print secure cipher suites")
        args = parser.parse_args()
        
        inputfile=args.inputfile
        nosecure = args.nosecure

        sslscan_root = parse_xml_file(inputfile)
        ciphers = get_ciphers_from_xml(sslscan_root)
        assess_ciphers(ciphers, nosecure)


if __name__ == '__main__':
   main(sys.argv)
