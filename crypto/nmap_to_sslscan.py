#!/usr/bin/python3

import sys
import subprocess
import os
import argparse
import requests
import json
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

def get_ssl_targets(root):
        ssl_targets = []
        for host in root.findall('host'):
            ip = host.find('address').get('addr')
            ports = host.find('ports')
            for port in ports.findall('port'):
                if port.find('state').get('state') == "open":
                    if port.find('service').get('tunnel') == "ssl":
                        ssl_targets.append(str(ip+':'+port.get('portid')))
        return ssl_targets


def get_sslscan_output_files(path, ext):
        sslscan_files = []
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.endswith(ext):
                    sslscan_files.append(file)
        return sslscan_files

def run_sslscan(targets, path, ext):
        for target in targets:
            subprocess.run(['sslscan', "--xml="+path+os.path.sep+target+"."+ext, target])

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

def print_results(sslscan_xml, nosecure, strength_dict):
    for file in sslscan_xml:
        sslscan_parsed = get_ciphers_from_xml(parse_xml_file(file).getroot())
        if sslscan_parsed[0]['host'] and sslscan_parsed[0]['port']:
            print(sslscan_parsed[0]['host']+":"+sslscan_parsed[0]['port'])
        for ciphersuite in sslscan_parsed:
            if nosecure:
                if strength_dict[ciphersuite['id']] == "secure" or strength_dict[ciphersuite['id']] == "recommended":
                    continue
            print(ciphersuite['proto'], ciphersuite['cipher'], strength_dict[ciphersuite['id']])
        print()

def main(argv):
        parser = argparse.ArgumentParser(description="Run sslscan based on nmap results and assess cipher suites strength")
        parser.add_argument('--inputfile', required=True, help="nmap XML file - scan needs to be run with -sV flag")
        parser.add_argument('--nosecure', default=False, action='store_true', help="(optional, False default) do not print secure cipher suites")
        parser.add_argument('--noscan', default=False, action='store_true', help="(optional, False default) do not run sslscan, just parse sslscan output")
        parser.add_argument('--nmaponly', default=False, action='store_true', help="(optional, False default) do not run sslscan, just parse nmap file and print targets")
        parser.add_argument('--ext', default='sslscan.xml', help="(optional, sslscan.xml default) extension for sslscan output files, useful if you have own sslscan files")
        parser.add_argument('--output', default=os.getcwd(), help="(optional, cwd default) path to resulting XML files from sslscan")
        parser.add_argument('--reportfile', help="(optional) path to report file for all parsed hosts")
        args = parser.parse_args()
        
        inputfile=args.inputfile
        output=args.output
        nosecure = args.nosecure
        noscan = args.noscan
        ext = args.ext
        reportfile = args.reportfile
        nmaponly = args.nmaponly
        
        if not os.path.exists(output):
            os.mkdir(output)

        nmap_root = parse_xml_file(inputfile).getroot()
        sslscan_targets = get_ssl_targets(nmap_root)
        
        if nmaponly:
            for target in sslscan_targets:
                print(target)
            sys.exit(0)

        if not noscan:
            run_sslscan(sslscan_targets, output, ext)
        sslscan_xml = get_sslscan_output_files(output, ext)
        strength_dict = get_api_data()

        
        print_results(sslscan_xml, nosecure, strength_dict)
        
        if reportfile:
            original_stdout = sys.stdout
            with open(reportfile, 'w') as f:
                sys.stdout = f 
                print_results(sslscan_xml, nosecure, strength_dict)
                sys.stdout = original_stdout


if __name__ == '__main__':
   main(sys.argv)
