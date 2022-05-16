#!/usr/bin/python3

import sys
import subprocess
import os
import argparse
import shutil

# apt install amass massdns
# go install -v github.com/s0md3v/smap/cmd/smap@latest
# set $PATH for go binaries


def run_amass(target):
    subprocess.run([
        'amass',
        'enum',
        '-passive',
        '-d', target,
        '-o', 'amass-'+target+'.txt'])


def run_massdns(target, resolvers):
    subprocess.run([
        'massdns',
        '-q',
        '-r', resolvers,
        '-t', 'A',
        '-o', 'S',
        '-w', 'massdns-'+target+'.txt',
        'amass-'+target+'.txt'])


def find_A_records(file, target):
    ips = []
    with open(file, 'r') as resolved:
        for line in resolved:
            if "A" in line.split():
                ips.append(line.split()[2])
    with open('resolved-'+target+'.txt', 'w') as A_records:
        for ip in ips:
            A_records.write(ip)
            A_records.write('\n')


def run_smap(target, targets):
    subprocess.run([
        'smap',
        '-sV',
        '-iL', targets,
        '-oA', 'smap-'+target])


def check_dependencies():
    if shutil.which('amass') is None:
        print('Install amass "apt install amass"')
        exit(1)
    if shutil.which('massdns') is None:
        print('Install massdns "apt install massdns"')
        exit(1)
    if shutil.which('smap') is None:
        print('Install smap "go install -v github.com/s0md3v/smap/cmd/smap@latest"')
        exit(1)


def main(argv):
    parser = argparse.ArgumentParser(
        description="Perform basic recon using only passive techniques\ntools: amass, massdns, smap")
    parser.add_argument('--domain', required=True, help="domain for amass, example.com")
    parser.add_argument('--resolvers', required=True, help="a file with resolvers in each line for massdns")
    args = parser.parse_args()

    check_dependencies()

    if not os.path.isfile('amass-'+args.domain+'.txt'):
        run_amass(args.domain)
    if not os.path.isfile('massdns-'+args.domain+'.txt'):
        run_massdns(args.domain, args.resolvers)
    if os.path.isfile('massdns-'+args.domain+'.txt'):
        find_A_records('massdns-'+args.domain+'.txt', args.domain)
    if os.path.isfile('resolved-'+args.domain+'.txt'):
        run_smap(args.domain, 'resolved-'+args.domain+'.txt')


if __name__ == '__main__':
    main(sys.argv)
