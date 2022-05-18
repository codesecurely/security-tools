#!/usr/bin/python3

import sys
import subprocess
import os
import argparse
import shutil

# apt install amass massdns
# go install -v github.com/s0md3v/smap/cmd/smap@latest
# set $PATH for go binaries


def run_amass(target, output):
    subprocess.run([
        'amass',
        'enum',
        '-passive',
        '-d', target,
        '-o', os.path.join(output, 'amass-'+target+'.txt')])


def run_massdns(target, resolvers, output):
    print(output)
    subprocess.run([
        'massdns',
        '-q',
        '-r', os.path.join(output, resolvers),
        '-t', 'A',
        '-o', 'S',
        '-w', os.path.join(output, 'massdns-'+target+'.txt'),
        os.path.join(output, 'amass-'+target+'.txt')])


def find_A_records(file, target, output):
    ips = set()  # we only want unique ips
    with open(file, 'r') as resolved:
        for line in resolved:
            if "A" in line.split():
                ips.add(line.split()[2])
    with open(os.path.join(output, 'resolved-'+target+'.txt'), 'w') as A_records:
        for ip in ips:
            A_records.write(ip+'\n')


def run_smap(target, targets, output):
    subprocess.run([
        'smap',
        '-sV',
        '-iL', targets,
        '-oA', os.path.join(output, 'smap-'+target)])


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


def prepare_resolvers(output):
    with open(os.path.join(output, 'resolvers.txt'), 'w') as resolvers:
        resolvers.write('1.0.0.1'+'\n')
        resolvers.write('8.8.8.8'+'\n')
        resolvers.write('208.67.220.222'+'\n')
        resolvers.write('198.82.247.34'+'\n')


def main(argv):
    parser = argparse.ArgumentParser(
        description="Perform basic recon using only passive techniques, tools: amass, massdns, smap")
    parser.add_argument('--domain', required=True,
                        help="domain for amass, example.com")
    parser.add_argument('--resolvers', required=False,
                        help="a file with resolvers in each line for massdns, optional")
    parser.add_argument('--output', required=False,
                        help="directory to save results, domain name as dirname otherwise, optional")
    args = parser.parse_args()

    check_dependencies()

    output = args.domain

    if args.output:
        output = args.output

    if output and not os.path.isdir(output):
        os.makedirs(output, exist_ok=True)

    resolvers = args.resolvers

    if not args.resolvers:
        prepare_resolvers(output)
        resolvers = 'resolvers.txt'

    print(os.path.join(output, resolvers))

    if not os.path.isfile(os.path.join(output, 'amass-'+args.domain+'.txt')):
        run_amass(args.domain, output)
    if not os.path.isfile(os.path.join(output, 'massdns-'+args.domain+'.txt')):
        run_massdns(args.domain, resolvers, output)
    if os.path.isfile(os.path.join(output, 'massdns-'+args.domain+'.txt')):
        find_A_records(os.path.join(output, 'massdns-' +
                       args.domain+'.txt'), args.domain, output)
    if os.path.isfile(os.path.join(output, 'resolved-'+args.domain+'.txt')):
        run_smap(args.domain, os.path.join(
            output, 'resolved-'+args.domain+'.txt'), output)


if __name__ == '__main__':
    main(sys.argv)
