#!/bin/bash
set -x
help() {
    echo -e "Usage:\n ./do_ssl_scans.sh MODE (--all, --sslscan, --testssl)\n\nneeds gnmap output in pwd to run\n\noutput in sslscan/ and testssl/ dirs"
}

#proper path for tools here
TESTSSL=testssl
SSLSCAN=~/tools/sslscan/sslscan

GNMAP=$(find . -maxdepth 1 -iname "*.gnmap")
if [[ -z "$GNMAP" ]]; then
    echo "[-] No gnmap files, exiting"
    exit 1
fi
if [[ $OSTYPE == darwin* ]]; then
	HEAD=ghead
else
	HEAD=head
fi

check_ciphers() {
    curl "https://ciphersuite.info/api/cs/" | jq '.ciphersuites[] | flatten | .[0] | [.openssl_name, .security] | join(" ")' | sed 's/"//g' > openssl_ciphers_strength.txt
    cat $1 | grep -E '"cipher.*_x' |  awk -F " {2,}" '{print $3}' | sed 's/"//g' | while read cipher || [[ -n $cipher ]];
    do
        grep -w "^$cipher" openssl_cipher_strength.txt >> $1.report.out
    done
 
}

run_sslscan() {
    if [ ! -d $(pwd)/sslscan ]; then
        mkdir sslscan
    fi
    for ssl in $(pwd)/*.ssl; do
        cat $ssl | while read line || [[ -n $line ]];
        do
            $SSLSCAN --no-colour $line > sslscan/$line.sslcan
            echo "[+] Done sslscan for $line"
        done
    done
    for file in sslscan/*; do
        if [[ ! -s $file ]]; then
        rm $file
        fi
    done
}

run_testssl() {
    if [ ! -d $(pwd)/testssl ]; then
        mkdir testssl
    fi
    for ssl in $(pwd)/*.ssl; do
        cat $ssl | while read line || [[ -n $line ]];
        do
            $TESTSSL --append --full -oA testssl/$line.testssl $line
            check_ciphers testssl/$line.testssl.csv
            echo "[+] Done testssl.sh for $line"
        done
    done
}

for gnmap in $(pwd)/*.gnmap; do
    cat $gnmap | awk '{for(i=1;i<=NF;i++){if ($i ~ /ssl/){print $2":"$i}}}' | awk -F "/" '{print $1}' > $(basename $gnmap).ssl
done

while [[ "$1" =~ ^- && ! "$1" == "--" ]]; do case $1 in
    -h | --help )
        help
        exit
    ;;
    -a | --all )
        run_sslscan
        run_testssl
        exit
    ;;
    --sslscan )
        run_sslscan
        exit
    ;;
    --testssl)
        run_testssl
        exit
    ;;
    *)
        echo "Error. Invalid option"
        help
        exit 1
    ;;
esac; shift; done
if [[ "$1" == '--' ]]; then shift; fi
