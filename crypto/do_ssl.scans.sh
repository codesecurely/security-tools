#!/bin/bash
help() {
	echo -e "Usage:\n ./do_ssl_scans.sh MODE (--all, --sslscan, --testssl, --target, --clean)\n\n --all, --sslscan, --testssl need gnmap output in pwd to run\n\n --target need ip:port or domain:port (omit port for default 443)\n eg. ./do_ssl_scans.sh --target google.pl\n\n output in sslscan/ and testssl/ dirs, run --clean to clear previous scans"
}

#proper path for tools here
TESTSSL=testssl
SSLSCAN=~/tools/sslscan/sslscan
WORKDIR=~/code/security-tools/crypto

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
    if [ ! -s "$WORKDIR/openssl_cipher_strength.txt" ]; then
		update
	fi
	cat $1 | grep -E '"cipher.*_x' |  awk -F " {2,}" '{print $3}' | sed 's/"//g' | while read cipher || [[ -n $cipher ]];
    do
        grep -w "^$cipher" $WORKDIR/openssl_cipher_strength.txt >> $1.out
    done
	cat $1.out | sort -u | sort -k2 > $1.report.out
}

update() {
	curl "https://ciphersuite.info/api/cs/" | jq '.ciphersuites[] | flatten | .[0] | [.openssl_name, .security] | join(" ")' | sed 's/"//g' > $WORKDIR/openssl_cipher_strength.txt
}

run_target() {
	echo $1 > $(pwd)/$1.ssl
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

parse_nmap() {
	for gnmap in $(pwd)/*.gnmap; do
	    cat $gnmap | awk '{for(i=1;i<=NF;i++){if ($i ~ /ssl/){print $2":"$i}}}' | awk -F "/" '{print $1}' > $(basename $gnmap).ssl
	done
}
while [[ "$1" =~ ^- && ! "$1" == "--" ]]; do case $1 in
    -h | --help )
        help
        exit
    ;;
    -a | --all )
		parse_nmap
        run_sslscan
        run_testssl
        exit
    ;;
    --sslscan )
		parse_nmap
        run_sslscan
        exit
    ;;
    --testssl)
		parse_nmap
        run_testssl
        exit
	;;
	--target)
		run_target $2
		run_sslscan
		run_testssl
		exit
	;;
	--clean)
		rm -rf testssl/ sslscan/
		exit
    ;;
    *)
        echo "Error. Invalid option"
        help
        exit 1
    ;;
esac; shift; done
if [[ "$1" == '--' ]]; then shift; fi
