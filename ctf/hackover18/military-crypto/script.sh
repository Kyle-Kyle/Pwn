#!/bin/bash
set -eu

SELF=$(pwd)/$0
DIR=$(mktemp -d)
cd "$DIR"

cp -r /home/ctf/.gnupg .
export GNUPGHOME="${DIR}/.gnupg"
chmod o-rx .gnupg

menu() {
cat <<EOF
====================================================
    == secure update service

    we didn't roll our own, powered by the
    best crypto known to humanity
====================================================
EOF
    PS3="> "
    opts=("Update firmware" "Download firmware" "Current firmware" "Quit")
    select opt in "${opts[@]}"; do
    case "${REPLY}" in
        1 ) update_firmware; break;;
        2 ) download_firmware; break;;
        3 ) current_firmware; break;;
        4 ) echo "EOF!"; exit 0;;
        *) echo "Unknown option"; continue;;
    esac; done
}

update_firmware() {
   cat <<EOF
====================================================
    1) send update binary as base64
    2) finish with an empty line
    3) send detached signature as base64
    4) finish with an empty line
====================================================
EOF
   echo 'Reading firmware...'
   touch update.bin.b64
   while IFS='' read -r firmware; do
       if [ -z "$firmware" ]; then break; fi
       echo "$firmware" >> update.bin.b64
   done
   base64 -d update.bin.b64 > update.bin
   rm update.bin.b64

   echo 'Reading detatched signaure...'
   touch update.bin.sig
   while IFS='' read -r signature; do
       if [ -z "$signature" ]; then break; fi
       echo "$signature" >> update.bin.sig.b64
   done
   base64 -d update.bin.sig.b64 > update.bin.sig
   rm update.bin.sig.b64

   if ! gpg --verify update.bin.sig; then
       set +x
       echo '!!!!!!!!!!!!!!!!!!!!!!!'
       echo '!! INVALID SIGNATURE !!'
       echo '!!!!!!!!!!!!!!!!!!!!!!!'
       exit 1
   else
       chmod +x update.bin
       echo 'Updating....'
       ./update.bin
       echo 'Rebooting....'
       exit 0
   fi
}

download_firmware() {
    echo "Firmware:"
    cat "${SELF}"|base64|tr -d '\n'
    echo
    echo "Signature:"
    cat "${SELF}.sig"|base64|tr -d '\n'
    echo
}

current_firmware() {
cat <<EOF
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Version: 1.0
Created: 2018-10-03
Audited: KRYPTOCHEF

-----BEGIN PGP SIGNATURE-----

iQIzBAEBCAAdFiEEwSuuOHnM9KfOOGG3QoUB03HVrd8FAlu2ra4ACgkQQoUB03HV
rd9kow//b/uQQonqD02g7VXMBYIUcCljLsGaOgvdEXSA6r6y5iym4DVLrDuZrIHP
ryAV30SJkm6gaxjcA19zYBg79tqcolhJPq4Tsd8bCOBEWG31Gk1LN7mzJbCk5TMO
ylf02qYbgpCULPkNxH87s4S8Oo7z0buR50jWAbe28fPkqyF0AG4iConSeIhKtMYB
LNFIdxXm3u99su5BATf13jSGrIIg+iO8aT7xrohOyaY75FlvsB6DBeDLTwf/9z//
SKVixZVKuoh+b4hevECqmwRB3t/NvyIbHz8e70WHXhWg6CXJMMz41YZylGhwNeDF
I3sHjIJ1wx4FDzH1WSlVcrYSOP4UZacgPzwxjMehvnUW2IGFXRiwsh1z21HI8Nlx
N0YZ5b+uwpj75AmP4mNDYvoGHHk1+fqna4a39y2t7qQEWMkEq2YQiuDQjCGAprC+
Q++8HAtODf566z2pB1h8dsdvOWDzzfMS8z3RC6LFydMEiRzVi7sL0tawY60JPBxH
DX2D6njzPi5XjRCNJiGqrK2qsL2aNxDn7zBQExvEUmgLsSR574YUILLa0xsMhMTA
Zn3ht/Rx7yxZJoN8FM0UvajbFdcDmgj2iullEq3aIpmQChoVnb/yygpCq0353UtY
OWZKfxCcH9mQSbcQCjDUFgr91nTXehMQ6d64bSbLxgZuqWwPoy4=
=IbNc
-----END PGP SIGNATURE-----
EOF
}

while true; do
    menu
done
