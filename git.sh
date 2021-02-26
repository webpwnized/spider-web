#!/bin/bash

if (( $# != 1 ))
then
    printf "%b" "Usage: git.sh <version>\n" >&2
    exit 1
fi

sudo git tag -a $1 -m $1
sudo git commit -a -m $1
sudo git push --tag
sudo git push
