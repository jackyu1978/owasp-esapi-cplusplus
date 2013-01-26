#!/bin/bash

# If you get "Bad Interpreter" or "Operation not Permitted" on Mac OS X,
# try the following:
# xattr -d com.apple.quarantine scriptname.sh

for file in ./*.html; do
       sed -i -e "s|esapi::||g" $file
done