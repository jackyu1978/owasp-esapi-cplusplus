#!/bin/bash

# If you get Operation not permitted on Mac OS X, try the following:
# xattr -d com.apple.quarantine scriptname.sh

for file in ./*.html; do
       sed -i -e "s|esapi::||g" $file
done