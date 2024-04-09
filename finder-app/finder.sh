#!/bin/bash

if [ $# -ne 2 ]; then
  echo "Need 2 arguments!"
  exit 1
fi

filesdir=$1
searchstr=$2

if [ ! -d "$filesdir" ] ; then
  echo "Directory does not exists!"
  exit 1
fi

files=`find "$filesdir" -type f | wc -l`
matching=`find "$filesdir" -type f | xargs grep -F "$searchstr" | wc -l`
echo "The number of files are $files and the number of matching lines are $matching"
