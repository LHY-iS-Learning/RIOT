#!/bin/bash
while [ True ]
do
 path=~/Desktop/RouterSend
 files=$(ls $path)
 for file in $files
 do
  filepath=$path/$file
  echo $filepath
  python generate_policy.py $filepath
  rm $path/$file
  mv output_pkl/* /var/www/html/monitored/
 done
done
