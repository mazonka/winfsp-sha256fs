#!/bin/bash

out=test02.out

rm -f $out
: > $out

echo "" >> $out
echo "***" >> $out
echo "list empty" >> $out
ls x:/ >> $out 2>&1
ls c:/mydrive/ >> $out 2>&1

echo "" >> $out
echo "***" >> $out
echo "create 2 files abc" >> $out
echo -n abc > x:/abc
cp x:/abc x:/abc2 >> $out  2>&1

echo "" >> $out
echo "***" >> $out
echo "list files 'ls x:/'" >> $out
ls x:/ >> $out  2>&1
ls -R c:/mydrive/ >> $out  2>&1

echo "" >> $out
echo "***" >> $out
echo "cat refs" >> $out
cat c:/mydrive/_sha256/ba/ba78/*.refs >> $out

echo "" >> $out
echo "***" >> $out
echo "removing files in x 'rm x:/*'" >> $out
rm x:/* >> $out 2>&1

echo "" >> $out
echo "***" >> $out
echo "list final empty" >> $out
ls x:/ >> $out  2>&1
ls -R c:/mydrive/ >> $out  2>&1

echo "" >> $out
echo "***" >> $out
echo "cleanup" >> $out
rm -rf c:/mydrive/*

