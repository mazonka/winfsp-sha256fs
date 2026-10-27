#!/bin/bash

out=test03.out
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
mkdir x:/aaa
cp x:/abc x:/aaa/abc >> $out  2>&1

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
echo "removing files" >> $out
rm x:/abc >> $out 2>&1
rm -rf x:/aaa >> $out 2>&1

echo "" >> $out
echo "***" >> $out
echo "list final empty" >> $out
ls x:/ >> $out  2>&1
ls -R c:/mydrive/ >> $out  2>&1

echo "" >> $out
echo "***" >> $out
echo "cleanup" >> $out
rm -rf c:/mydrive/*

