#!/bin/bash

rm -f test01.out
: > test01.out

echo "" >> test01.out
echo "***" >> test01.out
echo "list empty" >> test01.out
ls x:/ >> test01.out 2>&1
ls c:/mydrive/ >> test01.out 2>&1

echo "" >> test01.out
echo "***" >> test01.out
echo "create empty file 'touch x:/a'" >> test01.out
touch x:/a >> test01.out 2>&1

echo "" >> test01.out
echo "***" >> test01.out
echo "list with 1 file 'ls x:/'" >> test01.out
ls x:/ >> test01.out  2>&1
ls -R c:/mydrive/ >> test01.out  2>&1

echo "" >> test01.out
echo "***" >> test01.out
echo "removing files in x 'rm x:/*'" >> test01.out
rm x:/* >> test01.out 2>&1

echo "" >> test01.out
echo "***" >> test01.out
echo "list final empty" >> test01.out
ls x:/ >> test01.out  2>&1
ls -R c:/mydrive/ >> test01.out  2>&1

echo "" >> test01.out
echo "***" >> test01.out
echo "cleanup" >> test01.out
rm -rf c:/mydrive/*

