mv certcheck.c sample/
mv Makefile sample/
cd sample/
if [ "$1" == 1 ]; then
	make DEBUG=1
else
	make
fi
./certcheck sample_input.csv
make clean
rm certcheck
mv Makefile ../
mv certcheck.c ../
mv output.csv ../
cd ../
cat output.csv
rm output.csv
