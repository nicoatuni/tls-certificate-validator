if [ "$1" == 1 ]; then
	make DEBUG=1
else
	make
fi
mv certcheck sample/
cd sample
./certcheck sample_input.csv
cat output.csv
./testscript.sh
rm output.csv
rm certcheck
cd ../
make clean
