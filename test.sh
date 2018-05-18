mv certcheck.c sample/
mv Makefile sample/
cd sample/
make
./certcheck sample_input.csv
make clean
rm certcheck
mv Makefile ../
mv certcheck.c ../
mv output.csv ../
cd ../
cat output.csv
rm output.csv