# COMP30023 Sem 1 2018 Assignment 2
# Nico Eka Dinata < n.dinata@student.unimelb.edu.au >
# @ndinata

CC	= gcc
CFLAGS	= -lssl -lcrypto

SRC	= certcheck.c
OBJ	= certcheck.o
EXE	= certcheck


$(EXE):
	$(CC) -o $(EXE) $(SRC) $(CFLAGS)


clean:
	rm -f $(OBJ)


clobber: clean
	rm -f $(EXE)
	rm -f output.csv
