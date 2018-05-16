# COMP30023 Sem 1 2018 Assignment 2
# Nico Eka Dinata < n.dinata@student.unimelb.edu.au >
# @ndinata

CC	= gcc
CFLAGS = -lssl -lcrypto

SRC	= certcheck.c
OBJ	= certcheck.o
EXE = certcheck

# Creating the executable
$(EXE): $(OBJ)
	$(CC) -o $(EXE) $(OBJ) $(CFLAGS)

clean:
	rm -f $(OBJ)

clobber: clean
	rm $(EXE)
