# COMP30023 Sem 1 2018 Assignment 2
# Nico Eka Dinata < n.dinata@student.unimelb.edu.au >
# @ndinata

CC	= gcc
CFLAGS	= -Wall -lssl -lcrypto

# > > > > > > > > > > > > > > > > > > > > > > > > > > > |
# REMOVE THESE BEFORE SUBMISSION
I_FLAG	= -I/Users/nico/miniconda3/envs/util/include/
L_FLAG	= -L/Users/nico/miniconda3/envs/util/lib/
# > > > > > > > > > > > > > > > > > > > > > > > > > > > |

SRC	= certcheck.c
OBJ	= certcheck.o
EXE	= certcheck


all: $(EXE)


$(EXE): $(OBJ)
	# > > > > > > > > > > > > > > > > > > > > > > > > |
	# REMOVE THIS AND UNCOMMENT THE ONE BELOW IT
	$(CC) -o $(EXE) $(CFLAGS) $(L_FLAG) $(OBJ)
	# > > > > > > > > > > > > > > > > > > > > > > > > |
	# $(CC) -o $(EXE) $(0BJ) $(CFLAGS)


$(OBJ): $(SRC)
	$(CC) -c $(SRC) $(I_FLAG)


clean:
	rm -f $(OBJ)


clobber: clean
	rm $(EXE)
	rm -f output.csv
