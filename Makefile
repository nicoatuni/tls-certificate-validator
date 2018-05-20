# COMP30023 Sem 1 2018 Assignment 2
# Nico Eka Dinata < n.dinata@student.unimelb.edu.au >
# @ndinata

CC	= gcc
CFLAGS	= -Wall -lssl -lcrypto

# > > > > > > > > > > > > > > > > > > > > > > > > > > > |
# REMOVE
I_FLAG	= -I/Users/nico/miniconda3/envs/util/include/
L_FLAG	= -L/Users/nico/miniconda3/envs/util/lib/ -rpath /Users/nico/miniconda3/envs/util/lib/
# > > > > > > > > > > > > > > > > > > > > > > > > > > > |

SRC	= certcheck.c
OBJ	= certcheck.o
EXE	= certcheck


$(EXE): $(OBJ)
	# > > > > > > > > > > > > > > > > > > > > > > > > |
	# REMOVE & UNCOMMENT BELOW
	$(CC) -o $(EXE) $(OBJ) $(CFLAGS) $(L_FLAG)
	# > > > > > > > > > > > > > > > > > > > > > > > > |
	# $(CC) -o $(EXE) $(0BJ) $(CFLAGS)


# > > > > > > > > > > > > > > > > > > > > > > > > > > |
# REMOVE
$(OBJ): $(SRC)
ifeq ($(DEBUG),1)
	$(CC) -c $(SRC) $(I_FLAG) -DDEBUG
else
	$(CC) -c $(SRC) $(I_FLAG)
endif
# > > > > > > > > > > > > > > > > > > > > > > > > > > |


clean:
	rm -f $(OBJ)


clobber: clean
	rm -f $(EXE)
	rm -f output.csv
