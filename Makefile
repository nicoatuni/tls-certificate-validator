# COMP30023 Sem 1 2018 Assignment 2
# Nico Eka Dinata < n.dinata@student.unimelb.edu.au >
# @ndinata

CC	= gcc
CFLAGS	= -Wall -lssl -lcrypto

# > > > > > > > > > > > > > > > > > > > > > > > > > > > |
# REMOVE
I_FLAG	= -I/Users/nico/miniconda3/envs/util/include/
L_FLAG	= -L/Users/nico/miniconda3/envs/util/lib/
# > > > > > > > > > > > > > > > > > > > > > > > > > > > |

SRC	= certcheck.c
OBJ	= certcheck.o
EXE	= certcheck


all: $(EXE)


$(EXE): $(OBJ)
	# > > > > > > > > > > > > > > > > > > > > > > > > |
	# REMOVE & UNCOMMENT BELOW
	$(CC) -o $(EXE) $(CFLAGS) $(L_FLAG) $(OBJ)
	# > > > > > > > > > > > > > > > > > > > > > > > > |
	# $(CC) -o $(EXE) $(CFLAGS) $(0BJ)


$(OBJ): $(SRC)
# > > > > > > > > > > > > > > > > > > > > > > > > > > |
ifeq ($(DEBUG),1)
	$(CC) -c $(SRC) $(I_FLAG) -DDEBUG
else
	$(CC) -c $(SRC) $(I_FLAG)
	# $(CC) -c $(SRC)				# ONLY KEEP THIS
endif
# > > > > > > > > > > > > > > > > > > > > > > > > > > |

clean:
	rm -f $(OBJ)


clobber: clean
	rm $(EXE)
	rm -f output.csv
