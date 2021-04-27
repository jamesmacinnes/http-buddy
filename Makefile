#
# Makefile
#
IDIR =./
CC=gcc
CFLAGS=-I$(IDIR) -Wall -g

ODIR=./
LDIR =./

LIBS=-lpthread

_OBJ = http-buddy.o 
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

http-buddy: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ 
	
