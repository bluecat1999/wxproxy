GCC=g++

INCLUDEDIR=  -I./include  -I/usr/include/lua5.1

LIBDIR=  -l crypto   		
#CPPFLAGS = -g3 -W -Wall -fPIC
#CPPFLAGS = -O3 -W -Wall -fPIC 
CPPFLAGS =  -O3 -Wall -pedantic -DNDEBUG -fPIC

all: clean wxutil.so install test

clean:
	rm -f *.o 
	rm -f wxutil.so

wxutil.so : wxutil.o tinyxml2.o
	$(GCC) -o   $@ -shared $^  $(LIBDIR) 

wxutil.o	: ./src/wxutil.cpp
	$(GCC) $(CPPFLAGS) -c $< -o $@ 	$(INCLUDEDIR)

tinyxml2.o: ./include/tinyxml2.cpp
	$(GCC) $(CPPFLAGS) -c $< -o $@ 	$(INCLUDEDIR)

install	: wxutil.so
	cp --force wxutil.so  ../../pkgs/lib/

test:
	valgrind -v --log-file=valgrind.log --tool=memcheck --leak-check=full --show-mismatched-frees=yes ./wxutil.so
