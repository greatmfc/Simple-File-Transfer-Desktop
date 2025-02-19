CXX = g++

STDVER = -std=c++20

DEBUGFLAGS = -g -DDEBUG

WARMFLAGS = -Wall -Wextra -Wpointer-arith -Wnon-virtual-dtor

OPTFLAGS = -fno-rtti -O3 -march=native -static

object = main.cpp

output = sft_host.out

LIB = -lstdc++ -Iinclude

.PHONY: clean

sft_host: $(object)
	$(CXX) $(STDVER) $(WARMFLAGS) $(object) $(LIB) -o $(output) $(OPTFLAGS)

test: $(object)
	$(CXX) $(STDVER) $(WARMFLAGS) $(object) $(LIB) -o sfttest.out $(DEBUGFLAGS) -static

install: $(output)
	install -m 755 $(output) /usr/bin/

clean:
	rm -f sft_host.out test.out
