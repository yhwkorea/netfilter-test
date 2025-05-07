all: netfilter-test

netfilter-test: main.o
	g++ -o netfilter-test main.o -lnetfilter_queue

main.o: main.cpp
	g++ -c main.cpp

clean:
	rm -f netfilter-test main.o

