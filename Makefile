.PHONY: compile run

run: compile
	./server

compile:
	gcc -Wall -o server sniffer.c -lpcap
