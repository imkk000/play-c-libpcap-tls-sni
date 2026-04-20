.PHONY: compile run start

run: compile start

start:
	sudo ./server

compile:
	gcc -Wall -o server sniffer.c -lpcap
