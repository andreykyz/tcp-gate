all: client server

client: server
	gcc client.c -o client -g

server:
	gcc server.c -o server -g

clean:
	rm client server
