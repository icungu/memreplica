all: 
	$(CC) -g -O2 -Wall memreplica.c -o memreplica -lpcap
	
clean:
	rm -f memreplica
	
