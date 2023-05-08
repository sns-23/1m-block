CC = gcc
CFLAGS = -g -Wall
LDFLAGS = -lnetfilter_queue -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -lglib-2.0
OBJS = main.o util.o
TARGET = 1m-block

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(CFLAGS) $(LDFLAGS)

main.o: libnet-headers.h util.h
	$(CC) -c -o $@ main.c $(CFLAGS) $(LDFLAGS)

util.o: util.h
	$(CC) -c -o $@ util.c $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf $(TARGET) *.o

.PHONY:
	$(TARGET) $(OBJS) clean