# Makefile
CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread
TARGET = server

all: $(TARGET)

$(TARGET): server.c
	$(CC) $(CFLAGS) -o $(TARGET) server.c

clean:
	rm -f $(TARGET)
