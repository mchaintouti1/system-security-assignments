# Compiler and flags
CC = gcc
CFLAGS = -Wall -O2

# Output executable name
TARGET = ecdh_assign_1

# Required libraries
LIBSODIUM = -lsodium

# Source files
SRCS = ecdh_assign_1.c 

# Object files
OBJS = $(SRCS:.c=.o)

# Default target to build the executable
all: $(TARGET)

# Rule to compile the executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LIBSODIUM)

# Clean up 
clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean