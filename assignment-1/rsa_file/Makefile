# Compiler and flags
CC = gcc
CFLAGS = -Wall -g -o

# Required libraries
LIBS = -lgmp

# Output executable name
TARGET = rsa_assign_1

# Source files
SRC = rsa_assign_1.c

# Default target to build the executable
all: $(TARGET)

# Rule to compile the executable
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(TARGET) $(SRC) $(LIBS)

# Clean up 
clean:
	rm -f $(TARGET)
