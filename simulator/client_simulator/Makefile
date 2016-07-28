CFLAGS := -c -g -Wall -O3 --std=c++11
CROSS=
CC := $(CROSS)g++

SRCDIR=./src
OBJDIR = ./objs

LIBS = -lpthread
LDLIBS = $(LIBS)

SOURCES:= $(wildcard $(SRCDIR)/*.cpp)
CPPOBJS := $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)

INCLUDE:= -I./inc -I/usr/include -I./inc/vrv_protocol

BINDIR := ./bin

EXEC := client_simulator
TARGET := $(BINDIR)/$(EXEC)

$(TARGET): $(CPPOBJS)
	$(CC)  -o $@ $^ $(LDLIBS)

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $@ $<

clean:
	-rm -rf $(TARGET) $(CPPOBJS)
