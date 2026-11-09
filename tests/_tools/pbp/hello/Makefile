TARGET = hello
OBJS = main.o
CFLAGS = -Os -G0 -Wall

BUILD_PRX = 1

LIBS = -lpspdebug

PSPSDK=$(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build.mak
