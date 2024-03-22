CC = gcc
CFLAGS = -fPIC -Wall -Wextra -O2 -g -I$(src)
LDFLAGS = -shared -lxtables
RM = rm -f

LIBS = libxt_luanetfilter.so
OBJS = libxt_luanetfilter.o
DEPS = $(OBJS:.o=.d)

.PHONY: all
all: $(LIBS)

clean:
	$(RM) $(LIBS) $(OBJS) $(DEPS)

%.so:
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -c -o $@ $<

-include $(DEPS)

.PHONY: clean
clean:
	$(RM) $(LIBS) $(OBJS) $(DEPS)

libxt_luanetfilter.so: libxt_luanetfilter.o
