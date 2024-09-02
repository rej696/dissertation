LDFLAGS += $(shell pkg-config --libs glib-2.0) -lpthread -lm -lunicorn

all: unicorn-example

%: %.c
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@
