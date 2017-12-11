#########################################
# global defines
#########################################
ifndef DESTDIR
DESTDIR=/usr/local
endif
ifndef INIT_PROGRAM
INIT_PROGRAM=/etc/init.sh
endif
ifndef SHUTDOWN_PROGRAM
SHUTDOWN_PROGRAM=/etc/shutdown.sh
endif

DEFINES := -DMAX_SYSTEMPATH=1024 			\
	   -DINIT_PROGRAM=\"$(INIT_PROGRAM)\"		\
	   -DSHUTDOWN_PROGRAM=\"$(SHUTDOWN_PROGRAM)\"

CFLAGS  := -pedantic -Wall -Wextra -Werror $(DEFINES)

# remove unused code from eslb
CFLAGS  += -ffunction-sections
LDFLAGS := -Wl,--gc-sections

DEFLANG := -ansi
#DBG	:= -g

#########################################
# objects
#########################################
INIT_SRCS := 	./init.c		\
		./cmdline.c		\
		./program.c		\
		./shutdown.nomain.c	\
		./eslib/eslib_string.c	\
		./eslib/eslib_fortify.c
INIT_OBJS := $(INIT_SRCS:.c=.o)

SHUTDOWN_SRCS := ./shutdown.c
SHUTDOWN_OBJS := $(SHUTDOWN_SRCS:.c=.o)

INITRAM_SRCS := ./initram.c ./cmdline.c ./eslib/eslib_string.c
INITRAM_OBJS := $(INITRAM_SRCS:.c=.o)

TESTDAEMON_SRCS := ./testdaemon.c
TESTDAEMON_OBJS := $(TESTDAEMON_SRCS:.c=.o)

########################################
# target files
########################################
INIT        := init
SHUTDOWN    := shutdown
INITRAM     := initram
TESTDAEMON  := testdaemon


########################################
# build
########################################
%.nomain.o: %.c
	$(CC) -c $(DEFLANG) $(CFLAGS) -DSTRIP_MAIN $(DBG) -o $@ $<

%.o: %.c
	$(CC) -c $(DEFLANG) $(CFLAGS) $(DBG) -o $@ $<

all:						\
	$(SHUTDOWN)				\
	$(INIT)					\
	$(INITRAM)				\
	$(TESTDAEMON)


########################################
# targets
########################################
$(INIT):		$(INIT_OBJS)
			$(CC) $(LDFLAGS) $(INIT_OBJS) -o $@
			@echo ""
			@echo "x--------------------x"
			@echo "| init            OK |"
			@echo "x--------------------x"
			@echo ""

$(INITRAM):		$(INITRAM_OBJS)
			$(CC) $(LDFLAGS) $(INITRAM_OBJS) -o $@
			@echo ""
			@echo "x--------------------x"
			@echo "| initram         OK |"
			@echo "x--------------------x"
			@echo ""

$(SHUTDOWN):		$(SHUTDOWN_OBJS)
			$(CC) $(LDFLAGS) $(SHUTDOWN_OBJS) -o $@
			@echo ""
			@echo "x--------------------x"
			@echo "| shutdown        OK |"
			@echo "x--------------------x"
			@echo ""

$(TESTDAEMON):		$(TESTDAEMON_OBJS)
			$(CC) $(LDFLAGS) $(TESTDAEMON_OBJS) -o $@
			@echo ""
			@echo "x--------------------x"
			@echo "| testdaemon      OK |"
			@echo "x--------------------x"
			@echo ""

install:
	@umask 022
	@install -dvm 0755  "$(DESTDIR)/sbin"
	@install -dvm 0755  "$(DESTDIR)/etc/init"
	@install -Dvm 0750  "$(INIT)"          "$(DESTDIR)/sbin/init"
	@install -Dvm 0750  "$(SHUTDOWN)"      "$(DESTDIR)/sbin/shutdown"
	@install -Dvm 0750  "modman.sh"        "$(DESTDIR)/sbin/modman.sh"
	@install -Dvm 0750  "etc/init.sh"      "$(DESTDIR)/$(INIT_PROGRAM)"
	@install -Dvm 0750  "etc/shutdown.sh"  "$(DESTDIR)/$(SHUTDOWN_PROGRAM)"
	@install -Dvm 0750  "etc/init/programs/user-shell" \
						"$(DESTDIR)/etc/init/programs/user-shell"

clean:
	@$(foreach obj, $(INIT_OBJS), rm -fv $(obj);)
	@$(foreach obj, $(SHUTDOWN), rm -fv $(obj);)
	@$(foreach obj, $(INITRAM_OBJS), rm -fv $(obj);)
	@$(foreach obj, $(TESTDAEMON), rm -fv $(obj);)

	@-rm -fv ./$(INIT)
	@-rm -fv ./$(SHUTDOWN)
	@-rm -fv ./$(INITRAM)
	@-rm -fv ./$(TESTDAEMON)
	@echo "cleaned."

