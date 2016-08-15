#########################################
# global defines
#########################################
DEFINES := -DMAX_SYSTEMPATH=1024
CFLAGS  := -pedantic -Wall -Wextra -Werror $(DEFINES)
DEFLANG := -ansi
#DBG	:= -g
#########################################
# optional features
#########################################


#TODO strip debugging info
#########################################
# objects
#########################################
INIT_SRCS := 	./init.c		\
		./shutdown.nomain.c
INIT_OBJS := $(INIT_SRCS:.c=.o)
SHUTDOWN_SRCS := ./shutdown.c
SHUTDOWN_OBJS := $(SHUTDOWN_SRCS:.c=.o)


########################################
# target files
########################################
INIT := init
SHUTDOWN := shutdown


########################################
# build
########################################
%.nomain.o: %.c
	$(CC) -c $(DEFLANG) $(CFLAGS) -DSTRIP_MAIN $(DBG) -o $@ $<

%.o: %.c
	$(CC) -c $(DEFLANG) $(CFLAGS) $(DBG) -o $@ $<

all:						\
	$(SHUTDOWN)				\
	$(INIT)


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
$(SHUTDOWN):		$(SHUTDOWN_OBJS)
			$(CC) $(LDFLAGS) $(SHUTDOWN_OBJS) -o $@
			@echo ""
			@echo "x--------------------x"
			@echo "| shutdown        OK |"
			@echo "x--------------------x"
			@echo ""


clean:
	@$(foreach obj, $(INIT_OBJS), rm -fv $(obj);)
	@$(foreach obj, $(SHUTDOWN), rm -fv $(obj);)

	@-rm -fv ./$(INIT)
	@-rm -fv ./$(SHUTDOWN)
	@echo "cleaned."

