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
INIT_SRCS := ./init.c
INIT_OBJS := $(INIT_SRCS:.c=.o)


########################################
# target files
########################################
INIT := init


########################################
# build
########################################
%.o: %.c
	$(CC) -c $(DEFLANG) $(CFLAGS) $(DBG) -o $@ $<

all:				\
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

clean:
	@$(foreach obj, $(INIT_OBJS), rm -fv $(obj);)

	@-rm -fv ./$(INIT)
	@echo "cleaned."

