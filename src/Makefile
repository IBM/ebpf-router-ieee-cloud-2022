all: 
	$(MAKE) -C ptrace_do all
	gcc -o forwarder forward_fd.cpp
clean: 
	$(MAKE) -C ptrace_do clean
	rm forwarder