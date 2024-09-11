# Makefile

# Path to the license header file
PYTHON_LICENSE_HEADER_FILE = hack/boilerplate.py.txt
C_LICENSE_HEADER_FILE = hack/boilerplate.c.txt

# Read the license header into a variable
PYTHON_LICENSE_HEADER = $(shell cat $(PYTHON_LICENSE_HEADER_FILE))
C_LICENSE_HEADER = $(shell cat $(C_LICENSE_HEADER_FILE))

YAML_FILES := $(shell find . -name '*.yaml')
PYTHON_FILES := $(shell find . -name '*.py')
C_FILES := $(shell find . -name '*.c')

# Target to insert license header into all Python files
insert-license:
	@for file in $(PYTHON_FILES) $(YAML_FILES); do \
		if [ -f $$file ]; then \
			if ! grep -qF "Apache-2.0" $$file; then \
				{ echo "$$(cat $(PYTHON_LICENSE_HEADER_FILE))"; echo ""; cat $$file; } > $$file.tmp && mv $$file.tmp $$file; \
				echo "Updated $$file"; \
			else \
				echo "Skipped $$file (already contains license header)"; \
			fi \
		fi \
	done
	@for file in $(C_FILES); do \
		if [ -f $$file ]; then \
			if ! grep -qF "Apache-2.0" $$file; then \
				{ echo "$$(cat $(C_LICENSE_HEADER_FILE))"; echo ""; cat $$file; } > $$file.tmp && mv $$file.tmp $$file; \
				echo "Updated $$file"; \
			else \
				echo "Skipped $$file (already contains license header)"; \
			fi \
		fi \
	done
