.PHONY: all build test clean
all: build

build:
	./build.sh

test: build
	pytest

clean:
	rm -rf build __pycache__ tests/__pycache__ mera_data mera_demo_data
