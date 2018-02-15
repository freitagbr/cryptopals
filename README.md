# cryptopals

These are my solutions to the [Cryptopals Crypto
Challenges](https://cryptopals.com).


## Structure

Solutions for set X are located in `src/setX/*.cpp`. Common library code is
located in `src/*.cpp`, with the corresponding headers in `src/*.hpp`. Each
challenge is implemented as a single function in its source file, with the
`main` function in that file providing a test case.


## Dependencies

- `make`
- `gcc` or `clang`
- `valgrind`
  - Available on Linux and macOS Sierra 10.12 and below
- `openssl`
  - On Linux, the headers should already be included in `/usr/include/openssl`.
  - On macOS, the headers can be installed with `brew`:

		$ brew install openssl
		$ cd /usr/local/include/
		$ ln -s ../opt/openssl/include/openssl .


## Building

To build the solutions:

	$ make all

To build the solutions with debug symbols:

	$ make debug

The resulting object files, libraries, and binaries are placed in the `build/`
directory.


## Testing

To run tests:

	$ make test

To run the tests with `valgrind`:

	$ make valgrind
