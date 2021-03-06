#!/bin/sh -e

example_paths() {
  ls -1 examples/*.c | sed 's/.c$//g'
}

test_paths() {
  ls -1 tests/*.c | sed 's/.c$//g'
}

clean() {
  for p in $(test_paths) $(example_paths)
  do
    rm -f "${p}"
    rm -fR "${p}.dSYM" # for macOS
  done
}


build_and_test() {
  CFLAGS="$CFLAGS -Wextra -Wall -Wvla -std=c99 -I. -lpthread"
  CFLAGS="$CFLAGS -g"
  CFLAGS="$CFLAGS -Dserv_MAX_CLIENTS=20" # for tests/too_many_clients.c
  #CFLAGS="$CFLAGS -fsanitize=address"

  for p in $(test_paths) $(example_paths)
  do
    cc $CFLAGS -o "${p}" "${p}.c" libforks.c
  done

  (cd tests && ./main) # run the tests
}


if [ "$1" = "clean" ]
then
  clean
elif [ "$1" = "readme" ]
then
  ./generate_readme.ex >README.md
else
  build_and_test
fi

