#!/usr/bin/env bash
#
# mayhem/build.sh — build lib60870's fuzz harnesses and its Unity test suite.
#
# lib60870-C has no third-party dependencies without TLS (TLS needs an mbedtls tree, not used here),
# so the library sources are compiled directly — the same file set upstream's CMake builds — with no
# network access and no configure state. Re-runnable: every run recompiles into mayhem/out/
# (gitignored).
#
#  1) the library, sanitized + DWARF 3, WITHOUT the Linux socket/serial/time HAL: the harnesses supply
#     in-memory implementations of those three documented HAL interfaces (mayhem/harnesses/fuzz_hal_*.c)
#     so the CS104/CS101 stacks read their peer's bytes from the fuzz input and their timers from a
#     virtual clock each harness resets per input and advances per tick (deterministic timeouts);
#  2) each harness twice — libFuzzer binary /mayhem/<name> and run-once /mayhem/<name>-standalone;
#  3) upstream's tests/all_tests.c (Unity) against a normal-flags build of the full library, incl. the
#     real Linux HAL -> mayhem/out/tests/all_tests (run by mayhem/test.sh).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
L="$SRC/lib60870-C"
OUT="$SRC/mayhem/out"
H="$SRC/mayhem/harnesses"
INC=(-I"$L/config" -I"$L/src/file-service" -I"$L/src/inc/api" -I"$L/src/inc/internal"
     -I"$L/src/common/inc" -I"$L/src/hal/inc" -I"$H")

CORE_SRCS=( $(cd "$L" && find src/iec60870 src/common src/file-service src/hal/memory \
                 src/hal/thread/linux -name '*.c' | LC_ALL=C sort) )
LINUX_IO_SRCS=(src/hal/socket/linux/socket_linux.c src/hal/serial/linux/serial_port_linux.c
               src/hal/time/unix/time.c)

# compile_lib <objdir> <archive> <cflags...> -- <sources relative to lib60870-C...>
compile_lib() {
  local objdir="$1" archive="$2"; shift 2
  local flags=()
  while [ "$1" != "--" ]; do flags+=("$1"); shift; done; shift
  rm -rf "$objdir"; mkdir -p "$objdir"
  local pids=() n=0 s
  for s in "$@"; do
    "$CC" "${flags[@]}" -c "$L/$s" -o "$objdir/$(echo "$s" | tr / _).o" &
    pids+=($!); n=$((n+1))
    if [ $((n % MAYHEM_JOBS)) -eq 0 ]; then for p in "${pids[@]}"; do wait "$p"; done; pids=(); fi
  done
  for p in "${pids[@]}"; do wait "$p"; done
  rm -f "$archive"
  ar rcs "$archive" "$objdir"/*.o
}

# 1) sanitized library (fuzz)
# UBSan's -fsanitize=function check is relaxed (only that one check; ASan and the rest of UBSan stay
# on and halting): lib60870 implements InformationObject polymorphism with a C vtable whose
# encode/destroy slots hold functions taking the concrete subtype (e.g. ReadCommand_destroy(ReadCommand)),
# called through the base-type pointer in cs101_information_objects.c. That is the library's
# deliberate design, ABI-safe on every supported platform, and fires on every ASDU any target sees.
# The flag is added only when sanitizers are on (an empty SANITIZER_FLAGS builds with none).
UBSAN_RELAX=""
[ -z "$SANITIZER_FLAGS" ] || UBSAN_RELAX="-fno-sanitize=function"
SANITIZER_FLAGS="$SANITIZER_FLAGS $UBSAN_RELAX"
# SanCov on the library AND harness objects (unconditionally, also with sanitizers off), so the
# fuzzer sees edges in the protocol code, not just in the harness TU.
COV="-fsanitize=fuzzer-no-link"
FUZZ_CFLAGS=($SANITIZER_FLAGS $COV $DEBUG_FLAGS -O1 "${INC[@]}")
compile_lib "$OUT/obj-fuzz" "$OUT/lib60870_fuzz.a" "${FUZZ_CFLAGS[@]}" -- "${CORE_SRCS[@]}"

# 2) harnesses: support objects, then fuzzer + standalone per target
mkdir -p "$OUT/harn"
for s in fuzz_input fuzz_hal_socket fuzz_hal_serial fuzz_hal_time fuzz_file_provider; do
  "$CC" "${FUZZ_CFLAGS[@]}" -c "$H/$s.c" -o "$OUT/harn/$s.o"
done
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$OUT/harn/lsan_off.o"
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/harn/standalone_main.o"

SOCK=("$OUT/harn/fuzz_hal_socket.o")
SER=("$OUT/harn/fuzz_hal_serial.o")
FP=("$OUT/harn/fuzz_file_provider.o")
# name | source | extra defines | support objects
build_target() {
  local name="$1" src="$2" defs="$3"; shift 3
  "$CC" "${FUZZ_CFLAGS[@]}" $defs -c "$H/$src" -o "$OUT/harn/$name.o"
  local objs=("$OUT/harn/$name.o" "$@" "$OUT/harn/fuzz_input.o" "$OUT/harn/fuzz_hal_time.o" "$OUT/harn/lsan_off.o" "$OUT/lib60870_fuzz.a")
  "$CC" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${objs[@]}" -lpthread -lm -o "$SRC/$name"
  "$CC" $SANITIZER_FLAGS $COV $DEBUG_FLAGS "$OUT/harn/standalone_main.o" "${objs[@]}" -lpthread -lm -o "$SRC/$name-standalone"
}
build_target fuzz_asdu                   fuzz_asdu.c         ""                  "${SOCK[@]}" "${SER[@]}"
build_target fuzz_cs104_server           fuzz_cs104_server.c ""                  "${SOCK[@]}" "${SER[@]}" "${FP[@]}"
build_target fuzz_cs104_client           fuzz_cs104_client.c ""                  "${SOCK[@]}" "${SER[@]}"
build_target fuzz_cs101_slave_unbalanced fuzz_cs101_slave.c  "-DFUZZ_BALANCED=0" "${SOCK[@]}" "${SER[@]}" "${FP[@]}"
build_target fuzz_cs101_slave_balanced   fuzz_cs101_slave.c  "-DFUZZ_BALANCED=1" "${SOCK[@]}" "${SER[@]}" "${FP[@]}"
build_target fuzz_cs101_master_unbalanced fuzz_cs101_master.c "-DFUZZ_BALANCED=0" "${SOCK[@]}" "${SER[@]}"
build_target fuzz_cs101_master_balanced  fuzz_cs101_master.c "-DFUZZ_BALANCED=1" "${SOCK[@]}" "${SER[@]}"
build_target fuzz_file_service           fuzz_file_service.c ""                  "${SOCK[@]}" "${SER[@]}" "${FP[@]}"

# 3) upstream test suite, normal flags, real Linux HAL
TEST_CFLAGS=(-O1 -g $COVERAGE_FLAGS "${INC[@]}" -I"$L/tests/unity")
compile_lib "$OUT/obj-test" "$OUT/lib60870_test.a" "${TEST_CFLAGS[@]}" -- "${CORE_SRCS[@]}" "${LINUX_IO_SRCS[@]}"
mkdir -p "$OUT/tests"
"$CC" "${TEST_CFLAGS[@]}" "$L/tests/all_tests.c" "$L/tests/unity/unity.c" "$OUT/lib60870_test.a" \
  $COVERAGE_FLAGS -lpthread -lm -o "$OUT/tests/all_tests"
echo "build.sh: done"
