BUILD := debug
BUILD_DIR := build/${BUILD}/
.DEFAULT_GOAL := ${BUILD_DIR}checksums

pkgs = pkg-config --cflags gtkmm-3.0 libcurl libcrypto
ifneq ($(OS),Windows_NT)
	pkgs += libsecret-1
endif
pkgconfig_compile := pkg-config --cflags ${pkgs}
pkgconfig_link := pkg-config --cflags --libs ${pkgs}

cxxflags.common :=  -I. `${pkgconfig_compile}` -std=c++17

cxxflags.debug := -g -O0
cxxflags.release := -O2
cxxflags.sanitize_address:= -g -O0 -fsanitize=address
cxxflags.sanitize_thread:= -g -O0 -fsanitize=thread
CXXFLAGS := ${cxxflags.${BUILD}} ${cxxflags.common}

ldflags.common :=
ifeq ($(OS),Windows_NT)
	ldflags.common += -mwindows
endif
ldflags.debug :=
ldflags.release :=
ldflags.sanitize_address := -fsanitize=address
ldflags.sanitize_thread := -fsanitize=thread
LDFLAGS := ${ldflags.${BUILD}} ${ldflags.common}

VPATH=$(BUILD_DIR)third_party/json_parser/
CC=g++

_OBJ := token_window.o main_window.o resources.o api.o utils.o third_party/json_parser/json_parser.o
ifeq ($(OS),Windows_NT)
	_OBJ += utils_win.o
else
	_OBJ += utils_linux.o
endif

_TEST_OBJ := utils_unittest.o api_unittest.o
OBJ := ${patsubst %,${BUILD_DIR}%,${_OBJ}}
TEST_OBJ := ${patsubst %,${BUILD_DIR}%,${_TEST_OBJ}}
$(shell mkdir -p $(BUILD_DIR))
$(shell mkdir -p $(BUILD_DIR)third_party/json_parser/)

${BUILD_DIR}third_party/json_parser/%.o: %.cc
	$(CC) -c -o $@ $< $(CXXFLAGS)

${BUILD_DIR}%.o: %.cc
	$(CC) -c -o $@ $< $(CXXFLAGS)

${BUILD_DIR}checksums: $(OBJ)
	$(CC) ${LDFLAGS} -o ${BUILD_DIR}checksums shasums.cc $^ `${pkgconfig_link}`

${BUILD_DIR}run_tests: $(OBJ) $(TEST_OBJ)
	$(CC) ${LDFLAGS} -o ${BUILD_DIR}run_tests run_tests.cc /usr/lib/x86_64-linux-gnu/libgtest.a $^ `${pkgconfig_link}`

.PHONY: tests
tests: ${BUILD_DIR}run_tests

install:
	mkdir -p $(DESTDIR)/bin
	cp ${BUILD_DIR}checksums $(DESTDIR)/bin/

.PHONY: clean
clean:
	echo "Removing build files"
	rm ${BUILD_DIR}*.o 
	rm ${BUILD_DIR}third_party/json_parser/*.o
	rm ${BUILD_DIR}checksums
