# SPDX-License-Identifier: Apache-2.0

.PHONY: func \
	func_44 \
	func_65 \
	func_87 \
	run_func \
	run_func_44 \
	run_func_65\
	run_func_87 \
	build test all \
	clean quickcheck

.DEFAULT_GOAL := build
all: build

W := $(EXEC_WRAPPER)

include test/mk/config.mk
include test/mk/components.mk
include test/mk/rules.mk

quickcheck: test

build: func
	$(Q)echo "  Everything builds fine!"

test: run_func
	$(Q)echo "  Everything checks fine!"

run_func_44: func_44
	$(W) $(MLDSA44_DIR)/bin/test_mldsa44
run_func_65: func_65
	$(W) $(MLDSA65_DIR)/bin/test_mldsa65
run_func_87: func_87
	$(W) $(MLDSA87_DIR)/bin/test_mldsa87
run_func: run_func_44 run_func_65 run_func_87

func_44: $(MLDSA44_DIR)/bin/test_mldsa44
	$(Q)echo "  FUNC       ML-DSA-44:   $^"
func_65: $(MLDSA65_DIR)/bin/test_mldsa65
	$(Q)echo "  FUNC       ML-DSA-65:   $^"
func_87: $(MLDSA87_DIR)/bin/test_mldsa87
	$(Q)echo "  FUNC       ML-DSA-87:  $^"
func: func_44 func_65 func_87

lib: $(BUILD_DIR)/libmldsa.a $(BUILD_DIR)/libmldsa44.a $(BUILD_DIR)/libmldsa65.a $(BUILD_DIR)/libmldsa87.a

clean:
	-$(RM) -rf *.gcno *.gcda *.lcov *.o *.so
	-$(RM) -rf $(BUILD_DIR)