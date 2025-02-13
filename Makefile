# SPDX-License-Identifier: Apache-2.0

.PHONY: func kat \
	func_44  kat_44 \
	func_65 kat_65 \
	func_87 kat_87 \
	run_func run_kat \
	run_func_44 run_kat_44 \
	run_func_65 run_kat_65 \
	run_func_87 run_kat_87 \
	build test all \
	clean quickcheck

.DEFAULT_GOAL := build
all: build

W := $(EXEC_WRAPPER)

include test/mk/config.mk
include test/mk/components.mk
include test/mk/rules.mk

quickcheck: test

build: func kat
	$(Q)echo "  Everything builds fine!"

test: run_kat run_func
	$(Q)echo "  Everything checks fine!"


run_kat_44: kat_44
	$(W) $(MLDSA44_DIR)/bin/gen_KAT44 | sha256sum | cut -d " " -f 1 | xargs ./META.sh ML-DSA-44  kat-sha256
run_kat_65: kat_65
	$(W) $(MLDSA65_DIR)/bin/gen_KAT65 | sha256sum | cut -d " " -f 1 | xargs ./META.sh ML-DSA-65  kat-sha256
run_kat_87: kat_87
	$(W) $(MLDSA87_DIR)/bin/gen_KAT87 | sha256sum | cut -d " " -f 1 | xargs ./META.sh ML-DSA-87  kat-sha256
run_kat: run_kat_44 run_kat_65 run_kat_87

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

kat_44: $(MLDSA44_DIR)/bin/gen_KAT44
	$(Q)echo "  KAT        ML-DSA-44:   $^"
kat_65: $(MLDSA65_DIR)/bin/gen_KAT65
	$(Q)echo "  KAT        ML-DSA-65:   $^"
kat_87: $(MLDSA87_DIR)/bin/gen_KAT87
	$(Q)echo "  KAT        ML-DSA-87:  $^"
kat: kat_44 kat_65 kat_87

lib: $(BUILD_DIR)/libmldsa.a $(BUILD_DIR)/libmldsa44.a $(BUILD_DIR)/libmldsa65.a $(BUILD_DIR)/libmldsa87.a

clean:
	-$(RM) -rf *.gcno *.gcda *.lcov *.o *.so
	-$(RM) -rf $(BUILD_DIR)
