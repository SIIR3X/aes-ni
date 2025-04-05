###########################################################################
#                                                                         #
#   Makefile                                                              #
#                                                                         #
#   AES-NI                                                                #
#                                                                         #
###########################################################################

###########################################################################
################################ COMMANDS #################################
###########################################################################

rwildcard = $(wildcard $1$2) $(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2))

ifeq ($(OS),Windows_NT)
	MKDIR   = if not exist "$(1)" mkdir "$(1)" >nul 2>&1
	RMDIR   = if exist "$(1)" rmdir /S /Q "$(1)" >nul 2>&1
	RM_ALL  = if exist "$(1)" del /F /Q "$(1)\*" >nul 2>&1 & for /D %%p in ("$(1)\*") do rmdir "%%p" /S /Q >nul 2>&1
	RM_FILE = if exist "$(1)" del /F /Q "$(1)" >nul 2>&1
	MEMCHECK = @echo Memory check not available on Windows.
else
	MKDIR    = mkdir -p "$(1)" >/dev/null 2>&1
	RMDIR    = rm -rf "$(1)" >/dev/null 2>&1
	RM_ALL   = rm -rf "$(1)"/* >/dev/null 2>&1
	RM_FILE  = rm -f "$(1)" >/dev/null 2>&1
	MEMCHECK = valgrind --leak-check=full --show-leak-kinds=all $(1) $(2)
endif


###########################################################################
############################## EXECUTABLES ################################
###########################################################################

MAIN_ARGS = -mode ECB -e -in data/plaintext.txt -out data/ciphertext.txt -key 000102030405060708090a0b0c0d0e0f
TEST_ARGS =
EXPE_ARGS = 1000 10 16

MAIN_EXEC = aes
TEST_EXEC = tests
EXPE_EXEC = expe


###########################################################################
################################# FOLDERS #################################
###########################################################################

SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj
BIN_DIR = bin
EXPE_DIR = experiments
TEST_DIR = tests


###########################################################################
################################## FILES ##################################
###########################################################################

SRC_EXT = c

SRC_FILES = $(filter %.$(SRC_EXT), $(call rwildcard, $(SRC_DIR)/, *.$(SRC_EXT)))

TEST_FILES = $(filter %.$(SRC_EXT), $(call rwildcard, $(TEST_DIR)/, *.$(SRC_EXT)))

EXPE_FILES = $(filter %.$(SRC_EXT), $(call rwildcard, $(EXPE_DIR)/, *.$(SRC_EXT)))

ifeq ($(OS),Windows_NT)
	MAIN_PROGRAM = $(BIN_DIR)\$(MAIN_EXEC).exe
	TEST_PROGRAM = $(BIN_DIR)\$(TEST_EXEC).exe
	EXPE_PROGRAM = $(BIN_DIR)\$(EXPE_EXEC).exe
else
	MAIN_PROGRAM = $(BIN_DIR)/$(MAIN_EXEC)
	TEST_PROGRAM = $(BIN_DIR)/$(TEST_EXEC)
	EXPE_PROGRAM = $(BIN_DIR)/$(EXPE_EXEC)
endif


###########################################################################
################################# OBJECTS #################################
###########################################################################

OBJ_FILES = $(patsubst $(SRC_DIR)/%.$(SRC_EXT), $(OBJ_DIR)/%.o, $(SRC_FILES))
OBJ_FILES_NO_MAIN = $(filter-out $(OBJ_DIR)/main.o, $(OBJ_FILES))

EXPE_OBJ_FILES = $(patsubst $(EXPE_DIR)/%.$(SRC_EXT), $(OBJ_DIR)/$(EXPE_DIR)/%.o, $(EXPE_FILES))

TEST_OBJ_FILES = $(patsubst $(TEST_DIR)/%.$(SRC_EXT), $(OBJ_DIR)/$(TEST_DIR)/%.o, $(TEST_FILES))


###########################################################################
############################ COMPILER & FLAGS #############################
###########################################################################

CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -O3 -march=native -maes -msse2 -mssse3 -mpclmul -I$(INC_DIR)
LDFLAGS = -flto

TEST_CFLAGS = -std=c11 -Wall -Wextra -O3 -march=native -maes -msse2 -mssse3 -mpclmul -I$(INC_DIR) -I$(TEST_DIR)
TEST_LDFLAGS = -flto

EXPE_CFLAGS = -std=c11 -Wall -Wextra -O3 -march=native -maes -msse2 -mssse3 -mpclmul -I$(INC_DIR) -I$(EXPE_DIR)
EXPE_LDFLAGS = -flto


###########################################################################
################################## BUILD ##################################
###########################################################################

all: directories $(MAIN_PROGRAM)

$(MAIN_PROGRAM): $(OBJ_FILES)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@$(call MKDIR,$(dir $@))
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_PROGRAM): $(OBJ_FILES_NO_MAIN) $(TEST_OBJ_FILES)
	$(CC) $(TEST_CFLAGS) $^ -o $@ $(TEST_LDFLAGS)

$(OBJ_DIR)/$(TEST_DIR)/%.o: $(TEST_DIR)/%.$(SRC_EXT)
	@$(call MKDIR,$(dir $@))
	$(CC) $(TEST_CFLAGS) -c $< -o $@

$(EXPE_PROGRAM): $(OBJ_FILES_NO_MAIN) $(EXPE_OBJ_FILES)
	$(CC) $(EXPE_CFLAGS) $^ -o $@ $(EXPE_LDFLAGS)

$(OBJ_DIR)/$(EXPE_DIR)/%.o: $(EXPE_DIR)/%.$(SRC_EXT)
	@$(call MKDIR,$(dir $@))
	$(CC) $(EXPE_CFLAGS) -c $< -o $@


###########################################################################
################################## PHONY ##################################
###########################################################################

.PHONY: all directories run memorycheck test memorychecktest expe memorycheckexpe clean delete deletetest deleteexpe cleanall doc help

directories:
	@$(call MKDIR,$(OBJ_DIR))
	@$(call MKDIR,$(BIN_DIR))

run: all
	$(MAIN_PROGRAM) $(MAIN_ARGS)

memorycheck: all
	@$(call MEMCHECK,$(MAIN_PROGRAM),$(MAIN_ARGS))

test: directories $(TEST_PROGRAM)
	$(TEST_PROGRAM) $(TEST_ARGS)

memorychecktest: directories $(TEST_PROGRAM)
	@$(call MEMCHECK,$(TEST_PROGRAM),$(TEST_ARGS))

expe: directories $(EXPE_PROGRAM)
	$(EXPE_PROGRAM) $(EXPE_ARGS)

memorycheckexpe: directories $(EXPE_PROGRAM)
	@$(call MEMCHECK,$(EXPE_PROGRAM),$(EXPE_ARGS))

clean:
	@$(call RM_ALL,$(OBJ_DIR))
	@$(call RM_ALL,$(BIN_DIR))
	
delete:
	@$(call RM_FILE,$(MAIN_PROGRAM))

deletetest:
	@$(call RM_FILE,$(TEST_PROGRAM))

deleteexpe:
	@$(call RM_FILE,$(EXPE_PROGRAM))

cleanall:
	@$(call RMDIR,$(OBJ_DIR))
	@$(call RMDIR,$(BIN_DIR))

doc: 
	doxygen Doxyfile

help:
	@echo "Makefile for AES project"
	@echo "Usage:"
	@echo "  make all                : Build the main program"
	@echo "  make run               : Run the main program"
	@echo "  make memorycheck       : Run memory check on the main program"
	@echo "  make test              : Build and run tests"
	@echo "  make memorychecktest   : Run memory check on tests"
	@echo "  make expe              : Build and run experiments"
	@echo "  make memorycheckexpe   : Run memory check on experiments"
	@echo "  make clean             : Clean object and binary files"
	@echo "  make delete            : Delete the main program executable"
	@echo "  make deletetest        : Delete the test program executable"
	@echo "  make deleteexpe        : Delete the experiment program executable"
	@echo "  make cleanall          : Clean all object and binary files, including directories"
	@echo "  make doc               : Generate documentation using Doxygen"

#############################################################################