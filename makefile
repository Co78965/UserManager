# Компилятор и флаги
CC = cl.exe
CFLAGS = /nologo /W4 /O2 /EHsc /I. /IUsersInfo /IGroupsInfo
LDFLAGS = /nologo

# Директории
SRC_DIR = .
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj
BIN_DIR = $(BUILD_DIR)/bin

# Исходные файлы
SRCS = main.cpp UsersInfo/UsersInfo.cpp GroupsInfo/GroupsInfo.cpp

# Объектные файлы (с правильными путями)
OBJS = $(OBJ_DIR)/main.obj $(OBJ_DIR)/UsersInfo.obj $(OBJ_DIR)/GroupsInfo.obj

# Имя исполняемого файла
TARGET = $(BIN_DIR)/o.exe

# Правило по умолчанию
all: $(TARGET)

# Правило для компоновки
$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $(OBJS) /Fe$@

# Правила для компиляции
$(OBJ_DIR)/main.obj: main.cpp | $(OBJ_DIR)
	$(CC) $(CFLAGS) /c $< /Fo$@

$(OBJ_DIR)/UsersInfo.obj: UsersInfo/UsersInfo.cpp | $(OBJ_DIR)
	$(CC) $(CFLAGS) /c $< /Fo$@

$(OBJ_DIR)/GroupsInfo.obj: GroupsInfo/GroupsInfo.cpp | $(OBJ_DIR)
	$(CC) $(CFLAGS) /c $< /Fo$@

# Создание директорий
$(BUILD_DIR):
	@if not exist "$@" mkdir "$@"

$(OBJ_DIR): | $(BUILD_DIR)
	@if not exist "$@" mkdir "$@"

$(BIN_DIR): | $(BUILD_DIR)
	@if not exist "$@" mkdir "$@"

# Очистка
clean:
	@if exist "$(OBJ_DIR)" rmdir /s /q "$(OBJ_DIR)"
	@if exist "$(BIN_DIR)" rmdir /s /q "$(BIN_DIR)"
	@if exist "$(BUILD_DIR)" rmdir /s /q "$(BUILD_DIR)"

.PHONY: all clean