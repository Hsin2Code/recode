DIR_INC = ./inc
DIR_SRC = ./src
DIR_OBJ = ./obj
DIR_BIN = ./bin


ifeq ($(wildcard ${DIR_OBJ}),)
$(shell mkdir ${DIR_OBJ})
endif
ifeq ($(wildcard ${DIR_BIN}),)
$(shell mkdir ${DIR_BIN})
endif

######################################
# wildcard : 扩展通配符
# notdir : 去除路径
# patsubst : 替换通配符
######################################
SRC = $(wildcard ${DIR_SRC}/*.c)
OBJ = $(patsubst %.c, ${DIR_OBJ}/%.o, $(notdir ${SRC}))

# 可执行程序
TARGET = edp_client

BIN_TARGET = ${DIR_BIN}/${TARGET}

# 连接选项
LINK = -lpthread -ldl
# 编译器
CC = gcc
# 编译器选项
CFLAGS = -g -Wall -I${DIR_INC}

${BIN_TARGET}: ${OBJ}
	$(CC) $(OBJ) $(LINK) -o $@

${DIR_OBJ}/%.o:${DIR_SRC}/%.c
	$(CC) $(CFLAGS) -c  $< -o $@

.PHONY: clean
clean:
#	find ${DIR_OBJ} -name *.o -exec rm -rf {} \;
	rm -rf ${DIR_BIN} ${DIR_OBJ}
