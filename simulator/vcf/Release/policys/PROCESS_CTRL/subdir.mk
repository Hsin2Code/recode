################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../policys/PROCESS_CTRL/process_ctrl.o \
../policys/PROCESS_CTRL/dbus_comm.o 

CPP_SRCS += \
../policys/PROCESS_CTRL/process_ctrl.cpp \
../policys/PROCESS_CTRL/dbus_comm.cpp

OBJS += \
./policys/PROCESS_CTRL/process_ctrl.o \
./policys/PROCESS_CTRL/dbus_comm.o

CPP_DEPS += \
./policys/PROCESS_CTRL/process_ctrl.d \
./policys/PROCESS_CTRL/dbus_comm.d


DBUS_INC = ../include/dbus_misc/dbus-1.0/
DBUS_INC_PATL_DEPS = ../include/dbus_misc/plat_deps/
SM_LIBS = ../lib

# Each subdirectory must supply rules for building sources it contributes
policys/PROCESS_CTRL/%.o: ../policys/PROCESS_CTRL/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall \
		-I$(DBUS_INC) -I$(DBUS_INC_PATL_DEPS) \
		-L$(SM_LIBS) -ldbus-1 \
		-c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


