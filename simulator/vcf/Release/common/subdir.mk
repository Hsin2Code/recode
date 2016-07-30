################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../common/CYlog.cpp \
../common/Cmemerymgr.cpp \
../common/Commonfunc.cpp \
../common/ping.cpp 

OBJS += \
./common/CYlog.o \
./common/Cmemerymgr.o \
./common/Commonfunc.o \
./common/ping.o 

CPP_DEPS += \
./common/CYlog.d \
./common/Cmemerymgr.d \
./common/Commonfunc.d \
./common/ping.d 


# Each subdirectory must supply rules for building sources it contributes
common/%.o: ../common/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	$(CC) -O3 -Wall -c -fmessage-length=0 $(CXX_FLAGS_COMP) $(INC_FLAGS) -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


