################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../policys/UDISK_ACT_CTRL/udisk_act_ctrl.o \
../policys/UDISK_ACT_CTRL/udisk_descramble.o

CPP_SRCS += \
../policys/UDISK_ACT_CTRL/udisk_act_ctrl.cpp \
../policys/UDISK_ACT_CTRL/udisk_descramble.cpp

OBJS += \
./policys/UDISK_ACT_CTRL/udisk_act_ctrl.o \
./policys/UDISK_ACT_CTRL/udisk_descramble.o

CPP_DEPS += \
./policys/UDISK_ACT_CTRL/udisk_act_ctrl.d \
./policys/UDISK_ACT_CTRL/udisk_descramble.d


# Each subdirectory must supply rules for building sources it contributes
policys/UDISK_ACT_CTRL/%.o: ../policys/UDISK_ACT_CTRL/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


