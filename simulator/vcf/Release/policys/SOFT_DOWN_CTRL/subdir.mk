################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../policys/SOFT_DOWN_CTRL/soft_down_ctl.o 

CPP_SRCS += \
../policys/SOFT_DOWN_CTRL/soft_down_ctl.cpp 

OBJS += \
./policys/SOFT_DOWN_CTRL/soft_down_ctl.o 

CPP_DEPS += \
./policys/SOFT_DOWN_CTRL/soft_down_ctl.d 


# Each subdirectory must supply rules for building sources it contributes
policys/SOFT_DOWN_CTRL/%.o: ../policys/SOFT_DOWN_CTRL/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

