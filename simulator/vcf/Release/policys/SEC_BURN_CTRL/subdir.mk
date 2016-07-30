################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../policys/SEC_BURN_CTRL/sec_burn_ctl.o 

CPP_SRCS += \
../policys/SEC_BURN_CTRL/sec_burn_ctl.cpp 

OBJS += \
./policys/SEC_BURN_CTRL/sec_burn_ctl.o 

CPP_DEPS += \
./policys/SEC_BURN_CTRL/sec_burn_ctl.d 


# Each subdirectory must supply rules for building sources it contributes
policys/SEC_BURN_CTRL/%.o: ../policys/SEC_BURN_CTRL/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


