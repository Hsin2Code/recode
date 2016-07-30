################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../policys/POLICY_AUTO_SHUTDOWN/policy_auto_shutdown.o 

CPP_SRCS += \
../policys/POLICY_AUTO_SHUTDOWN/policy_auto_shutdown.cpp 

OBJS += \
./policys/POLICY_AUTO_SHUTDOWN/policy_auto_shutdown.o 

CPP_DEPS += \
./policys/POLICY_AUTO_SHUTDOWN/policy_auto_shutdown.d 


# Each subdirectory must supply rules for building sources it contributes
policys/POLICY_AUTO_SHUTDOWN/%.o: ../policys/POLICY_AUTO_SHUTDOWN/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


