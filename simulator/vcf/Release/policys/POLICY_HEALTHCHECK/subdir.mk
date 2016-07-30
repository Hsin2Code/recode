################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../policys/POLICY_HEALTHCHECK/policy_healthcheck.cpp 

OBJS += \
./policys/POLICY_HEALTHCHECK/policy_healthcheck.o 

CPP_DEPS += \
./policys/POLICY_HEALTHCHECK/policy_healthcheck.d 


# Each subdirectory must supply rules for building sources it contributes
policys/POLICY_HEALTHCHECK/%.o: ../policys/POLICY_HEALTHCHECK/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


