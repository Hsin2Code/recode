################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../policys/USER_RIGHT_AUDIT/user_right_audit.o 

CPP_SRCS += \
../policys/USER_RIGHT_AUDIT/user_right_audit.cpp 

OBJS += \
./policys/USER_RIGHT_AUDIT/user_right_audit.o 

CPP_DEPS += \
./policys/USER_RIGHT_AUDIT/user_right_audit.d 


# Each subdirectory must supply rules for building sources it contributes
policys/USER_RIGHT_AUDIT/%.o: ../policys/USER_RIGHT_AUDIT/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


