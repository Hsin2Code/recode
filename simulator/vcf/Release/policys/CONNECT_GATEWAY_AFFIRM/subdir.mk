################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../policys/CONNECT_GATEWAY_AFFIRM/connect_gateway_affirm.cpp 

OBJS += \
./policys/CONNECT_GATEWAY_AFFIRM/connect_gateway_affirm.o 

CPP_DEPS += \
./policys/CONNECT_GATEWAY_AFFIRM/connect_gateway_affirm.d 


# Each subdirectory must supply rules for building sources it contributes
policys/CONNECT_GATEWAY_AFFIRM/%.o: ../policys/CONNECT_GATEWAY_AFFIRM/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


