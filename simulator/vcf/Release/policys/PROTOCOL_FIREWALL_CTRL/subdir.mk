################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../policys/PROTOCOL_FIREWALL_CTRL/protocol_firewall_ctrl.o 

CPP_SRCS += \
../policys/PROTOCOL_FIREWALL_CTRL/protocol_firewall_ctrl.cpp 

OBJS += \
./policys/PROTOCOL_FIREWALL_CTRL/protocol_firewall_ctrl.o

CPP_DEPS += \
./policys/PROTOCOL_FIREWALL_CTRL/protocol_firewall_ctrl.d 


# Each subdirectory must supply rules for building sources it contributes
policys/PROTOCOL_FIREWALL_CTRL/%.o: ../policys/PROTOCOL_FIREWALL_CTRL/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


