################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../policys/ONLINE_DEAL_CTRL/online_deal_ctrl.o 

CPP_SRCS += \
../policys/ONLINE_DEAL_CTRL/online_deal_ctrl.cpp 

OBJS += \
./policys/ONLINE_DEAL_CTRL/online_deal_ctrl.o 

CPP_DEPS += \
./policys/ONLINE_DEAL_CTRL/online_deal_ctrl.d 


# Each subdirectory must supply rules for building sources it contributes
policys/ONLINE_DEAL_CTRL/%.o: ../policys/ONLINE_DEAL_CTRL/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


