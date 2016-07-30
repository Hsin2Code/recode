################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../policys/SERVICE_CTRL/service_ctrl.o 

CPP_SRCS += \
../policys/SERVICE_CTRL/service_ctrl.cpp 

OBJS += \
./policys/SERVICE_CTRL/service_ctrl.o 

CPP_DEPS += \
./policys/SERVICE_CTRL/service_ctrl.d 


# Each subdirectory must supply rules for building sources it contributes
policys/SERVICE_CTRL/%.o: ../policys/SERVICE_CTRL/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


