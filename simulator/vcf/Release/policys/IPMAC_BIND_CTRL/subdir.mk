################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../policys/IPMAC_BIND_CTRL/ipmac_bind_ctrl.o 

CPP_SRCS += \
../policys/IPMAC_BIND_CTRL/ipmac_bind_ctrl.cpp 

OBJS += \
./policys/IPMAC_BIND_CTRL/ipmac_bind_ctrl.o 

CPP_DEPS += \
./policys/IPMAC_BIND_CTRL/ipmac_bind_ctrl.d 


# Each subdirectory must supply rules for building sources it contributes
policys/IPMAC_BIND_CTRL/%.o: ../policys/IPMAC_BIND_CTRL/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


