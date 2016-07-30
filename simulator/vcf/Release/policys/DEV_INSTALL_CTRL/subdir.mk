################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../policys/DEV_INSTALL_CTRL/dev_install_ctrl.o 

CPP_SRCS += \
../policys/DEV_INSTALL_CTRL/dev_install_ctrl.cpp 

OBJS += \
./policys/DEV_INSTALL_CTRL/dev_install_ctrl.o 

CPP_DEPS += \
./policys/DEV_INSTALL_CTRL/dev_install_ctrl.d 


# Each subdirectory must supply rules for building sources it contributes
policys/DEV_INSTALL_CTRL/%.o: ../policys/DEV_INSTALL_CTRL/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


