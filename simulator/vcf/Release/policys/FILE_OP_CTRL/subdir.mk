################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../policys/FILE_OP_CTRL/file_op_ctl.o 

CPP_SRCS += \
../policys/FILE_OP_CTRL/file_op_ctl.cpp 

OBJS += \
./policys/FILE_OP_CTRL/file_op_ctl.o 

CPP_DEPS += \
./policys/FILE_OP_CTRL/file_op_ctl.d 


# Each subdirectory must supply rules for building sources it contributes
policys/FILE_OP_CTRL/%.o: ../policys/FILE_OP_CTRL/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


