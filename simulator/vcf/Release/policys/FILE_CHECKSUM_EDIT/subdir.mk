################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../policys/FILE_CHECKSUM_EDIT/file_checksum_edit.cpp 

OBJS += \
./policys/FILE_CHECKSUM_EDIT/file_checksum_edit.o 

CPP_DEPS += \
./policys/FILE_CHECKSUM_EDIT/file_checksum_edit.d 


# Each subdirectory must supply rules for building sources it contributes
policys/FILE_CHECKSUM_EDIT/%.o: ../policys/FILE_CHECKSUM_EDIT/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


