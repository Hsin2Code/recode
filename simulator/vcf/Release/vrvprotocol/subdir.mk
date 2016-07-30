################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../vrvprotocol/VrvProtocol.cpp 

OBJS += \
./vrvprotocol/VrvProtocol.o 

CPP_DEPS += \
./vrvprotocol/VrvProtocol.d 


# Each subdirectory must supply rules for building sources it contributes
vrvprotocol/%.o: ../vrvprotocol/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	$(CC) -O3 -Wall -c -fmessage-length=0 $(INC_FLAGS) -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


