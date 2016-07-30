################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../policys/policysExport.o 

CPP_SRCS += \
../policys/policysExport.cpp 

OBJS += \
./policys/policysExport.o 

CPP_DEPS += \
./policys/policysExport.d 

#PCAP_INC := ../include/pcap-1.0/
#DBUS_INC := ../include/dbus_misc/dbus-1.0/
#DBUS_INC_PATL_DEPS := ../include/dbus_misc/plat_deps/
#INC_FLAGS := -I$(PCAP_INC) -I$(DBUS_INC) -I$(DBUS_INC_PATL_DEPS)

# Each subdirectory must supply rules for building sources it contributes
policys/%.o: ../policys/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	$(CC) -O3 -Wall -c $(INC_FLAGS) \
		-fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


