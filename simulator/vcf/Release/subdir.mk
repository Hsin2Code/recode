################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../CArpAttack.cpp \
../CAuditlogFilter.cpp \
../CDeviceinfoHelper.cpp \
../CEdpApp.cpp \
../CEventNotify.cpp \
../CIMCClient.cpp \
../CIMCSrv.cpp \
../CMyIptables.cpp \
../CNetEngine.cpp \
../CPolicyManager.cpp \
../CSoftInstallHelper.cpp \
../CVCFApp.cpp \
../CVRVNetProtocol.cpp \
../CYApp.cpp \
../CYlocaldb.cpp \
../../include/Markup.cpp \
../main.cpp \
../msgdisp.cpp \
../vrcport_tool.cpp 

OBJS += \
./CArpAttack.o \
./CAuditlogFilter.o \
./CDeviceinfoHelper.o \
./CEdpApp.o \
./CEventNotify.o \
./CIMCClient.o \
./CIMCSrv.o \
./CMyIptables.o \
./CNetEngine.o \
./CPolicyManager.o \
./CSoftInstallHelper.o \
./CVCFApp.o \
./CVRVNetProtocol.o \
./CYApp.o \
./CYlocaldb.o \
./Markup.o \
./main.o \
./msgdisp.o \
./vrcport_tool.o 

CPP_DEPS += \
./CArpAttack.d \
./CAuditlogFilter.d \
./CDeviceinfoHelper.d \
./CEdpApp.d \
./CEventNotify.d \
./CIMCClient.d \
./CIMCSrv.d \
./CMyIptables.d \
./CNetEngine.d \
./CPolicyManager.d \
./CSoftInstallHelper.d \
./CVCFApp.d \
./CVRVNetProtocol.d \
./CYApp.d \
./CYlocaldb.d \
./Markup.d \
./main.d \
./msgdisp.d \
./vrcport_tool.d 

# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	$(CC) -O3 -Wall -c $(INC_FLAGS) -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

Markup.o: ../../include/Markup.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	$(CC) -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


