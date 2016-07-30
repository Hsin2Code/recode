################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include include.mk
-include sources.mk
-include subdir.mk
-include vrvprotocol/subdir.mk
-include policys/subdir.mk
#-include policys/USER_RIGHT_AUDIT/subdir.mk
#-include policys/UDISK_ACT_CTRL/subdir.mk
#-include policys/SYSTEM_CONN_MONITOR/subdir.mk
#-include policys/SOFT_INSTALL_CTRL/subdir.mk
#-include policys/SOFT_DOWN_CTRL/subdir.mk
#-include policys/SERVICE_CTRL/subdir.mk
#-include policys/SEC_BURN_CTRL/subdir.mk
#-include policys/RUN_INFORAMTION/subdir.mk
#-include policys/PROCESS_CTRL/subdir.mk
#-include policys/POLICY_HEALTHCHECK/subdir.mk
#-include policys/POLICY_AUTO_SHUTDOWN/subdir.mk
#-include policys/ONLINE_DEAL_CTRL/subdir.mk
#-include policys/IPMAC_BIND_CTRL/subdir.mk
#-include policys/HTTP_VISITED_CTRL/subdir.mk
#-include policys/HTTP_ACCESS_CTRL/subdir.mk
#-include policys/FILE_OP_CTRL/subdir.mk
#-include policys/FILE_CHECKSUM_EDIT/subdir.mk
#-include policys/DEV_INSTALL_CTRL/subdir.mk
#-include policys/CONNECT_GATEWAY_AFFIRM/subdir.mk
#-include policys/NET_BD_CHK/subdir.mk
#-include policys/PROTOCOL_FIREWALL_CTRL/subdir.mk
#-include policys/POLICY_CLIENT_SET/subdir.mk
-include common/subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C++_DEPS)),)
-include $(C++_DEPS)
endif
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
ifneq ($(strip $(CC_DEPS)),)
-include $(CC_DEPS)
endif
ifneq ($(strip $(CPP_DEPS)),)
-include $(CPP_DEPS)
endif
ifneq ($(strip $(CXX_DEPS)),)
-include $(CXX_DEPS)
endif
ifneq ($(strip $(C_UPPER_DEPS)),)
-include $(C_UPPER_DEPS)
endif
endif

-include ../makefile.defs

SHELL=/bin/bash


CXX_FLAGS_COMP=-std=c++11 

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: mklibs EdpService

mklibs:
	@if [ -a ../lib ] ; then \
		echo "rm lib links"; \
		rm -rf ../lib; \
	fi;\
	\
	architecture=$$(uname -m); \
	system_bit=$$(getconf LONG_BIT); \
	\
	if [ $$architecture = 'x86_64' ]; then \
		ln -s ../mklibs/x86_64 ../lib; \
		echo 'Create pre compile lib link for: ' $$architecture; \
	fi; 

# Tool invocations
EdpService: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C++ Linker'
	$(CC)  -Xlinker -rpath -Xlinker ../lib, $(CXX_FLAGS_COMP) $(INC_FLAGS) -o"EdpService" $(OBJS) $(USER_OBJS) $(LIBS)
	install_name_tool -change /usr/local/lib/libzmq.4.dylib @loader_path/./.libs/libzmq.4.dylib ./EdpService
	install_name_tool -change /usr/local/lib/libfastdb.2.dylib @loader_path/./.libs/libfastdb.2.dylib ./EdpService
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(OBJS)$(C++_DEPS)$(C_DEPS)$(CC_DEPS)$(CPP_DEPS)$(EXECUTABLES)$(CXX_DEPS)$(C_UPPER_DEPS) EdpService
	-@echo ' '

.PHONY: all clean dependents
.SECONDARY:

-include ../makefile.targets
