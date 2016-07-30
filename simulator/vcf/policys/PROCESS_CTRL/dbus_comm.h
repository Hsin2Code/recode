#ifndef DBUS_COMM_PROCESS_CTL_H
#define DBUS_COMM_PROCESS_CTL_H
#include <vector>
#include <string>
#include "dbus/dbus.h"
#include "../../common/Commonfunc.h"

using namespace YCommonTool;

enum {
    LOCAL_SESSION = 1,
    NON_LOCAL_SESSION = 2
};

#if 0
typedef struct active_user_info {
    std::string user_name;
    std::string home_dir;
    std::string display_no;
    int is_local;
    int uid;
    active_user_info() {
        user_name = "", home_dir = "", display_no = "";
        is_local = -1, uid = -1;
    }
} active_user_info_t;
#endif

/*for ConsoleKit Manager*/
extern const char dest_console_kit[];
extern const char obj_path_ck_manager[];
extern const char interface_ck_manager[];
extern const char method_name_get_seats[];

/*for ConsoleKit Seat*/
extern const char interface_seat[];
extern const char method_name_get_active_session[];

/*for ConsoleKit Session*/
extern const char interface_session[];
extern const char m_get_ac_uid[];
extern const char m_get_ac_display[];
extern const char m_get_is_local[];

bool query(const char *dest, const char * interface, 
		const char *obj_path, const char *method_name, const char* param, 
		std::vector<std::string> &out_vals);

//void dump(const char *name, const std::vector<std::string> &vec);

bool get_active_user_info(std::vector<active_user_info_t> &uinfo);

#endif
