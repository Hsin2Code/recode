#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <pwd.h>
#include "dbus_comm.h"

/*for ConsoleKit Manager*/
const char dest_console_kit[] = "org.freedesktop.ConsoleKit";
const char obj_path_ck_manager[] = "/org/freedesktop/ConsoleKit/Manager";
const char interface_ck_manager[] = "org.freedesktop.ConsoleKit.Manager";
const char method_name_get_seats[] = "GetSeats";

/*for ConsoleKit Seat*/
const char interface_seat[] = "org.freedesktop.ConsoleKit.Seat";
const char method_name_get_active_session[] = "GetActiveSession";

/*for ConsoleKit Session*/
const char interface_session[] = "org.freedesktop.ConsoleKit.Session";
const char m_get_ac_uid[] = "GetUnixUser";
const char m_get_ac_display[] = "GetX11Display";
const char m_get_is_local[] = "IsLocal";


static void filter_iter (DBusMessageIter *iter, 
        std::vector<std::string> &out_vals)
{
	do
	{
		int type = dbus_message_iter_get_arg_type (iter);

		if (type == DBUS_TYPE_INVALID)
			break;

		switch (type)
		{
			case DBUS_TYPE_STRING:
				{
					char *val;
					dbus_message_iter_get_basic (iter, &val);
					out_vals.push_back(val);
					break;
				}

			case DBUS_TYPE_SIGNATURE:
				{
					char *val;
					dbus_message_iter_get_basic (iter, &val);
					out_vals.push_back(val);
					break;
				}

			case DBUS_TYPE_OBJECT_PATH:
				{
					char *val;
					dbus_message_iter_get_basic (iter, &val);
					out_vals.push_back(val);
					break;
				}

			case DBUS_TYPE_INT16:
				{
					dbus_int16_t val;
					char buf[32] = {0};
					dbus_message_iter_get_basic (iter, &val);
					sprintf(buf, "%d", val);
					out_vals.push_back(buf);
					break;
				}

			case DBUS_TYPE_UINT16:
				{
					dbus_uint16_t val;
					dbus_message_iter_get_basic (iter, &val);
					char buf[32] = {0};
					sprintf(buf, "%u", val);
					out_vals.push_back(buf);
					break;
				}

			case DBUS_TYPE_INT32:
				{
					dbus_int32_t val;
					dbus_message_iter_get_basic (iter, &val);
					char buf[32] = {0};
					sprintf(buf, "%d", val);
					out_vals.push_back(buf);
					break;
				}

			case DBUS_TYPE_UINT32:
				{
					dbus_uint32_t val;
					dbus_message_iter_get_basic (iter, &val);
					char buf[32] = {0};
					sprintf(buf, "%u", val);
					out_vals.push_back(buf);
					break;
				}

			case DBUS_TYPE_INT64:
				{
					dbus_int64_t val;
					dbus_message_iter_get_basic (iter, &val);
					char buf[32] = {0};
					sprintf(buf, "%lld", val);
					out_vals.push_back(buf);
					break;
				}

			case DBUS_TYPE_UINT64:
				{
					dbus_uint64_t val;
					dbus_message_iter_get_basic (iter, &val);
					char buf[32] = {0};
					sprintf(buf, "%llu", val);
					out_vals.push_back(buf);
					break;
				}

			case DBUS_TYPE_DOUBLE:
				{
					double val;
					dbus_message_iter_get_basic (iter, &val);
					char buf[32] = {0};
					sprintf(buf, "%g", val);
					out_vals.push_back(buf);
					break;
				}

			case DBUS_TYPE_BYTE:
				{
					unsigned char val;
					dbus_message_iter_get_basic (iter, &val);
					char buf[32] = {0};
					sprintf(buf, "%d", val);
					out_vals.push_back(buf);
					break;
				}

			case DBUS_TYPE_BOOLEAN:
				{
					dbus_bool_t val;
					dbus_message_iter_get_basic (iter, &val);
					out_vals.push_back( val ? "true" : "false");
					break;
				}

			case DBUS_TYPE_VARIANT:
				{
					DBusMessageIter subiter;

					dbus_message_iter_recurse (iter, &subiter);

					filter_iter (&subiter, out_vals);
					break;
				}
			case DBUS_TYPE_ARRAY:
				{
					int current_type;
					DBusMessageIter subiter;

					dbus_message_iter_recurse (iter, &subiter);

					while ((current_type = dbus_message_iter_get_arg_type (&subiter)) != DBUS_TYPE_INVALID)
					{
						filter_iter (&subiter, out_vals);
						dbus_message_iter_next (&subiter);
					}
					break;
				}
			case DBUS_TYPE_DICT_ENTRY:
				{
					DBusMessageIter subiter;

					dbus_message_iter_recurse (iter, &subiter);

					filter_iter (&subiter, out_vals);
					dbus_message_iter_next (&subiter);
					filter_iter (&subiter, out_vals);
					break;
				}

			case DBUS_TYPE_STRUCT:
				{
					int current_type;
					DBusMessageIter subiter;

					dbus_message_iter_recurse (iter, &subiter);

					while ((current_type = dbus_message_iter_get_arg_type (&subiter)) != DBUS_TYPE_INVALID)
					{
						filter_iter (&subiter, out_vals);
						dbus_message_iter_next (&subiter);
					}
					break;
				}

			default:
				break;
		}
	} while (dbus_message_iter_next (iter));
}

	void
filter_message (DBusMessage *message, std::vector<std::string> &out_vals)
{
	int message_type = dbus_message_get_type (message);
	if(message_type != DBUS_MESSAGE_TYPE_METHOD_RETURN) {
		return;
	}
	DBusMessageIter iter;
	const char *sender;
	const char *destination;
	sender = dbus_message_get_sender (message);
	destination = dbus_message_get_destination (message);

	dbus_message_iter_init (message, &iter);
	filter_iter (&iter, out_vals);
}

bool query(const char *dest, const char * interface, 
		const char *obj_path, const char *method_name, const char* param, 
		std::vector<std::string> &out_vals)
{
    (void)(param);
	if(dest == NULL || interface == NULL || obj_path == NULL) {
		return false;
	}
    bool t_ret = true;
	DBusMessage* msg = NULL;
	DBusConnection* conn = NULL;
	DBusError err;
	DBusPendingCall* pending = NULL;

	//printf("Calling remote method with %s\n", param);

	// initialiset the errors
	dbus_error_init(&err);

	// connect to the system bus and check for errors
	conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
	if (dbus_error_is_set(&err)) { 
		fprintf(stderr, "Connection Error (%s)\n", err.message); 
        t_ret = false;
        goto out;
	}
	if (NULL == conn) { 
        t_ret = false;
        goto out;
	}

	// create a new method call and check for errors
	msg = dbus_message_new_method_call(dest, // target for the method call
			obj_path, // object to call on
			interface, // interface to call on
			method_name); // method name
	if (NULL == msg) { 
		fprintf(stderr, "Message Null\n");
        t_ret = false;
        goto out;
	}

	// send message and get a handle for a reply
	if (!dbus_connection_send_with_reply (conn, msg, &pending, 5000)) { // -1 is default timeout
		fprintf(stderr, "Out Of Memory!\n"); 
        t_ret = false;
        goto out;
	}
	if (NULL == pending) { 
		fprintf(stderr, "Pending Call Null\n"); 
        t_ret = false;
        goto out;
	}
	dbus_connection_flush(conn);
	// free message
	dbus_message_unref(msg);
    msg = NULL;

	// block until we recieve a reply
	dbus_pending_call_block(pending);

	// get the reply message
	msg = dbus_pending_call_steal_reply(pending);
	if (NULL == msg) {
		fprintf(stderr, "Reply Null\n"); 
        t_ret = false;
        goto out;
	}
	// free the pending message handle
	dbus_pending_call_unref(pending);
    pending = NULL;

	filter_message(msg, out_vals);

out:
    dbus_error_free(&err);
    // free reply and close connection
    if(pending) {
        dbus_pending_call_unref(pending);
        pending = NULL;
    }
    if(msg) {
        dbus_message_unref(msg);   
        msg = NULL;
    }
    //dbus_connection_close(conn);
    if(conn) {
        dbus_connection_unref(conn);
        conn = NULL;
    }
    return t_ret;
}

/*
void dump(const char *name, const std::vector<std::string> &vec) {
	std::vector<std::string>::const_iterator iter = vec.begin();
	for(;iter != vec.end(); iter++) {
		std::cout << "name: " << name 
			<<" val: " << (*iter) << std::endl;
	}
}
*/

bool get_active_user_info(std::vector<active_user_info_t> &uinfo) {
    bool ret_val = true;
    std::vector<std::string> seats;
    if(!(ret_val = query(dest_console_kit, interface_ck_manager, 
            obj_path_ck_manager, method_name_get_seats, NULL, seats))) {
        return ret_val;
    }
    ret_val = seats.empty() ? false : true;
    if(!ret_val) {
        return ret_val;
    }

    uinfo.clear();
    for(size_t i = 0; i < seats.size(); i++) {
		std::vector<std::string> sessions;
		if(!query(dest_console_kit, interface_seat, 
				seats.at(i).c_str(), method_name_get_active_session, NULL, sessions)) {
            continue;
        }
        if(sessions.empty()) {
            continue;
        }

        for(size_t j = 0; j < sessions.size(); j++) {
            std::vector<std::string> is_locals;
            std::vector<std::string> ac_uids;
            std::vector<std::string> ac_uid_disps;

            (void)query(dest_console_kit, interface_session, 
                    sessions.at(j).c_str(), m_get_is_local, NULL, is_locals);

            if(!(query(dest_console_kit, interface_session, 
                    sessions.at(j).c_str(), m_get_ac_uid, NULL, ac_uids) && 
                query(dest_console_kit, interface_session, 
                    sessions.at(j).c_str(), m_get_ac_display, NULL, ac_uid_disps))) {
                continue;
            }

            /*must be one*/
            active_user_info_t tmp_info;
            if(is_locals.size() == 1) {
                tmp_info.is_local = is_locals.at(0) == "true" ? 1 :
                    is_locals.at(0) == "false" ? 0 : -1;
            } 
            struct passwd *pwd = NULL;
            if(ac_uids.size() == 1) {
                tmp_info.uid = atoi(ac_uids.at(0).c_str());
                pwd = getpwuid(atoi(ac_uids.at(0).c_str()));
            }
            if(ac_uid_disps.size() == 1) {
                tmp_info.display_no = ac_uid_disps.at(0);
            }
            if(pwd != NULL) {
                tmp_info.user_name.append(pwd->pw_name == NULL ? "" : pwd->pw_name);
                tmp_info.home_dir.append(pwd->pw_dir == NULL ? "" : pwd->pw_dir);
            }

            //dump("is_locals", is_locals);
            //dump("ac_uid", ac_uids);
            //dump("ac_uid_disps", ac_uid_disps);
            /*skip the gdm Manager
             *May be has other user to skip but we can't find it out this time*/
            if(tmp_info.user_name == "gdm") {
                continue;
            }
            uinfo.push_back(tmp_info);
        }
    }
    if(uinfo.empty()) {
        return false;
    }
    return true;
}

