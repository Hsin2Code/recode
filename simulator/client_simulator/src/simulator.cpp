#include <iostream>
#include <sys/types.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/stat.h>
#include "common.h"
#include "regesiter.h"
#include "pull_policy.h"
#include "SimpleIni.h"
#include "send_thread.h"

using namespace std;
#define UNUSED(x) (void)(x)

static bool quit_flags = false;
static pthread_t hb_thr = 0;
static pthread_t pull_policy_thr = 0;
static pthread_t send_thr = 0;
static int toggle_report_assert = 1;
static int random_wait_sec = -1;

void sig_action(int sig_no) {
    UNUSED(sig_no);
    SM_LOG() << " quit and clean and close file";
    struct stat buf;
    lstat("./reports", &buf);
    if(!((buf.st_mode & S_IFMT) == S_IFDIR)) {
        mkdir("./reports", S_IRWXU | S_IRWXG | S_IRWXO);
    }
    std::string report_ini = "./reports/report_" + g_dev_id + ".ini";
    unlink(report_ini.c_str());
	CSimpleIniA ini;
    ini.LoadFile(report_ini.c_str());
	ini.SetUnicode();
    char _buf[128] = {0};
    sprintf(_buf, "%d", policy_pull_success_times);
	ini.SetValue("policy", "pull_success", _buf);
    sprintf(_buf, "%d", policy_pull_falied_times);
    ini.SetValue("policy", "pull_failed", _buf);
    sprintf(_buf, "%d", policy_pull_falied_times + policy_pull_success_times);
    ini.SetValue("policy", "pull_times", _buf);

    sprintf(_buf, "%d", success_num);
	ini.SetValue("log", "send_success", _buf);
    sprintf(_buf, "%d", error_num);
	ini.SetValue("log", "send_error", _buf);
    sprintf(_buf, "%d", send_num);
	ini.SetValue("log", "total", _buf);

    ini.SaveFile(report_ini.c_str());

    SM_LOG() << "start to free software down thr";
    if(g_running_file_tid_ptr != NULL) {
        if(*g_running_file_tid_ptr != 0) {
            pthread_cancel(*g_running_file_tid_ptr);
            if(pthread_join(*g_running_file_tid_ptr, NULL) != 0) {
                SM_ERROR() << "free running file thread error";
            } else {
                SM_LOG() << "free running thread success" ;
            }
        }
    }

    SM_LOG() << "start free hb thr";
    if(hb_thr) {
        pthread_cancel(hb_thr);
        if(pthread_join(hb_thr, NULL) != 0) {
            SM_ERROR() << "free heart beat thread error ";
        }
    }

    SM_LOG() << "start free policy pull thr";
    if(pull_policy_thr) {
        pthread_cancel(pull_policy_thr);
        if(pthread_join(pull_policy_thr, NULL) != 0) {
            SM_ERROR() << "free pull policy  thread  error ";
        }
    }

    SM_LOG() << "start free send thr";
    if(send_thr) {
        pthread_cancel(send_thr);
        if(pthread_join(send_thr, NULL) != 0) {
            SM_ERROR() << "free send_thread policy  thread  error ";
        }
    }
    usleep(2000000);
    quit_flags = true;
    SM_LOG() << "quit return";
    return;
}

void usage() {
    std::cout << "usage is :" << std::endl;
    std::cout << " -t  time to run [sec]" << std::endl;
    std::cout << " -d  dev_id " << std::endl;
    std::cout << " -p  server_ip " << std::endl;
    std::cout << " -s  self ip address " << std::endl;
    std::cout << " -c  conf_file " << std::endl;
    std::cout << " -l  loging interval " << std::endl;
    std::cout << " -m  pull policy interval" << std::endl;
    std::cout << " -F  switch softdown ctl 1:on 0:off " << std::endl;
    std::cout << " -T  everytime upload logs count default to 1" << std::endl;
    std::cout << " -M  toggle software report 1" << std::endl;
    std::cout << " -R  Random wait second before start" << std::endl;
    std::cout << " -N  Audit and Report" << std::endl;

}

INITIALIZE_EASYLOGGINGPP

void init_logger() {
    el::Loggers::addFlag(el::LoggingFlag::DisableApplicationAbortOnFatalLog);
    el::Loggers::addFlag(el::LoggingFlag::ColoredTerminalOutput);
    std::string loginfo_fname = "./logs/sim_info_" + g_dev_id + ".log";
    std::string logerror_fname = "./logs/sim_error_" + g_dev_id + ".log";
    std::string log_pcontent_fname = "./logs/sim_policy_" + g_dev_id + ".log";

    el::Configurations log_info;
    el::Configurations log_error;
    el::Configurations log_policy_content;

    log_info.setGlobally(el::ConfigurationType::Filename,  loginfo_fname);
    log_error.setGlobally(el::ConfigurationType::Filename,  logerror_fname);
    log_policy_content.setGlobally(el::ConfigurationType::Filename, log_pcontent_fname);

	log_info.set(el::Level::Global,
			el::ConfigurationType::Format, "%datetime{%y-%M-%d %H:%m:%s} %level %msg");
	log_error.set(el::Level::Global,
			el::ConfigurationType::Format, "%datetime{%y-%M-%d %H:%m:%s} %level %msg");
    log_policy_content.set(el::Level::Global,
            el::ConfigurationType::Format, "%datetime{%y-%M-%d %H:%m:%s} %level %msg");

    el::Loggers::reconfigureLogger(IL, log_info);
    el::Loggers::reconfigureLogger(EL, log_error);
    el::Loggers::reconfigureLogger(PL, log_policy_content);
}


int main(int argc, char *argv[]) {
    if(argc == 1) {
        usage();
        return -1;
    }
	START_EASYLOGGINGPP(argc, argv);

    signal(SIGINT, sig_action);

	int opt;
	size_t nsecs = 0;
    g_policy_interval = 0;
    g_log_interval = 0;
    g_run_times = -1;

    std::string conf_file = "";
	while ((opt = getopt(argc, argv, "d:t:c:p:s:l:m:F:T:M:R:N:")) != -1) {
		switch (opt) {
			case 'd':
                g_dev_id.append(optarg == NULL ? "" : optarg);
                g_mac_addr.append(optarg == NULL ? "" : optarg);
				break;
            case 't':
                if(optarg) {
                    nsecs = atoi(optarg);
                }
                break;
            case 'c':
                conf_file.append(optarg == NULL ? "" : optarg);
                break;
            case 'p':
                g_server_ip.append(optarg == NULL ? "" : optarg);
                g_server_port = 88;
                break;
            case 's':
                g_self_ipaddr.append(optarg == NULL ? "" : optarg);
                break;
            case 'l':
                if(optarg) {
                    g_log_interval = atoi(optarg);
                }
                break;
            case 'm':
                if(optarg) {
                    g_policy_interval = atoi(optarg);
                }
                break;
            case 'F':
                if(optarg) {
                    g_sfd_flag = atoi(optarg);
                }
                break;
            case 'T':
                if(optarg) {
                    g_upload_log_times = atoi(optarg);
                }
                break;
            case 'M':
                if(optarg) {
                    toggle_report_assert = atoi(optarg);
                }
                break;
            case 'R':
                if(optarg) {
                    random_wait_sec = atoi(optarg);
                }
                break;
            case 'N':
                if(optarg) {
                    g_run_times = atoi(optarg);
                }
                break;
			default: /* '?' */
                usage();
				exit(EXIT_FAILURE);
		}
	}
    g_run_times = (g_run_times != -1) ? g_run_times : 10;
    nsecs = (nsecs > 10) ? nsecs : 0;
    g_policy_interval = (g_policy_interval == 0) ? 5 : g_policy_interval;
    g_log_interval = (g_log_interval == 0) ? 30 : g_log_interval;

    if(g_dev_id.empty() || g_server_ip.empty() || g_self_ipaddr.empty()) {
        std::cout << "parameter empty see usage for more info" << std::endl;
        exit(EXIT_FAILURE);
    }
    if(!g_upload_log_times) {
        g_upload_log_times = 1;
    }
    g_upload_log_times = abs(g_upload_log_times);

    init_logger();
    if(random_wait_sec != -1) {
        while(random_wait_sec >= 0) {
            SM_LOG() << "Wait for start. dev_id: " << g_dev_id << " sec: " << random_wait_sec--;
            sleep(1);
        }
    }

    SM_LOG() << "start regesite to server : " << g_server_ip ;
    {
        std::string do_reg = "do_regesiter:" + g_dev_id;
        TIMED_SCOPE(timer, do_reg.c_str());
        if(!do_regesiter(g_dev_id)) {
            SM_ERROR() << "regesiter failed";
            exit(EXIT_FAILURE);
        }
        SM_LOG() << "end regesite to server : " << g_server_ip ;
    }

    if(toggle_report_assert) {
        {
            std::string assert = "report_assert:" + g_dev_id;
            TIMED_SCOPE(timer, assert.c_str());
            SM_LOG() << "begin report assert";
            report_assert();
            SM_LOG() << "end report assert";
        }
    }

    int ret = pthread_create(&hb_thr, NULL, heart_beat_worker, NULL);
    if(ret != 0) {
        SM_ERROR() << "create heartbeat thr error";
        exit(-1);
    }
    ret = pthread_create(&pull_policy_thr, NULL, pull_policy_worker, NULL);
    if(ret != 0) {
        SM_ERROR() << "create  pull policy thread error";
        exit(-1);
    }
    ret = pthread_create(&send_thr, NULL, thread_send_msg, NULL);
    if(ret != 0) {
        SM_ERROR() << "create  send_log thread  error";
        exit(-1);
    }

    size_t count_sec = 0;
    while(1) {
        if(count_sec > nsecs && nsecs != 0) {
            kill(getpid(), SIGINT);
            count_sec = 0;
        }
        SM_LOG() << "running ...:" <<count_sec << "s ip: " << g_self_ipaddr << " devid: " << g_dev_id;
        if(quit_flags) {
            exit(0);
        } else {
            count_sec++;
        }
        usleep(1000000);
    }
    return 0;
}
