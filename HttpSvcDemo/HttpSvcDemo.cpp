// HttpSvcDemo.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "mongoose.h"

#include <condition_variable>
#include <iostream>
#include <thread>
#include <string>
#include <chrono>
#include <random>
#include <atomic>
#include <deque>
#include <mutex>


struct Task
{
    uint64_t conn_id = 0;
};


mg_str g_state = mg_mk_str("{ \
            \"code\": 1, \
            \"log_file_location\": {}, \
            \"note\": \"ok\", \
            \"records\": [ \
                { \
                    \"all_proc\": 0, \
                    \"extend_info\": \"null\\n\", \
                    \"logs\": null, \
                    \"online_client\": 0, \
                    \"online_debug\": false, \
                    \"proc_speed\": 0, \
                    \"stats\": null, \
                    \"status_alert\": false, \
                    \"status_run\": false, \
                    \"svc_name\": \"a5_sc_qsrc_1\", \
                    \"svc_region\": \"a5_sc_qsrc\", \
                    \"unproc\": 0, \
                    \"uptime\": \"\", \
                    \"version\": \"\" \
                }, \
                { \
                    \"all_proc\": 0, \
                    \"extend_info\": \"null\\n\", \
                    \"logs\": null, \
                    \"online_client\": 0, \
                    \"online_debug\": false, \
                    \"proc_speed\": 0, \
                    \"stats\": null, \
                    \"status_alert\": false, \
                    \"status_run\": false, \
                    \"svc_name\": \"a5_sc_exquote_1\", \
                    \"svc_region\": \"a5_sc_exquote\", \
                    \"unproc\": 0, \
                    \"uptime\": \"\", \
                    \"version\": \"\" \
                } \
            ], \
            \"serverInfo\": { \
                \"CPU\": 0, \
                \"DiskFree\": 0, \
                \"DiskTotal\": 0, \
                \"DownSpeed\": 0, \
                \"MemFree\": 0, \
                \"MemTotal\": 0, \
                \"MemUsedPercent\": 0, \
                \"UpSpeed\": 0 \
            }, \
            \"serverTime\": \"20180619 10:08:53.250\", \
            \"stat_file_location\": {} \
        }");


std::mutex g_q_mutex;
std::deque<Task> g_queue;
std::atomic_int g_rest_num;
std::condition_variable g_w_cond, g_q_cond;


Task take_task()
{
    std::lock_guard<std::mutex> lock(g_q_mutex);

    if (g_queue.empty())
    {
        return Task();
    }

    Task task = g_queue.front();
    g_queue.pop_front();
    return task;
}


void spend_large_time(int id)
{
    std::random_device r_dev;
    std::default_random_engine engine(r_dev());
    std::uniform_int_distribution<> dis(0, 10000);

    int sleep_time = dis(engine);
    std::cout << "[thread " << id << "] sleep time: " << sleep_time << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(sleep_time));
}


static void worker_ev_handler(mg_connection *conn, int ev, void *ev_data)
{
    for (auto c = mg_next(conn->mgr, nullptr); c != nullptr; c = mg_next(conn->mgr, c))
    {
        if (c->user_data != nullptr)
        {
            Task *task = reinterpret_cast<Task *>(ev_data);
            uint64_t *res_conn_id = reinterpret_cast<uint64_t *>(c->user_data);

            if (task->conn_id == *res_conn_id)
            {
                std::cout << "[response] conn id: " << std::to_string(task->conn_id) << std::endl;

                mg_send_head(c, 200, g_state.len, "");
                mg_printf(c, "%.*s", g_state.len, g_state.p);

                delete c->user_data;
                c->user_data = nullptr;
            }
        }
    }
}


void worker_func(int id, mg_mgr *mgr)
{
    while (true)
    {
        std::mutex mutex;
        std::unique_lock<std::mutex> lock(mutex);

        // wait for rest task
        g_w_cond.wait(lock, []() {
            return !g_queue.empty();
        });

        // sub the rest thread num
        g_rest_num.fetch_sub(1, std::memory_order_acq_rel);

        std::cout << "[thread " << id << "] get task" << std::endl;
        Task task = take_task();

        if (task.conn_id == 0)
        {
            // task queue is empty, and the rest of task is held by other thread
            // add the rest thread num
            g_rest_num.fetch_add(1, std::memory_order_acq_rel);
            std::cout << "[thread " << id << "] get null task" << std::endl;
            continue;
        }

        // call the sleep func
        spend_large_time(id);

        // add the rest thread num
        g_rest_num.fetch_add(1, std::memory_order_acq_rel);
        std::cout << "[thread " << id << "] rest" << std::endl;
        g_q_cond.notify_one();

        mg_broadcast(mgr, worker_ev_handler, reinterpret_cast<void *>(&task), sizeof(task));
    }
}


bool verify_cookie(mg_str *cookie)
{
    if (cookie != nullptr)
    {
        char *buffer = new char[cookie->len + 1];
        mg_http_parse_header2(cookie, "-http-session-", &buffer, cookie->len);
        mg_str val = mg_mk_str(buffer);

        if (mg_vcmp(&val, "3::http.session::d89568f0f5b37035fa4a6924d99b24d9") == 0)
        {
            delete[] buffer;
            return true;
        }
        else
        {
            delete[] buffer;
            return false;
        }
    }

    return false;
}


static void ev_handler(mg_connection *conn, int ev, void *ev_data)
{
    switch (ev)
    {
    case MG_EV_HTTP_REQUEST:
    {
        http_message *http_msg = reinterpret_cast<http_message *>(ev_data);

        if (mg_vcmp(&http_msg->method, "GET") == 0)
        {
			 if (mg_vcmp(&http_msg->uri, "/") == 0)
            {
                mg_str *cookie = mg_get_http_header(http_msg, "Cookie");

                if (verify_cookie(cookie))
                {
                    // has cookie
                    // redirect to '/index.html'
                    mg_http_send_redirect(conn, 301, mg_mk_str("/index.html"), mg_mk_str(nullptr));
                }
                else
                {
                    // not cookie
                    // redirect to '/public/login.html'
                    mg_http_send_redirect(conn, 301, mg_mk_str("/public/login.html"), mg_mk_str(nullptr));
                }
            }
            else if (mg_vcmp(&http_msg->uri, "/logout") == 0)
            {
				mg_str response = mg_mk_str("admin");
				mg_send_head(conn, 200, response.len, "");
				mg_printf(conn, "%.*s", response.len, response.p);
                mg_http_send_redirect(conn, 302, mg_mk_str("/public/login.html"), mg_mk_str(nullptr));
            }
			else if (mg_vcmp(&http_msg->uri, "/action/getLoginUser") == 0)
			{



				mg_str response = mg_mk_str("admin");
				mg_send_head(conn, 200, response.len, "");
				mg_printf(conn, "%.*s", response.len, response.p);




			}
            else
            {
                mg_serve_http_opts opts;
                memset(&opts, 0, sizeof(opts));

                // serve the static file from local store
                opts.document_root = "d:\\hlstest\\test";
                mg_serve_http(conn, http_msg, opts);
            }
        }
        else if (mg_vcmp(&http_msg->method, "POST") == 0)
        {
            if (mg_vcmp(&http_msg->uri, "/action/login") == 0)
            {
                size_t max_len = http_msg->body.len;
                char *buffer = new char[max_len];

                memset(buffer, 0, max_len);
                std::string username, password;

                if (mg_get_http_var(&http_msg->body, "username", buffer, max_len) > 0)
                {
                    username = buffer;
                }

                memset(buffer, 0, max_len);

                if (mg_get_http_var(&http_msg->body, "password", buffer, max_len) > 0)
                {
                    password = buffer;
                }

                delete[] buffer;

                if (username == "admin" && password == "000000")
                {
                    mg_send_head(conn, 200, 0, "Content-Type: text/plain\r\nSet-Cookie: -http-session-=3::http.session::d89568f0f5b37035fa4a6924d99b24d9; path=/; domain=192.168.70.224; httponly");
					mg_str response = mg_mk_str("admin");

					mg_send_head(conn, 200, response.len, "");
					mg_printf(conn, "%.*s", response.len, response.p);
				}
            }
			else if (mg_vcmp(&http_msg->uri, "/action/getLoginUser") == 0)
			{



				mg_str response = mg_mk_str("admin");
				mg_send_head(conn, 200, response.len, "");
				mg_printf(conn, "%.*s", response.len, response.p);




			}
            else if (mg_vcmp(&http_msg->uri, "/action/actionMonitor") == 0)
            {
                mg_str *cookie = mg_get_http_header(http_msg, "Cookie");

             
                    mg_str response = mg_mk_str("admin");

                    mg_send_head(conn, 200, response.len, "");
				    mg_printf(conn, "%.*s", response.len, response.p);
                
            }
            else if (mg_vcmp(&http_msg->uri, "/action/corsSync") == 0)
            {
                // cors

                mg_send_head(conn, 200, 0, "Access-Control-Allow-Origin: *");

				mg_str response = mg_mk_str("admin");
				mg_send_head(conn, 200, response.len, "");
				mg_printf(conn, "%.*s", response.len, response.p);
            }
            else if (mg_vcmp(&http_msg->uri, "/action/getstate") == 0)
            {
                mg_str *cookie = mg_get_http_header(http_msg, "Cookie");

                if (verify_cookie(cookie))
                {
                    //std::cout << "[info] rest thread num: " << g_rest_num << std::endl;

                    //std::mutex mutex;
                    //std::unique_lock<std::mutex> lock(mutex);
                    //g_q_cond.wait(lock, []() {
                    //    return g_rest_num != 0;
                    //});

                    //std::lock_guard<std::mutex> q_lock(g_q_mutex);

                    //// use the 'conn' pointer value to be 'conn_id'
                    //uint64_t *conn_id = new uint64_t(reinterpret_cast<uint64_t>(conn));
                    //conn->user_data = reinterpret_cast<void *>(conn_id);

                    //std::cout << "[request] conn id: " << std::to_string(*conn_id) << std::endl;

                    //Task task = { *conn_id };
                    //g_queue.push_back(task);

                    //std::cout << "[info] queue elem num: " << g_queue.size() << std::endl;
                    //g_w_cond.notify_one();

                    mg_send_head(conn, 200, g_state.len, "");
                    mg_printf(conn, "%.*s", g_state.len, g_state.p);
                }
            }
        }
        break;
    }
    case MG_EV_CLOSE:
    {
        if (conn->user_data != nullptr)
        {
            delete conn->user_data;
            conn->user_data = nullptr;
        }
        break;
    }
    }
}


int main()
{
    mg_mgr mgr;
    mg_connection *conn;

    g_rest_num = 100;
    std::thread *t[100];

    for (int i = 0; i < g_rest_num; ++i)
    {
        t[i] = new std::thread(std::bind(&worker_func, i, &mgr));
    }

    mg_mgr_init(&mgr, nullptr);
    
    conn = mg_bind(&mgr, "8080", ev_handler);
    mg_set_protocol_http_websocket(conn);

    while (true)
    {
        mg_mgr_poll(&mgr, 1000);
    }

    mg_mgr_free(&mgr);
    return 0;
}

