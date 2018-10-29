
#include "StdAfx.h"
#include "HttpServerMongo.h"
#include <unordered_map>
#include <windows.h>


bool HttpServerMongo::stopServer = false;

static const char *s_ssl_cert = "server.pem";
static const char *s_ssl_key = "server.key";



static mg_serve_http_opts opts;
//boolean stop_webserver = false;

bool verify_cookie(mg_str *cookie)
{
	if (cookie != nullptr)
	{
		char *buffer = new char[cookie->len + 1];
		//mg_http_parse_header2(cookie, "-http-session-", &buffer, cookie->len);
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


class WebConfig
{
public:
	WebConfig()
	{
	
		m_nWebThreadCount = 10;
		document_root = "d:\\hlstest\\test";
	}
	~WebConfig() {}

	std::string GetPorts()
	{
		return m_sPorts;
	}

	int GetThreadCount()
	{
		return m_nWebThreadCount;
	}

	const char * GetRoot()
	{
		return document_root;
	}

	bool ParseFile(const std::string& sxml)
	{
		m_sPorts = "8443";


		std::vector<std::string> cpp_options;
		cpp_options.push_back("listening_ports");
		cpp_options.push_back(m_sPorts);
		cpp_options.push_back("num_threads");
		cpp_options.push_back("5");
		m_arOptions = cpp_options;
		return true;
	}

	std::vector<std::string> GetOptions()
	{
		return m_arOptions;
	}



public:
	int m_nWebThreadCount;
	std::string m_sPorts;
	const char * document_root;
	std::vector<std::string> m_arOptions;
};


WebConfig cfg;

//class WebServer
//{
//private:
//	//CAxLock mapLock_;
//	std::unordered_map<std::string, const char *> mapUser_;
//
//	struct http_message *hm = NULL;
//public:
//	WebConfig cfg_;
//
//public:
//
//	bool IsAuth(struct mg_connection *conn, void *ev_data)
//	{
//		http_message *http_msg = reinterpret_cast<http_message *>(ev_data);
//		mg_str *sCookie = mg_get_http_header(http_msg, "Cookie");
//		if (!verify_cookie(sCookie))
//		{
//			return false;
//		}
//		return IsAuth(sCookie);
//	}
//
//	bool IsAuth(mg_str * sCookie)
//	{
//		//CAxLock::Owner lockscope(mapLock_);
//		if (mapUser_.find(std::string(sCookie->p)) == mapUser_.end())
//		{
//			return false;
//		}
//		return true;
//	}
//	bool AddAuth(struct mg_connection *conn, const std::string& sUser, void *ev_data)
//	{
//		mg_send_head(conn, 200, 0, "Content-Type: text/plain\r\nSet-Cookie: -http-session-=3::http.session::d89568f0f5b37035fa4a6924d99b24d9; path=/; domain=192.168.70.224; httponly");
//		http_message *http_msg = reinterpret_cast<http_message *>(ev_data);
//		mg_str *sCookie = mg_get_http_header(http_msg, "Cookie");
//		if (!verify_cookie(sCookie))
//		{
//			return false;
//		}
//		const char * User = sUser.c_str();
//		return AddAuth(sCookie, User);
//	}
//	bool AddAuth(mg_str * sCookie, const std::string& sUser)
//	{
//		//CAxLock::Owner lockscope(mapLock_);
//		const char * User = sUser.c_str();
//		mapUser_.emplace((std::string(sCookie->p)), User);
//		return true;
//	}
//	bool RemoveAuth(struct mg_connection *conn, void *ev_data)
//	{
//		http_message *http_msg = reinterpret_cast<http_message *>(ev_data);
//		mg_str *sCookie = mg_get_http_header(http_msg, "Cookie");
//		if (!verify_cookie(sCookie))
//		{
//			return false;
//		}
//		return RemoveAuth(sCookie);
//	}
//
//	bool RemoveAuth(mg_str * sCookie)
//	{
//		//CAxLock::Owner lockscope(mapLock_);
//		auto it = mapUser_.find((std::string(sCookie->p)));
//		if (it != mapUser_.end())
//		{
//			mapUser_.erase(it);
//		}
//		return true;
//	}
//
//	const char * GetAuthUser(struct mg_connection *conn, void *ev_data)
//	{
//		http_message *http_msg = reinterpret_cast<http_message *>(ev_data);
//		mg_str *sCookie = mg_get_http_header(http_msg, "Cookie");
//		char *buffer = new char[sCookie->len + 1];
//		//mg_http_parse_header2(sCookie, "-http-session-", &buffer, sCookie->len);
//		mg_str val = mg_mk_str(buffer);
//
//		if (mg_vcmp(&val, "3::http.session::d89568f0f5b37035fa4a6924d99b24d9") == 0)
//		{
//			//delete[] buffer;
//			return  buffer;
//		}
//		else
//			/*if (!verify_cookie(sCookie))
//			{
//			printf("!verify_cookie");
//			return "";
//			}*/
//			//CAxLock::Owner lockscope(mapLock_);
//			printf("cookie is %s\n", (*sCookie).p);
//		std::unordered_map<std::string, const char *>::iterator it = mapUser_.find((*sCookie).p);
//		//printf("key :%s ", it->first);
//		if (it != mapUser_.end())
//		{
//			return it->second;
//		}
//		printf("not found");
//		return "";
//	}
//
//};




static void LoginHandler(struct mg_connection *conn, int ev, void *ev_data) {


	http_message *http_msg = reinterpret_cast<http_message *>(ev_data);
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



static void LogoutHandler(struct mg_connection *conn, int ev, void *p) {

	mg_http_send_redirect(conn, 302, mg_mk_str("/public/login.html"), mg_mk_str(nullptr));
	mg_str response = mg_mk_str("admin");
	mg_send_head(conn, 200, response.len, "");
	//mg_printf(conn, "%.*s", response.len, response.p);
}
static void GetLoginUserHandler(struct mg_connection *conn, int ev, void *ev_data) {
	
	mg_str response = mg_mk_str("admin");
	mg_send_head(conn, 200, response.len, "");
	//	mg_printf(conn, "%.*s", response.len, response.p);
}

static void ActionMonitorHandler(struct mg_connection *conn, int ev, void *ev_data) {
	mg_str response = mg_mk_str("admin");
	mg_send_head(conn, 200, response.len, "");

}


static void DoActionHandler(struct mg_connection *conn, int ev, void *ev_data) {
	mg_str response = mg_mk_str("admin");
	mg_send_head(conn, 200, response.len, "");
}

HttpServerMongo::~HttpServerMongo()
{
	mg_mgr_free(&mgr);

}

void HttpServerMongo::ev_handler(mg_connection *conn, int ev, void *ev_data) {
	
	switch (ev)
	{
	case MG_EV_HTTP_REQUEST:
	{
						  			
		http_message *http_msg = reinterpret_cast<http_message *>(ev_data);
		if (mg_vcmp(&http_msg->uri, "/") == 0)
		{			
			mg_http_send_redirect(conn, 301, mg_mk_str("/public/login.html"), mg_mk_str(nullptr));		
		}

		memset(&opts, 0, sizeof(opts));
		
		// serve the static file from local store
		opts.document_root = cfg.GetRoot();
		mg_serve_http(conn, http_msg, opts);
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


bool HttpServerMongo::Start(const std::string& sxml)
{
	struct mg_bind_opts bind_opts;
	const char *err;
	memset(&bind_opts, 0, sizeof(bind_opts));
	bind_opts.ssl_cert = s_ssl_cert;
	bind_opts.ssl_key = s_ssl_key;
	bind_opts.error_string = &err;
	stopServer = false;

	WebConfig cfg;
	if (cfg.ParseFile(sxml) == false)
	{
		printf("failed to start http server, parse config failed %s", sxml.c_str());
		return false;
	}
	
	mg_mgr_init(&mgr, nullptr);

	conn = mg_bind_opt(&mgr, cfg.GetPorts().c_str(), ev_handler, bind_opts);//https
	//conn = mg_bind(&mgr, cfg.GetPorts().c_str(), ev_handler); //http

	if (conn != NULL)
		printf("start web server at port %s.", cfg.GetPorts().c_str());
	else
		printf("Failed to create listener: %s\n", err);

	mg_set_protocol_http_websocket(conn);

	mg_register_http_endpoint(conn, "/logout", LogoutHandler);
	mg_register_http_endpoint(conn, "/action/login", LoginHandler);
	mg_register_http_endpoint(conn, "/action/getLoginUser", GetLoginUserHandler);
	mg_register_http_endpoint(conn, "/action/actionMonitor", ActionMonitorHandler);
	mg_register_http_endpoint(conn, "/action/getstate", DoActionHandler);
	mg_register_http_endpoint(conn, "/action/corsSync", DoActionHandler);
	mg_register_http_endpoint(conn, "/action/corsAsync", DoActionHandler);


	while (!stopServer)
	{

		mg_mgr_poll(&mgr, 1000);

	}



	return true;
}



void  HttpServerMongo::Stop()
{

	stopServer = true;
	mg_mgr_free(&mgr);
	conn = NULL;
	delete conn;
}

	