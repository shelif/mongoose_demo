#ifndef __HTTPSERVERMONGO_H__
#define __HTTPSERVERMONGO_H__
#include <string>
#include "mongoose.h"
#include <iostream>
#include <thread>
class HttpServerMongo
{
public:

	~HttpServerMongo();
	bool Start(const std::string& sxml);	
	static bool stopServer;
	void Stop();
private:

	mg_connection *conn;
	mg_mgr mgr;
	static void ev_handler(mg_connection *conn, int ev, void *ev_data);
};

#endif // __HTTPSERVERMONGO_H__