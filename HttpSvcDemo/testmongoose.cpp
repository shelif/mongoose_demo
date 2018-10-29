#include "stdafx.h"
#include "HttpServerMongo.h"



void  stop(HttpServerMongo * websvr)
{
	printf("press any key to exit...\n");
	getchar();
	websvr->Stop();
}

int main()
{
	HttpServerMongo *websvr = new HttpServerMongo();
	std::thread thread_stop(stop, websvr);
	printf("start web server %s \n", websvr->Start("web.xml") ? "Ok" : "Failed");
	thread_stop.join();
	getchar();
	delete websvr;
	return 0;
}

