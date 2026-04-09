#include <iostream>
#include <thread>
#include <chrono>
#include <getopt.h>
#include <cstdlib>
#include "Connection.h"
#include "objects.h"
#include "config.h"

using namespace std;
using namespace wpp;

// ─── Global runtime config (read by objects.cpp) ────────────────────────────
ClientConfig g_config;
// ────────────────────────────────────────────────────────────────────────────

static void printUsage(const char *prog) {
	cout << "\nUsage: " << prog << " [options]\n\n"
	     << "Options:\n"
	     << "  -u <url>      Server URL\n"
	     << "                  NoSec example : coap://myserver.com:5683\n"
	     << "                  PSK example   : coaps://myserver.com:5684\n"
	     << "  -e <name>     Endpoint / client name (default: Lwm2mClient)\n"
	     << "  -i <psk-id>   PSK identity  (only used when URL is coaps://)\n"
	     << "  -k <psk-key>  PSK secret key in HEX bytes, e.g. FF00FF\n"
	     << "                  Each byte must be two hex digits, no separators.\n"
	     << "  -p <port>     Local UDP port to bind (default: 56830)\n"
	     << "  -h            Show this help and exit\n\n"
	     << "Examples:\n"
	     << "  # No security\n"
	     << "  ./WppExample -u coap://deviosfriendlytech.com:5683 -e Navs\n\n"
	     << "  # PSK security\n"
	     << "  ./WppExample -u coaps://deviosfriendlytech.com:5684 -e Navs \\\n"
	     << "               -i FriendlyTestDevID -k FF00FF\n\n";
}

void socketPolling(Connection *connection) {
	while (!isDeviceShouldBeRebooted()) {
		connection->loop();
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
}

void wppErrorHandler(WppClient &client, int errCode) {
	cout << "wppErrorHandler(): Error: " << errCode << endl;
	if (client.getState() == STATE_BOOTSTRAPPING || client.getState() == STATE_BOOTSTRAP_REQUIRED) {
		cout << "Trying to restore security and server objects" << endl;
		Object &securityObj = Lwm2mSecurity::object(client);
		Object &serverObj = Lwm2mServer::object(client);
		#if OBJ_O_2_LWM2M_ACCESS_CONTROL
		for (auto *inst : securityObj.instances()) Lwm2mAccessControl::remove(*inst);
		for (auto *inst : serverObj.instances()) Lwm2mAccessControl::remove(*inst);
		#endif
		securityObj.clear();
		serverObj.clear();
		securityInit(client);
		serverInit(client);
	}
}

// Found Wakaama bugs:
// TODO: Device work with NON confirmation messages
int main(int argc, char *argv[]) {

	// ── Parse command-line arguments ──────────────────────────────────────
	int opt;
	while ((opt = getopt(argc, argv, "u:e:i:k:p:h")) != -1) {
		switch (opt) {
			case 'u': g_config.serverUrl    = optarg; break;
			case 'e': g_config.endpointName = optarg; break;
			case 'i': g_config.pskId        = optarg; break;
			case 'k': g_config.pskKey       = optarg; break;
			case 'p': g_config.localPort    = optarg; break;
			case 'h': printUsage(argv[0]); return 0;
			default:  printUsage(argv[0]); return 1;
		}
	}

	// Basic validation: PSK fields must both be present or both absent
	if (g_config.pskId.empty() != g_config.pskKey.empty()) {
		cerr << "[ERROR] Both -i (PSK identity) and -k (PSK key) must be "
		        "provided together.\n";
		printUsage(argv[0]);
		return 1;
	}

	// Warn if coaps:// is used without PSK credentials (or vice-versa)
	bool isSecureUrl = (g_config.serverUrl.rfind("coaps://", 0) == 0);
	bool hasPsk      = !g_config.pskId.empty();
	if (isSecureUrl && !hasPsk) {
		cerr << "[WARN] URL uses coaps:// but no PSK credentials were supplied. "
		        "DTLS handshake will likely fail.\n";
	}
	if (!isSecureUrl && hasPsk) {
		cerr << "[WARN] PSK credentials supplied but URL uses coap:// (no DTLS). "
		        "Credentials will be ignored.\n";
	}

	// Print effective config so the user can verify before connecting
	cout << "\n---- Runtime configuration ----\n"
	     << "  Server URL    : " << g_config.serverUrl    << "\n"
	     << "  Endpoint name : " << g_config.endpointName << "\n"
	     << "  PSK identity  : " << (g_config.pskId.empty()  ? "(none)" : g_config.pskId)  << "\n"
	     << "  PSK key       : " << (g_config.pskKey.empty() ? "(none)" : g_config.pskKey) << "\n"
	     << "  Local port    : " << g_config.localPort    << "\n";
	// ─────────────────────────────────────────────────────────────────────

	cout << endl << "---- Creating required components ----" << endl;
	Connection connection(g_config.localPort.c_str(), AF_INET);

	// Client initialization
	cout << endl << "---- Creating WppClient ----" << endl;
	string clientName = g_config.endpointName;
	#if DTLS_WITH_PSK
	clientName += "PSK";
	#elif DTLS_WITH_RPK
	clientName += "RPK";
	#endif
	cout << "WppClient name: " << clientName << endl;
	WppClient::create({clientName, "", ""}, connection, wppErrorHandler);
	WppClient *client = WppClient::takeOwnershipBlocking();

	// Initialize wpp objects
	#ifdef OBJ_O_2_LWM2M_ACCESS_CONTROL
	acInit(*client);
	#endif

	cout << endl << "---- Initialization wpp Server ----" << endl;
	serverInit(*client);

	cout << endl << "---- Initialization wpp Security ----" << endl;
	securityInit(*client);

	cout << endl << "---- Initialization wpp Device ----" << endl;
	deviceInit(*client);

	#ifdef OBJ_O_5_FIRMWARE_UPDATE
	cout << endl << "---- Initialization wpp FirmwareUpdate ----" << endl;
	fwUpdaterInit(*client);
	#endif

	#ifdef OBJ_O_4_CONNECTIVITY_MONITORING
	cout << endl << "---- Initialization wpp ConnectivityMonitoring ----" << endl;
	connMonitoringInit(*client);
	#endif

	#ifdef OBJ_O_3339_AUDIO_CLIP
	cout << endl << "---- Initialization wpp AudioClip ----" << endl;
	audioClipInit(*client);
	#endif

	// Giving ownership to registry
	client->giveOwnership();

	// Add tasks with send operation
	#if defined(LWM2M_SUPPORT_SENML_JSON) && RES_1_23 && RES_3_13
	WppTaskQueue::addTask(5, [](WppClient &client, void *ctx) {
		WPP_LOGD(TAG_WPP_TASK, "Task: Send operation, sending current time to the server");
		DataLink dataLink = {{OBJ_ID::DEVICE, 0}, {Device::CURRENT_TIME_13,}};
		client.send(dataLink);
		return false;
	});
	#endif

	cout << endl << "---- Starting Connection thread ----" << endl;
	thread my_thread(socketPolling, &connection);

	time_t callTime = 0;
	for (int iterationCnt = 0; !isDeviceShouldBeRebooted(); iterationCnt++) {
		time_t currTime = time(NULL);
		cout << endl << "---- iteration:" << iterationCnt << ", time: " << time(NULL) << " ----" << endl;
		if (currTime >= callTime || connection.getPacketQueueSize()) {
			// Handle client state and process packets from the server
			client = WppClient::takeOwnership();
			if (client) {
				callTime = currTime + client->loop();
				client->giveOwnership();
				cout << "Sleep time: " << callTime - time(NULL) << endl;
			}
		}
		this_thread::sleep_for(chrono::seconds(1));
	}

	cout << endl << "---- Closing example ----" << endl;
	my_thread.join();
	WppClient::remove();

	return 0;
}
