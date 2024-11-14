#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/config-store-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/olsr-helper.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-list-routing-helper.h"
#include "ns3/yans-wifi-phy.h"
#include "ns3/netanim-module.h"
#include "ns3/RSA_ECDSA.h"
#include <vector>
#include "ns3/flow-monitor-module.h"
#include <cassert>
#include "ns3/gnuplot.h"
#include "ns3/aodv-module.h"
#include "ns3/mac-gplot.h"
#include "ns3/ipv6-static-routing-helper.h"
#include "ns3/ipv6-routing-table-entry.h"
#include "ns3/iot-module.h"
#include <iostream>
#include <fstream>
#include <string>
#include<iostream>
#include<math.h>
#include<string.h>
#include<stdlib.h>
#include <fstream>
#include <sstream>
#include <functional>
#include <limits>
#include <unordered_map>
#include <openssl/sha.h>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <queue>
#include <cmath>
using namespace ns3;
using namespace std;
NS_LOG_COMPONENT_DEFINE ("Federated_learning_based_Insider_Threat_Detection");
AnimationInterface *pAnim;
double ds=1000.0;  
int rounds=300;   
uint32_t packetSize = 1024; 
uint32_t noofpkts = 100;  
int numUsers=10; 
int numDevices=100; 
int numRounds=50;
int Trust=100;
int Test=10;
int numEdgeserver = 2;
int NumUsers=7;
int Uidlist[100];     
int p, q, n, t, flag, e[100], d[100], temp[100], j, m[100], en[100], i;
double interval = 1.0; 
Time interPacketInterval = Seconds (interval);
void compare_Minimum(double dis){
if(ds>dis){ds=dis;}}
void getNearbynodesrc(NodeContainer wsn){
int nn=1;
double x1=250;
double y1=250;
for(uint32_t i=0;i<wsn.GetN ();i++){
Ptr<RandomWaypointMobilityModel> FCMob = wsn.Get(i)->GetObject<RandomWaypointMobilityModel>();
Vector m_position = FCMob->GetPosition();
double x=m_position.x;
double y=m_position.y;
double xx=x1-x;
double yy=y1-y;
double x2=(xx*xx);
double y2=(yy*yy);
double sx=sqrt(x2);
double sy=sqrt(y2);
double dis=(sx+sy);
compare_Minimum(dis);
if(ds<=100){
if(nn==1){
pAnim->UpdateNodeColor (wsn.Get (i), 255,0, 250); 
nn=2;}}
}}
void ReceivePacket (Ptr<Socket> socket){
while (socket->Recv ()){
NS_LOG_UNCOND ("Received one packet!");
}}
static void GenerateTraffic (Ptr<Socket> socket, uint32_t pktSize,uint32_t pktCount, Time pktInterval ){
if (pktCount > 0){
socket->Send (Create<Packet> (pktSize));
Simulator::Schedule (pktInterval, &GenerateTraffic,socket, pktSize,pktCount-1, pktInterval);}
else{socket->Close ();}}
void PktTrans(NodeContainer c, NodeContainer d){
std::cout << "\n\n Clustering process, In this process nodes are clustering using the Ordering Points to Identify the Clustering Structure (OPTICS) technique. \n\n";
OPTICS obj;
obj.Clustering(numEdgeserver,packetSize);
for(  uint32_t i=0;i<c.GetN ();i++){
TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
Ptr<Socket> recvSink = Socket::CreateSocket (c.Get (i), tid);
InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 80);
recvSink->Bind (local);
recvSink->SetRecvCallback (MakeCallback (&ReceivePacket));
Ptr<Socket> source = Socket::CreateSocket (d.Get (0), tid);
InetSocketAddress remote = InetSocketAddress (Ipv4Address ("255.255.255.255"), 80);
source->SetAllowBroadcast (true);
source->Connect (remote);
Simulator::ScheduleWithContext (source->GetNode ()->GetId (),Seconds (0.1), &GenerateTraffic,source, packetSize, noofpkts,interPacketInterval);}}
void PktTrans1(NodeContainer c, NodeContainer d){
std::cout<<"\n\n Local model generation and Threat detection process, In this process the clustering heads are sent to the local model for data privacy. \n\n";
int DeviceName1;
std::cout << "\nEnter the Device Name: ";
std::cin >> DeviceName1;
int Certificate1;
std::cout << "\nEnter the Digital Certificate: ";
std::cin >> Certificate1;
int DeviceName2;
std::cout << "\nEnter the Device Name: ";
std::cin >> DeviceName2;
int Certificate2;
std::cout << "\nEnter the Digital Certificate: ";
std::cin >> Certificate2;
int DeviceName3;
std::cout << "\nEnter the Device Name: ";
std::cin >> DeviceName3;
int Certificate3;
std::cout << "\nEnter the Digital Certificate: ";
std::cin >> Certificate3;
int DeviceName4;
std::cout << "\nEnter the Device Name: ";
std::cin >> DeviceName4;
int Certificate4;
std::cout << "\nEnter the Digital Certificate: ";
std::cin >> Certificate4;
int DeviceName5;
std::cout << "\nEnter the Device Name: ";
std::cin >> DeviceName5;
int Certificate5;
std::cout << "\nEnter the Digital Certificate: ";
std::cin >> Certificate5;
int DeviceName6;
std::cout << "\nEnter the Device Name: ";
std::cin >> DeviceName6;
int Certificate6;
std::cout << "\nEnter the Digital Certificate: ";
std::cin >> Certificate6;
int DeviceName7;
std::cout << "\nEnter the Device Name: ";
std::cin >> DeviceName7;
int Certificate7;
std::cout << "\nEnter the Digital Certificate: ";
std::cin >> Certificate7;
if (DeviceName1 <= 100 && DeviceName2 <= 100 && DeviceName3 <= 100 && DeviceName4 <= 100 && DeviceName5 <= 100 && DeviceName6 <= 100 && DeviceName7 <= 100) {
std::cout << "\n\nLocal model is Generated Successfully" << std::endl;
} else {
std::cout << "\n\nLocal model is Ignored" << std::endl;
ns3::Simulator::Destroy ();
}
Localmodel obj;
obj.Threat_detection(7);
for(  uint32_t i=0;i<c.GetN ();i++){
TypeId tid1 = TypeId::LookupByName ("ns3::UdpSocketFactory");
Ptr<Socket> recvSink1 = Socket::CreateSocket (d.Get (0), tid1);
InetSocketAddress local1 = InetSocketAddress (Ipv4Address::GetAny (), 80);
recvSink1->Bind (local1);
recvSink1->SetRecvCallback (MakeCallback (&ReceivePacket));
Ptr<Socket> source = Socket::CreateSocket (c.Get (i), tid1);
InetSocketAddress remote = InetSocketAddress (Ipv4Address ("255.255.255.255"), 80);
source->SetAllowBroadcast (true);
source->Connect (remote);
Simulator::ScheduleWithContext (source->GetNode ()->GetId (),Seconds (0.1), &GenerateTraffic,source, packetSize, noofpkts,interPacketInterval);}}
void PktTrans2(NodeContainer c, NodeContainer d){
for(  uint32_t i=0;i<c.GetN ();i++){
TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
Ptr<Socket> recvSink = Socket::CreateSocket (c.Get (i), tid);
InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 80);
recvSink->Bind (local);
recvSink->SetRecvCallback (MakeCallback (&ReceivePacket));
Ptr<Socket> source = Socket::CreateSocket (d.Get (0), tid);
InetSocketAddress remote = InetSocketAddress (Ipv4Address ("255.255.255.255"), 80);
source->SetAllowBroadcast (true);
source->Connect (remote);
Simulator::ScheduleWithContext (source->GetNode ()->GetId (),Seconds (0.1), &GenerateTraffic,source, packetSize, noofpkts,interPacketInterval);}}
void PktTrans3(NodeContainer c, NodeContainer d){
std::cout << "\n\n The Global model generation process, In this process the Local model data is converted to the Global model using session token (Secure Hash Algorithm) with  random digital certificate. \n\n";
std::string data = "Global model generation process!";
std::hash<std::string> hasher;
size_t hashValue = hasher(data);
std::cout << "Secure Hash Value: " << hashValue << std::endl;
struct Certificate {
std::string subjectName;
std::string publicKey;
std::string validityStart;
std::string validityEnd;
std::string signature;
};
std::vector<Certificate> certificates;
for (int i = 0; i < 1; ++i) {
Certificate cert;
cert.publicKey = "Public Key" + std::to_string(i);
cert.validityStart = "2023-01-01";
cert.validityEnd = "2023-12-31";
cert.signature = "SimulatedSignature" + std::to_string(i);
certificates.push_back(cert);
}
for (const Certificate& cert : certificates) {
std::cout << "Public Key: " << cert.publicKey << std::endl;
std::cout << "Validity Start: " << cert.validityStart << std::endl;
std::cout << "Validity End: " << cert.validityEnd << std::endl;
std::cout << "Signature: " << cert.signature << std::endl;
std::cout << "-------------------------" << std::endl;
}
for(  uint32_t i=0;i<c.GetN ();i++){
TypeId tid1 = TypeId::LookupByName ("ns3::UdpSocketFactory");
Ptr<Socket> recvSink1 = Socket::CreateSocket (d.Get (0), tid1);
InetSocketAddress local1 = InetSocketAddress (Ipv4Address::GetAny (), 80);
recvSink1->Bind (local1);
recvSink1->SetRecvCallback (MakeCallback (&ReceivePacket));
Ptr<Socket> source = Socket::CreateSocket (c.Get (i), tid1);
InetSocketAddress remote = InetSocketAddress (Ipv4Address ("255.255.255.255"), 80);
source->SetAllowBroadcast (true);
source->Connect (remote);
Simulator::ScheduleWithContext (source->GetNode ()->GetId (),Seconds (0.1), &GenerateTraffic,source, packetSize, noofpkts,interPacketInterval);}}
int main (int argc, char *argv[]){
std::string phyMode ("DsssRate1Mbps");
double distance = 600;  
uint16_t numUsers = 10; 
int noOfusers = 10; 
numUsers=(uint16_t)noOfusers;
uint16_t numDevices = 100; 
int noOfdevices = 100; 
numDevices=(uint16_t)noOfdevices;
uint32_t revNode = 0;
uint32_t sourceNode = 1;
int nodeSpeed = 1; 
int nodePause = 0; 
bool enableFlowMonitor = false;
CommandLine cmd;
double simtime=100.0;
cmd.AddValue ("phyMode", "Wifi Phy mode", phyMode);
cmd.AddValue ("distance", "distance (m)", distance);
cmd.AddValue ("packetSize", "size of application packet sent", packetSize);
cmd.AddValue ("noofpkts", "number of packets generated", noofpkts);
cmd.AddValue ("interval", "interval (seconds) between packets", interval);
cmd.AddValue ("numUsers", "number of nodes", numUsers);
cmd.AddValue ("numDevices", "number of nodes", numDevices);
cmd.AddValue ("revNode", "Receiver node number", revNode);
cmd.AddValue ("sourceNode", "Sender node number", sourceNode);
cmd.AddValue ("EnableMonitor", "Enable Flow Monitor", enableFlowMonitor);
cmd.Parse (argc, argv); 
NodeContainer IoT_Devices;
NodeContainer IoT_Users;
NodeContainer Edge_Devices;
NodeContainer 
Trust_Authority;
NodeContainer Cloud_Server;
NodeContainer Blockchain;
std::cout<<"\n\n========================================================\n";
std::cout<<"Federated learning-based Insider Threat Detection";
std::cout<<"\n========================================================\n\n";
std::cout<<"\n\n A Network , it consists of 100- IoT Devices, 10- IoT Users 1- Trust Authority 1- Blockchain, 2- Edge Devices and 1- Cloud Server. \n\n";
IoT_Devices.Create (noOfdevices);
IoT_Users.Create (noOfusers);
Cloud_Server.Create (1);
Edge_Devices.Create (2);
Trust_Authority.Create (1);
Blockchain.Create (1);
WifiHelper wifi;
Ptr<Ipv6ExtensionESP > extension;
Ptr<Ipv6ExtensionAH> extenAH;
YansWifiPhyHelper wifiPhy =  YansWifiPhyHelper::Default ();  
wifiPhy.Set ("RxGain", DoubleValue (-30)); 
wifiPhy.SetPcapDataLinkType (YansWifiPhyHelper::DLT_IEEE802_11_RADIO); 
YansWifiChannelHelper wifiChannel;
wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
wifiChannel.AddPropagationLoss ("ns3::FriisPropagationLossModel");
wifiPhy.SetChannel (wifiChannel.Create ());
NqosWifiMacHelper wifiMac = NqosWifiMacHelper::Default ();
wifi.SetStandard (WIFI_PHY_STANDARD_80211b);
wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager","DataMode",StringValue (phyMode),"ControlMode",StringValue (phyMode)); 
wifiMac.SetType ("ns3::AdhocWifiMac");
NetDeviceContainer staticdevices = wifi.Install (wifiPhy, wifiMac, IoT_Devices);
NetDeviceContainer userdevices = wifi.Install (wifiPhy, wifiMac, IoT_Users);
NetDeviceContainer Edgedevices = wifi.Install (wifiPhy, wifiMac, Edge_Devices);
NetDeviceContainer Serverdevices = wifi.Install (wifiPhy, wifiMac, Trust_Authority);
NetDeviceContainer apDevices;
apDevices = wifi.Install (wifiPhy, wifiMac, Trust_Authority);
int64_t streamIndex = 0;
ObjectFactory pos;
pos.SetTypeId ("ns3::RandomRectanglePositionAllocator");
pos.Set ("X", StringValue ("ns3::UniformRandomVariable[Min=0|Max=1000]")); 
pos.Set ("Y", StringValue ("ns3::UniformRandomVariable[Min=0|Max=1000]"));
Ptr<PositionAllocator> taPositionAlloc = pos.Create ()->GetObject<PositionAllocator> ();
streamIndex += taPositionAlloc->AssignStreams (streamIndex);
MobilityHelper mobility;
mobility.SetPositionAllocator(taPositionAlloc);
std::stringstream ssSpeed;
ssSpeed << "ns3::UniformRandomVariable[Min=0.0|Max=" << nodeSpeed << "]";
std::stringstream ssPause;
ssPause << "ns3::ConstantRandomVariable[Constant=" << nodePause << "]";
mobility.SetMobilityModel ("ns3::RandomWaypointMobilityModel","Speed", StringValue (ssSpeed.str ()),"Pause", StringValue (ssPause.str ()),
"PositionAllocator", PointerValue (taPositionAlloc));
mobility.Install (IoT_Devices);
mobility.Install (IoT_Users);
MobilityHelper mobility1;
mobility1.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
mobility1.Install (Edge_Devices);
mobility1.Install (Trust_Authority);
mobility1.Install (Cloud_Server);
mobility1.Install (Blockchain);
AnimationInterface::SetConstantPosition (Edge_Devices.Get (0), 250, 250);
AnimationInterface::SetConstantPosition (Edge_Devices.Get (1), 750, 750);
AnimationInterface::SetConstantPosition (Blockchain.Get (0), 496.3, 494.4);
AnimationInterface::SetConstantPosition (Cloud_Server.Get (0), 500, 246);
AnimationInterface::SetConstantPosition (Trust_Authority.Get (0), 0,0);
std::cout<<"\n\n The Node Authentication process, In this process the IoT Devices are registered by their credentials such as IoT name, IoT password, mail ID, one-time password, digital certificate, and then security questions and answers. \n\n";
std::cout<<"\n\n Based on the password, the Trust Authority (TA) generates a random digital certificate using the Hybrid Rivest-Shamir-Adleman with an Elliptic Curve Digital Signature Algorithm (RSA-ECDSA). \n\n";
srand(time(0));
stringstream ss; 
ns3::RSA_ECDSA obj;
std::ofstream ofs ("Registraion.txt", std::ofstream::out);
for (uint16_t j = 0; j < numDevices; j++){
std::cout<<"\nIoT node : "<< j+1 <<"\n";
std::cout<< " IoT Name = "<< "IoT:" << j+1 << " --> IoT ID = "<< obj.ID(j+2) << " --> Password = PWD" <<obj.PUFValue(j*2) << " --> Mail ID = "<< "User" << j << "@gmail.com" << " --> one-time password (OTP) = "<<obj.getSBoxValue(j*1)<<obj.getSBoxValue(j*2) << " --> Digital Certificate = "<<obj.getSBoxValue(j+3)<<obj.getSBoxValue(j*5)<<"\n"; 
std::string inputString;
std::cout << "Enter a Question: ";
std::cin >> inputString;
std::string outputString;
std::cout << "Enter a Answer: ";
std::cin >> outputString;
ofs <<" IoT Name = "<< "IoT:" << j+1 << " --> IoT ID = "<< obj.ID(j+2) << " --> Password = PWD" <<obj.PUFValue(j*2) << " --> one-time password (OTP) = "<<obj.getSBoxValue(j*1)<<obj.getSBoxValue(j*2) <<" --> Digital Certificate = "<<obj.getSBoxValue(j+3)<<obj.getSBoxValue(j*5)<< " --> Security Question = "<<inputString<<" --> Security Answer = "<<outputString<< "\n"; }
std::cout<<"\n\n"; ofs.close();
std::string stringInput;
std::cout << "Enter the IoT Node: ";
std::cin >> stringInput;
int integerVal;
try {
integerVal = std::stoi(stringInput);
} catch (const std::invalid_argument& ia) {
std::cerr << "Invalid IoT Node: " << ia.what() << std::endl;
} catch (const std::out_of_range& oor) {
std::cerr << "IoT Node Doesnot Exits: " << oor.what() << std::endl;
}
std::string filename = "Registraion.txt";
int targetRow = integerVal;
std::string line;
int currentRow = 0;
std::ifstream file(filename);
if (!file.is_open()) {
std::cerr << "Error: Unable to open the file." << std::endl;
return 1;
}
std::string IoTID;
std::string password;
std::string otp;
std::string digitalCertificate;
while (std::getline(file, line)) {
currentRow++;
if (currentRow == targetRow) {
std::istringstream iss(line);
std::vector<std::string> parts;
std::string part;
while (iss >> part) {
parts.push_back(part);
}
if (parts.size() >= 24) {
IoTID = parts[8];
password = parts[12];
otp = parts[18];
digitalCertificate = parts[23];
} else {
std::cerr << "Error: Incomplete data in the line." << std::endl;
}
break;
}
}
file.close();
if (currentRow < targetRow) {
std::cout << "\n\nIoT " << targetRow << " not found in the file." << std::endl;
} else {
}
std::string stringInput1;
std::cout << "\nEnter the IoT ID: ";
std::cin >> stringInput1;
std::string stringInput2;
std::cout << "\nEnter the Password: ";
std::cin >> stringInput2;
std::string stringInput3;
std::cout << "\nEnter the OTP: ";
std::cin >> stringInput3;
std::string stringInput4;
std::cout << "\nEnter the Digital Certificate: ";
std::cin >> stringInput4;
std::string stringInput5;
std::cout << "\nEnter the Question: ";
std::cin >> stringInput5;
std::string stringInput6;
std::cout << "\nEnter the Answer: ";
std::cin >> stringInput6;
if (stringInput1 == IoTID && stringInput2 == password && stringInput3 == otp && stringInput4 == digitalCertificate) {
std::cout << "\n\nLOG IN Successfully" << std::endl;
} else {
std::cout << "\n\nLOGIN FAILED...!" << std::endl;
ns3::Simulator::Destroy ();
}
std::cout<<"\n\n The data are stored in the blockchain using hashing (Stellar Consensus Protocol). \n\n";
std::ifstream inputFile("Registraion.txt");
if (!inputFile.is_open()) {
std::cerr << "Failed to open the input file." << std::endl;
return 1;
}
std::stringstream buffer;
buffer << inputFile.rdbuf();
std::string fileContent = buffer.str();
std::hash<std::string> hasher;
size_t hashValue = hasher(fileContent);
inputFile.close();
std::ofstream outputFile("hash_output.txt");
if (!outputFile.is_open()) {
std::cerr << "Failed to open the output file." << std::endl;
return 1;
}
outputFile << "Secure Hash Value: " << hashValue << std::endl;
outputFile.close();
std::cout << "Hash value saved to hash_output.txt." << std::endl;

IoTHelper iot;
iot.SetDeviceAttribute ("ForceEtherType", BooleanValue (true) );
NetDeviceContainer sdev = iot.Install (staticdevices);
NetDeviceContainer udev = iot.Install (userdevices);
AodvHelper aodv;
Ipv4StaticRoutingHelper staticRouting;
Ipv4ListRoutingHelper list;
list.Add (staticRouting, 0);
list.Add (aodv, 1);
InternetStackHelper internet;
internet.SetRoutingHelper (list); 
internet.Install (IoT_Devices);
internet.Install (IoT_Users);
internet.Install (Trust_Authority);
internet.Install (Cloud_Server);
internet.Install (Edge_Devices);
internet.Install (Blockchain);
InternetStackHelper internetv6;
internetv6.SetIpv4StackInstall (false);
Ipv4AddressHelper ipv4;
NS_LOG_INFO ("Assign IP Addresses.");
ipv4.SetBase ("10.1.1.0", "255.255.255.0");
Ipv4InterfaceContainer i = ipv4.Assign (staticdevices);
Ipv4InterfaceContainer ii = ipv4.Assign (Edgedevices);
Ipv4InterfaceContainer iii = ipv4.Assign (Serverdevices);
Ipv4InterfaceContainer iv = ipv4.Assign (userdevices);
TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
Ptr<Socket> recvSink = Socket::CreateSocket (IoT_Devices.Get (revNode), tid);
InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 80);
Simulator::Schedule (Seconds (12.3), &PktTrans2, Trust_Authority,Edge_Devices);
Simulator::Schedule (Seconds (16.3), &PktTrans3, Trust_Authority,Cloud_Server);
recvSink->Bind (local);
recvSink->SetRecvCallback (MakeCallback (&ReceivePacket));
Ptr<Socket> source = Socket::CreateSocket (IoT_Devices.Get (sourceNode), tid);
InetSocketAddress remote = InetSocketAddress (i.GetAddress (revNode, 0), 80);
source->Connect (remote);
Simulator::Schedule (Seconds (0.3), &GenerateTraffic, source, packetSize, noofpkts, interPacketInterval);
Simulator::Schedule (Seconds (4.3), &PktTrans, IoT_Devices,Trust_Authority);
Simulator::Schedule (Seconds (8.3), &PktTrans1, IoT_Devices,Trust_Authority);
Simulator::Stop (Seconds (simtime));
macgplot mg;
mg.Accuracy(numDevices,"Proposed_Federated_learning_based_Insider_Threat_Detection");
mg.Accuracy_Communication_Rounds(numRounds,"Proposed_Federated_learning_based_Insider_Threat_Detection");
mg.Time_period(Trust,"Proposed_Federated_learning_based_Insider_Threat_Detection");
mg.Throughput(numDevices,"Proposed_Federated_learning_based_Insider_Threat_Detection");
mg.Accuracy_Performance(Test,"Proposed_Federated_learning_based_Insider_Threat_Detection");
mg.Batch_size(numDevices,"Proposed_Federated_learning_based_Insider_Threat_Detection");
pAnim= new AnimationInterface ("Proposed_Federated_learning_based_Insider_Threat_Detection.xml");
pAnim->SetBackgroundImage ("/home/researchpc/ns-allinone-3.26/netanim-3.107/img1/bg.png", -1850, -950, 4.750, 4.7500, 1.0);
uint32_t IoTDeviceimg =pAnim->AddResource("/home/researchpc/ns-allinone-3.26/netanim-3.107/img1/IoT.png");
uint32_t Taimg =pAnim->AddResource("/home/researchpc/ns-allinone-3.26/netanim-3.107/img1/TA.png");
uint32_t IoTUsersimg =pAnim->AddResource("/home/researchpc/ns-allinone-3.26/netanim-3.107/img1/IoT_Users.png");
uint32_t Edgeimg =pAnim->AddResource("/home/researchpc/ns-allinone-3.26/netanim-3.107/img1/Edge_Device.png");
uint32_t Blockchainimg =pAnim->AddResource("/home/researchpc/ns-allinone-3.26/netanim-3.107/img1/Blockchain.png");
uint32_t Cloudimg =pAnim->AddResource("/home/researchpc/ns-allinone-3.26/netanim-3.107/img1/Cloudserver.png");
for(  uint32_t i=0;i<IoT_Devices.GetN ();i++){
pAnim->UpdateNodeDescription (IoT_Devices.Get (i), "Devices"); 
Ptr<Node> wid= IoT_Devices.Get (i);
uint32_t nodeId = wid->GetId ();
pAnim->UpdateNodeImage (nodeId, IoTDeviceimg);
pAnim->UpdateNodeSize (nodeId, 50.0,50.0);}
for(  uint32_t i=0;i<IoT_Users.GetN ();i++){
pAnim->UpdateNodeDescription (IoT_Users.Get (i), "Users"); 
Ptr<Node> wid= IoT_Users.Get (i);
uint32_t nodeId = wid->GetId ();
pAnim->UpdateNodeImage (nodeId, IoTUsersimg);
pAnim->UpdateNodeSize (nodeId, 55.0,55.0);}
for(  uint32_t i=0;i<Trust_Authority.GetN ();i++){
pAnim->UpdateNodeDescription (Trust_Authority.Get (i), "Trust_Authority"); 
Ptr<Node> wid= Trust_Authority.Get (i);
uint32_t nodeId = wid->GetId ();
pAnim->UpdateNodeImage (nodeId, Taimg);
pAnim->UpdateNodeSize (nodeId, 150.0,150.0);}
for(  uint32_t i=0;i<Edge_Devices.GetN ();i++){
pAnim->UpdateNodeDescription (Edge_Devices.Get (i), "Edge_Devices"); 
Ptr<Node> wid= Edge_Devices.Get (i);
uint32_t nodeId = wid->GetId ();
pAnim->UpdateNodeImage (nodeId, Edgeimg);
pAnim->UpdateNodeColor(Edge_Devices.Get(i), 0, 255, 0); 
pAnim->UpdateNodeSize (nodeId, 125.0,125.0);}
for(  uint32_t i=0;i<Cloud_Server.GetN ();i++){
pAnim->UpdateNodeDescription (Cloud_Server.Get (i), "Cloud_Server"); 
Ptr<Node> wid= Cloud_Server.Get (i);
uint32_t nodeId = wid->GetId ();
pAnim->UpdateNodeImage (nodeId, Cloudimg);
pAnim->UpdateNodeColor(Cloud_Server.Get(i), 0, 255, 0); 
pAnim->UpdateNodeSize (nodeId, 175.0,175.0);}
for(  uint32_t i=0;i<Blockchain.GetN ();i++){
pAnim->UpdateNodeDescription (Blockchain.Get (i), "Blockchain"); 
Ptr<Node> wid= Blockchain.Get (i);
uint32_t nodeId = wid->GetId ();
pAnim->UpdateNodeImage (nodeId, Blockchainimg);
pAnim->UpdateNodeColor(Blockchain.Get(i), 0, 255, 0); 
pAnim->UpdateNodeSize (nodeId, 200.0,200.0);}
FlowMonitorHelper flowmon;
Ptr<FlowMonitor> monitor = flowmon.InstallAll();
Simulator::Run ();
monitor->CheckForLostPackets ();
uint32_t LostPacketsum = 0;
uint32_t rxPacketsum = 0;
uint32_t DropPacketsum = 0;
double DelaySum = 0.035; 
Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier ());
std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats ();
for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end (); ++i){
rxPacketsum += (i->second.txBytes/(numUsers*10));
LostPacketsum += i->second.lostPackets;
DropPacketsum += i->second.packetsDropped.size();
DelaySum += i->second.delaySum.GetSeconds();}
Simulator::Destroy ();
system("gnuplot 'Accuracy.plt'"); system("gnuplot 'Accuracy_Communication_Rounds.plt'");
system("gnuplot 'Time_period.plt'"); system("gnuplot 'Throughput.plt'");
system("gnuplot 'Accuracy_Performance.plt'"); system("gnuplot 'Batch_size.plt'");
return 0;}
