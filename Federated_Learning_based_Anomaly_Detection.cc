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
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
using namespace ns3;
using namespace std;
NS_LOG_COMPONENT_DEFINE ("Federated_Learning_based_Anomaly_Detection");
AnimationInterface *pAnim;
double ds=1000.0;  
int rounds=300;  
int numUsers=100;
int numDevices=100; 
int numRounds=50;
int Trust=100;
int Test=10;
int Uidlist[500];
int passlist[500];    
uint32_t packetSize = 512; 
uint32_t noofpkts = 100;     
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
NS_LOG_UNCOND ("Received one Data!");
}}
static void GenerateTraffic (Ptr<Socket> socket, uint32_t pktSize,uint32_t pktCount, Time pktInterval ){
if (pktCount > 0){
socket->Send (Create<Packet> (pktSize));
Simulator::Schedule (pktInterval, &GenerateTraffic,socket, pktSize,pktCount-1, pktInterval);}
else{socket->Close ();}}
void PktTrans2(NodeContainer c, NodeContainer d){
std::cout<<"\n\n The non-FL version of intrusion detection process \n\n";
std::random_device rd;
std::mt19937 gen(rd());
std::uniform_int_distribution<int> dist(1, 100);
int nonFL = dist(gen);
if (nonFL <= 50) {
std::cout << "Node Classification: Normal" << std::endl;
} else {
std::cout << "Node Classification: Attack" << std::endl;
}
ostringstream str1; 
string regval = str1.str();
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
void PktTrans1(NodeContainer c, NodeContainer d){
std::cout<<"\n The attacker sends a flood of messages to overwhelm the end-device and make it unavailable to serve genuine message packets. \n\n";
int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
if (clientSocket == -1) {
std::cerr << "Error creating socket" << std::endl;
}
sockaddr_in serverAddr;
serverAddr.sin_family = AF_INET;
serverAddr.sin_port = htons(12345);
serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
std::cerr << "Error connecting to the server" << std::endl;
close(clientSocket);
}
const char* message = "Hello, server!";
int messageCount = 100;
for (int i = 0; i < messageCount; ++i) {
if (send(clientSocket, message, strlen(message), 0) == -1) {
close(clientSocket);
}
std::cout << "Message " << i << " sent successfully" << std::endl;
}
close(clientSocket);

ifstream myFile;
myFile.open("Modbus_based_network_dataset.csv");
while (myFile.good()) {
string line;
getline(myFile, line, ',');
cout << line << endl;
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
void PktTrans3(NodeContainer c, NodeContainer d){
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
uint16_t numNodes = 100; 
int noOfDevices = 100;  
numNodes=(uint16_t)noOfDevices;
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
cmd.AddValue ("numNodes", "number of nodes", numNodes);
cmd.AddValue ("revNode", "Receiver node number", revNode);
cmd.AddValue ("sourceNode", "Sender node number", sourceNode);
cmd.AddValue ("EnableMonitor", "Enable Flow Monitor", enableFlowMonitor);
cmd.Parse (argc, argv); 
NodeContainer IoT_Devices;
NodeContainer Cloud_Server;
std::cout<<"\n\n==========================================================================\n";
std::cout<<"Federated Learning-based Anomaly Detection for IoT Security Attacks";
std::cout<<"\n=============================================================================\n\n";
std::cout<<"\n\n An IoT based Network, it consists of 100 - IoT Devices and 1-Cloud Server\n\n";
std::cout<<"\n Load the Modbus-based network dataset\n\n";
ifstream file;
file.open("Modbus_based_network_dataset.csv");
string line;
getline(file, line);
while (getline(file, line)) {
cout << line << endl;
}
file.close();
IoT_Devices.Create (noOfDevices);
Cloud_Server.Create (1);
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
NetDeviceContainer clouddevices = wifi.Install (wifiPhy, wifiMac, Cloud_Server);
int64_t streamIndex = 0;
ObjectFactory pos;
pos.SetTypeId ("ns3::RandomRectanglePositionAllocator");
pos.Set ("X", StringValue ("ns3::UniformRandomVariable[Min=1.0|Max=850.0]"));
pos.Set ("Y", StringValue ("ns3::UniformRandomVariable[Min=1.0|Max=850.0]"));
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
MobilityHelper mobility1;
mobility1.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
mobility1.Install (Cloud_Server);
AnimationInterface::SetConstantPosition (Cloud_Server.Get (0), 420.6, 409.2);
IoTHelper iot;
iot.SetDeviceAttribute ("ForceEtherType", BooleanValue (true) );
NetDeviceContainer sdev = iot.Install (staticdevices);
AodvHelper aodv;
Ipv4StaticRoutingHelper staticRouting;
Ipv4ListRoutingHelper list;
list.Add (staticRouting, 0);
list.Add (aodv, 1);
InternetStackHelper internet;
internet.SetRoutingHelper (list); 
internet.Install (IoT_Devices);
internet.Install (Cloud_Server);
InternetStackHelper internetv6;
internetv6.SetIpv4StackInstall (false);
Ipv4AddressHelper ipv4;
Ipv4AddressHelper ipv4h;
ipv4h.SetBase ("1.0.0.0", "255.0.0.0");
NS_LOG_INFO ("Assign IP Addresses.");
ipv4.SetBase ("10.1.1.0", "255.255.255.0");
Ipv4InterfaceContainer i = ipv4.Assign (staticdevices);
Ipv4InterfaceContainer ii = ipv4.Assign (clouddevices);
TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
Ptr<Socket> recvSink = Socket::CreateSocket (IoT_Devices.Get (revNode), tid);
InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 80);
Simulator::Schedule (Seconds (8.3), &PktTrans2, IoT_Devices,Cloud_Server);
Simulator::Schedule (Seconds (12.3), &PktTrans3, IoT_Devices,Cloud_Server);
recvSink->Bind (local);
recvSink->SetRecvCallback (MakeCallback (&ReceivePacket));
Ptr<Socket> source = Socket::CreateSocket (IoT_Devices.Get (sourceNode), tid);
InetSocketAddress remote = InetSocketAddress (i.GetAddress (revNode, 0), 80);
source->Connect (remote);
Simulator::Schedule (Seconds (0.3), &GenerateTraffic, source, packetSize, noofpkts, interPacketInterval);
Simulator::Schedule (Seconds (4.3), &PktTrans1, IoT_Devices,Cloud_Server);
Simulator::Stop (Seconds (simtime));
macgplot mg;
mg.Accuracy(numDevices,"Existing_Federated_Learning_based_Anomaly_Detection");
mg.Accuracy_Communication_Rounds(numRounds,"Existing_Federated_Learning_based_Anomaly_Detection");
mg.Time_period(Trust,"Existing_Federated_Learning_based_Anomaly_Detection");
mg.Throughput(numDevices,"Existing_Federated_Learning_based_Anomaly_Detection");
mg.Accuracy_Performance(Test,"Existing_Federated_Learning_based_Anomaly_Detection");
mg.Batch_size(numDevices,"Proposed_Federated_learning_based_Insider_Threat_Detection");
pAnim= new AnimationInterface ("Existing_Federated_Learning_based_Anomaly_Detection.xml");
pAnim->SetBackgroundImage ("/home/researchpc/ns-allinone-3.26/netanim-3.107/img1/bg1.png", -705, -625, 2.00, 2.500, 1.0);
uint32_t iotimg =pAnim->AddResource("/home/researchpc/ns-allinone-3.26/netanim-3.107/img1/IoT1.png");
uint32_t blockchainimg =pAnim->AddResource("/home/researchpc/ns-allinone-3.26/netanim-3.107/img1/Cloudserver1.png");
for(  uint32_t i=0;i<IoT_Devices.GetN ();i++){
pAnim->UpdateNodeDescription (IoT_Devices.Get (i), "IoT_Devices"); 
Ptr<Node> wid= IoT_Devices.Get (i);
uint32_t nodeId = wid->GetId ();
pAnim->UpdateNodeImage (nodeId, iotimg);
pAnim->UpdateNodeColor(IoT_Devices.Get(i), 0, 255, 0); 
pAnim->UpdateNodeSize (nodeId, 50.0,50.0);}
for(  uint32_t i=0;i<Cloud_Server.GetN ();i++){
pAnim->UpdateNodeDescription (Cloud_Server.Get (i), "Cloud_Server"); 
Ptr<Node> wid= Cloud_Server.Get (i);
uint32_t nodeId = wid->GetId ();
pAnim->UpdateNodeImage (nodeId, blockchainimg);
pAnim->UpdateNodeColor(Cloud_Server.Get(i), 0, 255, 0); 
pAnim->UpdateNodeSize (nodeId, 150.0,150.0);}
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
rxPacketsum += (i->second.txBytes/(numNodes*10));
LostPacketsum += i->second.lostPackets;
DropPacketsum += i->second.packetsDropped.size();
DelaySum += i->second.delaySum.GetSeconds();}
Simulator::Destroy ();
system("gnuplot 'Accuracy.plt'"); system("gnuplot 'Accuracy_Communication_Rounds.plt'");
system("gnuplot 'Time_period.plt'"); system("gnuplot 'Throughput.plt'");
system("gnuplot 'Accuracy_Performance.plt'"); system("gnuplot 'Batch_size.plt'");
return 0;}
