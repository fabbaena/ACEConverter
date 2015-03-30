#include "heading.h"
#include "node.h"
#include <iostream>
#include <vector>
#include <cstdlib> // for stoi and atoi
#include <sstream>

extern NS* netscaler;

Attr::Attr (const std::string& name, const int& type) : name(name), type(type) {}

int Attr::getInt() { return 0; }

int Attr::getInt(int num) { return 0; }

std::string Attr::getStr() { return ""; }

std::string Attr::getStr(int num) { return ""; }

bool Attr::getBool() { return false; }

std::string Attr::debugStr() { 
        std::string debug("DEBUG: No type, Name=" + name + ".\n");
        if(fbdebug) return debug; 
        else return "";
}


AttrBool::AttrBool (const std::string& name, const bool& value) : 
    Attr(name, 0), value(value) {}

bool AttrBool::getBool() { return value; }

std::string AttrBool::debugStr() { 
    std::string debug("DEBUG: Type=Boolean, Name="+name+", Value=");
    if(value) debug += "true.\n";
    else debug += "false.\n";
    if(fbdebug) return debug; 
    else return "";
}

int AttrInt::getInt() { return value; }

std::string AttrInt::getStr() { return convertInt(value); }

std::string AttrInt:: debugStr() { 
    std::string debug("DEBUG: Type=Int, Name="+ name +
        ", Value="+convertInt(value)+ ".\n");
    if(fbdebug) return debug; 
    else return "";
}

string AttrInt::convertInt(int number){
   stringstream ss;//create a stringstream
   ss << number;//add number to the stream
   return ss.str();//return a string with the contents of the stream
}

std::string AttrInt2::debugStr() { 
    std::string debug("DEBUG: Type=Int, Name="+ name +
        ", Value2="+convertInt(value)+ ".\n");
    if(fbdebug) return debug; 
    else return "";
}

std::string AttrInt2::convertInt(int number){
   stringstream ss;//create a stringstream
   ss << number;//add number to the stream
   return ss.str();//return a string with the contents of the stream
}

std::string AttrStr::debugStr() { 
    std::string debug("DEBUG: Type=String, Name="+name+", Value=" + value + ".\n");
    if(fbdebug) return debug; 
    else return "";
}

std::string AttrStr2::debugStr() { 
    std::string debug("DEBUG: Type=String2, Name="+name+", Value=" + value + ".\n");
    if(fbdebug) return debug; 
    else return "";
}

AttrIP::AttrIP (const std::string& name, const std::string& value) :
    Attr(name, 3), iptxt(value) {
    int i=0;
    std::istringstream iss(iptxt);
    std::string token;
    while (getline(iss, token, '.')) {
        ipv4[i++] =  atoi( token.c_str() );
    }
}

std::string AttrIP::debugStr() { 
    std::string debug("DEBUG: Type=IP, Name="+name+", Value=" + iptxt + ".\n");
    if(fbdebug) return debug; 
    else return "";
}

std::string AttrSNMPProbe::debugStr() {
    std::string debug("DEBUG : AttrSNMPProbe Type=SNMP, Name=oid, Value=" + name + ".\n");

    for ( AttrList::iterator it = attributes->begin() ; 
            it != attributes->end(); ++it){
        debug += (*it)->debugStr();
    }
    if(fbdebug) return debug; 
    else return "";
}

aaaSG::aaaSG(const std::string& name, const std::string& type, 
            const AttrList *attributes ) : name(name), type(type) { 
    localDB = -1;
    password = -1;
    deadtime = 100;
    cout << "Processing aaaSG;" << endl;
    
    for ( AttrList::const_iterator it = attributes->begin() ; 
            it != attributes->end(); ++it){
        cout << (*it)->debugStr();

        if(!(*it)->name.compare("server")) {
            serverList.push_back((*it));
        } else if (!(*it)->name.compare("deadtime")) {
                deadtime = (*it)->getInt();
        } else if (!(*it)->name.compare("attribute user-profile")) {
                attr_user_profile = (*it)->getStr();
        } else if (!(*it)->name.compare("baseDN")) {
                baseDN = (*it)->getStr();
        } else if (!(*it)->name.compare("filter search-user")) {
                filter_search_user = (*it)->getStr();
        } else {
                cout << "AAASG "<<name<<": ERROR - Attribute " << 
                    (*it)->name << " not recognized on line " << 
                    yylineno << "." << endl;
        }
    }

}


void aaa::aaaacc(const AttrList *attributes) {
    cout << "Processing aaaacc;" << endl;
    /* set attributes globally or directly to groups */
}

void aaa::aaalog(const AttrList *attributes) {
    cout << "Processing aaalogin;" << endl;
}

Probe::Probe (const std::string& name, const std::string& type, AttrList *attributes) : 
    name(name), type(type) 
{
    Attributes = attributes;
    toNS();
}
void Probe::dump() {
    cout << "DEBUG : Probe name=" << name << ", attrcount=" << Attributes->size() 
        << ", type=" << type << endl;
    for ( AttrList::const_iterator it = Attributes->begin() ; 
            it != Attributes->end(); ++it){
        cout << (*it)->debugStr();
    }
}
void Probe::toNS() {
    std::string nsconfig;
    std::string nstype = type;
    std::string load;
    std::stringstream metricname;
    metricTable* mt = NULL;
    metricBind* mb;
    metric* m;
    monitor* mon;
    int i=1;

    mon = new monitor(name, type);
    for ( AttrList::const_iterator it = Attributes->begin() ; 
            it != Attributes->end(); ++it)
    {
        if((*it)->type == 4) {

            if(!mt) {
                mt = new metricTable("mt_" + name);
                netscaler->metricTable.push_back(mt);
            }
            metricname.str("");
            metricname << "metric" << i++;
            m = new metric(metricname.str(), (*it)->name, mt->name);
            netscaler->metricTableBind.push_back(m);

            mb = new metricBind(name, m);

            for ( AttrList::iterator it2 = (*it)->getAttr()->begin() ; 
                    it2 != (*it)->getAttr()->end(); ++it2){
                    
                if((*it2)->name == "weight")  mb->weight = (*it2)->getInt();
                else if ((*it2)->name == "threshold") mb->threshold = (*it2)->getInt();
                
            }
            netscaler->monitorBind.push_back(mb);
        } else if((*it)->name == "port") {
            mon->destPort = (*it)->getStr();
        } else if((*it)->name == "expect status") {
            mon->respCode_start = (*it)->getInt(1);
            mon->respCode_end = (*it)->getInt(2);
        } else if((*it)->name == "request method") {
            if(type == "http") { mon->httpRequest = (*it)->getStr() + " "; }
            if(type == "https" ) { mon->httpRequest = (*it)->getStr() + " "; }
            if(type == "rtsp" ) { mon->rtspRequest = (*it)->getStr() + " "; }
            if(type == "sip udp" ) { mon->sipMethod = (*it)->getStr(); }
            if(type == "sip tcp" ) { mon->sipMethod = (*it)->getStr(); }
        } else if((*it)->name == "url") {
            if(type == "http") { mon->httpRequest += (*it)->getStr(); }
            if(type == "https" ) { mon->httpRequest += (*it)->getStr(); }
            if(type == "rtsp" ) { mon->rtspRequest += (*it)->getStr(); }
        } else if((*it)->name == "send-data") {
            mon->send = (*it)->getStr();
        } else if((*it)->name == "expect regex") {
            mon->recv = (*it)->getStr();
        } else if((*it)->name == "domain") {
            mon->query = (*it)->getStr();
        } else if((*it)->name == "credentials") {
            mon->userName = (*it)->getStr(1);
            mon->password = (*it)->getStr(2);
        } else if((*it)->name == "secret") {
            mon->userName = (*it)->getStr();
        } else if((*it)->name == "nas ip address") {
            mon->radNASip = (*it)->getStr();
        } else if((*it)->name == "interval") {
            mon->interval = (*it)->getInt();
        } else if((*it)->name == "receive") {
            mon->resptimeout = (*it)->getInt();
        } else if((*it)->name == "faildetect") {
            mon->retries = (*it)->getInt();
        } else if((*it)->name == "passdetect count") {
            mon->successRetries = (*it)->getInt();
        } else if((*it)->name == "passdetect interval") {
            mon->downtime = (*it)->getInt();
        } else if((*it)->name == "ip address") {
            mon->destIP = (*it)->getStr();
        } else if((*it)->name == "expect address") {
            mon->IPAddress = (*it)->getStr();
        } else if((*it)->name == "community") {
            mon->IPAddress = (*it)->getStr();
        } else if((*it)->name == "header") {
            mon->customHeaders += (*it)->getStr(1) + ": " + (*it)->getStr(2) + "\\n";
        } else {
            cout << "WARNING : Probe->toNS - " << (*it)->name << 
                " cannot be converted to NS." << endl;
        }
    }
    netscaler->monitor.push_back(mon);
}
RServer::RServer (const std::string& name, const std::string& type, AttrList *attributes) : 
    name(name), type(type) 
{
    Attributes = attributes;
    toNS();
}
void RServer::toNS() {}
std::string NS::dumpConfig() {
    std::stringstream ret;
    ret << "# Converstion Tool" << endl;
    for ( std::vector<NS*>::iterator it = metricTable.begin() ; 
            it != metricTable.end(); ++it){
        ret << (*it)->dumpConfig();
    }
    for ( std::vector<NS*>::iterator it = metricTableBind.begin() ; 
            it != metricTableBind.end(); ++it){
        ret << (*it)->dumpConfig();
    }
    for ( std::vector<NS*>::iterator it = monitor.begin() ; 
            it != monitor.end(); ++it){
        ret << (*it)->dumpConfig();
    }
    for ( std::vector<NS*>::iterator it = monitorBind.begin() ; 
            it != monitorBind.end(); ++it){
        ret << (*it)->dumpConfig();
    }
    return ret.str();
}
std::string metricTable::dumpConfig() {
    std::stringstream ret;
    ret << "add lb metricTable " << name << endl;
    return ret.str();
}
std::string metric::dumpConfig() {
    std::stringstream ret;
    ret << "bind lb metricTable " << mtname << " " << name << " " << oid << endl;
    return ret.str();
}
std::string metricBind::dumpConfig() {
    std::stringstream ret;
    ret << "bind lb monitor " << mon << " -metric " << met->name << 
        " -metricThreshold " << threshold << " -metricWeight " << weight << endl;
    return ret.str();
}
std::string monitor::dumpConfig() {
    std::stringstream ret;
    ret << "add lb monitor " << name << " " << type;
    cout << "preparing destport=" << destPort << endl;
    if(destPort != "" ) { ret << " -destPort " << destPort; } 
    if(respCode_start > 0 && respCode_end > 0) { 
        ret << " -respCode " << respCode_start << "-" << respCode_end;
    }
    if(httpRequest != "") { ret << " -httpRequest q{" << httpRequest << "}"; }
    if(rtspRequest != "") { ret << " -rtspRequest q{" << rtspRequest << "}"; }
    if(sipMethod != "") { ret << " -sipMethod " << sipMethod; }
    if(send != "" ) { ret << " -send q{" << send << "}"; }
    if(recv != "" ) { ret << " -recv q{" << recv << "}"; }
    if(query != "" ) { ret << " -query " << query << "}"; }
    if(userName != "" ) { ret << " -userName " << userName; }
    if(password != "" ) { ret << " -password " << password; }
    if(radKey != "" ) { ret << " -radKey " << radKey; }
    if(radNASip != "" ) { ret << " -radNASip " << radNASip; }
    if(interval > 0 ) { ret << " -interval " << interval; }
    if(resptimeout > 0 ) { ret << " -resptimeout " << resptimeout; }
    if(successRetries > 0 ) { ret << " -successRetries " << successRetries; }
    if(downtime > 0 ) { ret << " -downtime " << downtime; }
    if(destIP != "" ) { ret << " -destIP " << destIP; }
    if(IPAddress != "" ) { ret << " -IPAddress " << IPAddress; }
    if(customHeaders != "") { ret << " -customHeaders q{" << customHeaders << "}"; }
    ret << endl;
    return ret.str();
}
