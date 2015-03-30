#include <iostream>
#include <vector>
#include <cstdlib> // for stoi and atoi
#include <sstream>

extern int fbdebug;
extern int yylineno;
extern int yydebug;

int port_to_number(const std::string& port);
class Node;
class Attr;
class AttrBool;
class AttrInt;
class AttrInt2;
class AttrStr;
class AttrStr2;
class AttrIP;
class AttrSNMPProbe;
class aaaSG;
class aaaSGList;
class aaa;
class Probe;
class RServer;
class NBlock;
class NS;
class metric;
class metricBind;
class metricTable;
class monitor;

typedef std::vector<aaaSG*> aaaSGvec;
typedef std::vector<Attr*> AttrList;
typedef std::vector<Probe*> ProbeList;
typedef std::vector<RServer*> RServerList;
typedef std::vector<AttrSNMPProbe*> oidList;

class Node {
public:
    virtual ~Node() {}
};

class Attr {
public:
    std::string name;
    int type;
    /*
        Types: 0 Boolean;
                1 Int;
                2 String;
                3 IP;
                4 SNMP Probe;
    */
    Attr (const std::string& name, const int& type);
    virtual ~Attr() {}
    virtual int getInt();
    virtual int getInt(int num);
    virtual std::string getStr() ;
    virtual std::string getStr(int num);
    virtual bool getBool();
    virtual std::string debugStr();
    virtual AttrList* getAttr() { return NULL;};
    
};

class AttrBool : public Attr {
public: 
    bool value;
    AttrBool (const std::string& name, const bool& value);
    bool getBool();
    std::string debugStr();
};

class AttrInt : public Attr {
public: 
    int value;
    AttrInt (const std::string& name, const std::string& value) : 
        Attr(name, 1), value(atoi( value.c_str() )) {} 
    AttrInt (const std::string& name, const int value) :
        Attr(name, 1), value(value) {}
    int getInt();
    std::string getStr();
    std::string debugStr();
    std::string convertInt(int number);
};

class AttrInt2 : public Attr {
public: 
    int value;
    int value2;
    AttrInt2 (const std::string& name, const std::string& value, 
        const std::string& value2) : Attr(name, 1), value(atoi( value.c_str() )), 
        value2(atoi( value2.c_str() )) {} 
    AttrInt2 (const std::string& name, const int value, const int value2) :
        Attr(name, 1), value(value), value2(value2) {}
        
    int getInt(int num) { return num==1?value:value2; }
    std::string debugStr();
    std::string convertInt(int number);
};

class AttrStr : public Attr {
public: 
    std::string value;
    AttrStr (const std::string& name, const std::string& value) : 
        Attr(name, 2), value(value) {}

    std::string getStr() { return value; }
    std::string debugStr();
};

class AttrStr2 : public Attr {
public: 
    std::string value;
    std::string value2;
    AttrStr2 (const std::string& name, const std::string& value, 
        const std::string& value2) : Attr(name, 2), value(value), value2(value2) {}

    std::string getStr(int num) { return num ==1?value:value2;}
    std::string debugStr();
};

class AttrIP : public Attr {
public: 
    char ipv4[4];
    std::string iptxt;
    
    AttrIP (const std::string& name, const std::string& value);
    std::string getStr() { return iptxt; }
    std::string debugStr();
};

class AttrSNMPProbe : public Attr {
public: 
    int threshold;
    int type_absolute_max;
    int weigth;
    AttrList *attributes;
    
    AttrSNMPProbe (const std::string& oid, AttrList *attr) : 
        Attr(oid, 4), attributes(attr) {}
    std::string debugStr();
    AttrList* getAttr(){ return attributes; }
};

class aaaSG : public Node {
public:
    std::string name;
    std::string type;
    int deadtime;
    std::string attr_user_profile;
    std::string baseDN;                     
    std::string filter_search_user;
    std::vector<Attr*> serverList;
    int localDB;
    int password;
    
    aaaSG(const std::string& name, const std::string& type, const AttrList *attributes );
};

class aaaSGList : public aaaSGvec {
public:
    aaaSG* node (const string& name) {
        for (aaaSGList::iterator it = begin(); it != end(); ++it) {
            if((*it)->name == name) {
                return (*it);
            }
        }
        return NULL;
    }
};

class aaa : public Node {
public:
    int localDB;
    int password;
    aaaSGList groups;
    
    aaa() : localDB(1), password(1){}
    void aaaacc(const AttrList *attributes);
    void aaalog(const AttrList *attributes);
};

class Probe : public Node {
public: 
    std::string name;
    std::string type;
    AttrList* Attributes;
    
    Probe (const std::string& name, const std::string& type, AttrList *attributes);
    Probe (const std::string& name, const std::string& type) : name(name), type(type) {}
    
    void dump();
    void toNS ();
};

class RServer : public Node {
public: 
    std::string name;
    std::string type;
    AttrList* Attributes;
    
    RServer (const std::string& name, const std::string& type, AttrList *attributes);
    RServer (const std::string& name, const std::string& type) : name(name), type(type) {}
    
    void dump();
    void toNS ();
};

class NBlock : public Node {
public:
    aaa Authentication;
    ProbeList probes;
    RServerList rservers;
    std::string aaaacc;
    NBlock() {}
};

class NS : public Node {
public:
    std::vector<NS*> metricTable;
    std::vector<NS*> metricTableBind;
    std::vector<NS*> monitor;
    std::vector<NS*> monitorBind;
    NS() {}
    virtual std::string dumpConfig();
};

class monitor : public NS {
public:
    std::string name;
    std::string type;
    int respCode_start;
    int respCode_end;
    std::string httpRequest;
    std::string rtspRequest;
    std::string customHeaders;
    std::string sipMethod;
    std::string send;
    std::string recv;
    std::string query;
    std::string userName;
    std::string password;
    std::string radKey;
    std::string radNASip;
    int interval;
    int resptimeout;
    int retries;
    int downtime;
    int successRetries;
    std::string destIP;
    std::string destPort;
    std::string IPAddress;
    std::string snmpOID;
    std::string snmpCommunity;
    std::string snmpThreshold;
    std::string snmpVersion;
    monitor();
    monitor(const std::string& name, const std::string& type) : name(name), type(type) {}
    std::string dumpConfig();
};

class metric : public NS {
public:
    std::string name;
    std::string oid;
    std::string mtname;
    metric(const std::string& metricname, const std::string& oid, const std::string& mt) : 
        name(metricname), oid(oid), mtname(mt) {}
    std::string dumpConfig();
};

class metricBind : public NS {
public:
    std::string mon;
    metric* met;
    int weight;
    int threshold;
    
    metricBind(const std::string& monname, metric* m) : 
        mon(monname), met(m) { }
    std::string dumpConfig();
};

class metricTable : public NS {
public:
    std::string name;
    
    metricTable(const std::string& name) : name(name) {}
    std::string dumpConfig();
};
