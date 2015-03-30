/* main.cc */

#include "heading.h"
#include "node.h"
#include <string.h>

// prototype of bison-generated parser function
extern int yyparse();
extern NBlock* programBlock;
extern int yydebug;
NS* netscaler;

int fbdebug;

int main(int argc, char **argv)
{
  netscaler = new NS();
  if ((argc > 1) && (freopen(argv[1], "r", stdin) == NULL))
  {
    cerr << argv[0] << ": File " << argv[1] << " cannot be opened.\n";
    return 1;
  }
  if((argc > 2) && !strcmp(argv[2], "-fbd"))
      fbdebug = 1;
  else
      fbdebug = 0;
  if((argc > 3) && !strcmp(argv[3], "-d"))
      yydebug = 1;
  else
      yydebug = 0;
  yyparse();
  
  cout << "program has " << programBlock->Authentication.groups.size() << " aaaSGs" << endl;
  cout << "TacServer deadtime=" << programBlock->Authentication.groups.node("TacServer")->deadtime <<endl;
  cout << netscaler->dumpConfig();
  return 0;
}

int port_to_number(const std::string& port) {
    return !port.compare("dns")?52:
            !port.compare("echo")?7:
            !port.compare("finger")?79:
            !port.compare("ftp")?21:
            !port.compare("http")?80:
            !port.compare("https")?443:
            !port.compare("imap")?143:
            !port.compare("pop")?110:
            !port.compare("radius")?1812:
            !port.compare("rtsp")?554:
            !port.compare("sip")?5060:
            !port.compare("smtp")?25:
            !port.compare("telnet")?23:
            !port.compare("tcp")?80:
            !port.compare("udp")?53:
            atoi( port.c_str());
}

