%{
#include "heading.h"
#include "node.h"
#define YYDEBUG 1
int yyerror(char *s);
int yylex(void);

NBlock *programBlock; /* the top level root node */

%}

%union{
  Attr *attr;
  AttrList *attrlist;
  aaaSG *aaasg;
  Probe *probe;
  RServer *rserver;
  NBlock *block;
  std::string *string;
  int token;
}

%start	program 

%token <token>  EOL IND DED NO AAASG AAAACC AAALOG PROBE ATTRSNMPPROBE ATTRCOMP
%token <token>  RSERVER
%token <string> TIDENTIFIER ATTRNAME ATTRBOOL ATTRINT ATTRSTR ATTRIPV4 
%token <string> ATTRINT2 ATTRSTR2

%type <string> ident 
%type <probe> probe
%type <rserver> rserver
%type <block> program input
%type <aaasg> aaasg 
%type <attr> attribute 
%type <attrlist> attributeList attrblock  aaaacc aaalog 

%%

program:        input { programBlock = $1; }
                ;

input:		    /* empty */ { $$ = new NBlock(); }
		        | input aaasg  {$$->Authentication.groups.push_back($<aaasg>2); }
		        | input aaaacc { $$->Authentication.aaaacc($2); }
		        | input aaalog { $$->Authentication.aaalog($2); }
		        | input probe { $$->probes.push_back($2); }
		        | input rserver { $$->rservers.push_back($2); }
		        ;

aaasg:          AAASG ident ident EOL attrblock EOL { $$=new aaaSG(*$<string>3, *$<string>2, $5);}
                ;

aaaacc:         AAAACC attributeList {$$=$2;}
                ;

aaalog:         AAALOG attributeList {$$=$2;}
                ;

probe:          PROBE ident ident EOL attrblock EOL { $$= new Probe(*$3, *$2, $5); }
                | PROBE ident EOL attrblock EOL { $$ = new Probe(*$2, "http", $4); }
                ;

rserver:        RSERVER ident ident EOL attrblock EOL { $$= new RServer(*$3, *$2, $5); }
                | RSERVER ident EOL attrblock EOL { $$ = new RServer(*$2, "http", $4); }
                ;

attrblock:      IND attributeList DED {$$=$2;}
                ;

attributeList:  attribute { $$ = new AttrList();$$->push_back($1);}
                | attribute EOL { $$ = new AttrList();$$->push_back($1);}
                | attributeList attribute { $$->push_back($2); }
                | attributeList attribute EOL { $$->push_back($2); }
                ;

attribute:      ATTRSTR ident { $$= new AttrStr(*$1, *$2);}
                | ATTRINT ident { $$= new AttrInt(*$<string>1, *$<string>2);}
                | ATTRINT { $$= new AttrInt(*$<string>1, -1);}
                | ATTRIPV4 ident { $$=new AttrIP(*$<string>1, *$<string>2); }
                | ATTRSTR2 ident { $$= new AttrStr2(*$<string>1, *$<string>2, "");}
                | ATTRSTR2 ident ident { $$= new AttrStr2(*$<string>1, *$<string>2, *$<string>3);}
                | ATTRINT2 ident { $$= new AttrInt2(*$<string>1, *$<string>2, "");}
                | ATTRINT2 ident ident { $$= new AttrInt2(*$<string>1, *$<string>2, *$<string>3);}
                | ATTRCOMP ident ATTRSTR ident { $$= new AttrStr2(*$<string>1, *$<string>2, *$<string>4); }
                | ATTRBOOL  { $$= new AttrBool(*$<string>1, "1"); }
                | ATTRSNMPPROBE ident EOL attrblock { $$= new AttrSNMPProbe(*$2, $4) }
                | NO ATTRSTR { $$= new AttrStr(*$<string>2, "");}
                | NO ATTRINT { $$= new AttrInt(*$<string>2, -1);}
                | NO ATTRBOOL { $$= new AttrBool(*$<string>2, false); }
                ;

ident:          TIDENTIFIER { }
                ;

%%

int yyerror(string s)
{
  extern int yylineno;	// defined and maintained in lex.c
  extern char *yytext;	// defined and maintained in lex.c
  
  cerr << "ERROR: " << s << " at symbol \"" << yytext;
  cerr << "\" on line " << yylineno << endl;
  return 0;
}

int yyerror(char *s)
{
  return yyerror(string(s));
}

