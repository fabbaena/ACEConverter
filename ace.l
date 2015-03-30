%{
#include <stack>
#include "heading.h"
#include "node.h"
#include "ace_y.h"
#define SAVE_TOKEN yylval.string = new std::string(yytext, yyleng)

int spacecounter = 0;
int yyerror(char *s);
extern "C" int yywrap();
std::stack<int> indstack;

%}
%option stack

%x SPACE
%x INDEN
%x noteol

alnum       [a-zA-Z0-9_\-]
num         [0-9]+
nonspace    [^ \n]
noteol      [^\n]
ipaddr      {num}\.{num}\.{num}\.{num}
qt          \"[^"]*\"

%%

\n                              {yylineno++; yy_push_state(SPACE); return EOL;}
<SPACE>\n                       {yylineno++; spacecounter=0;}
<SPACE>[ ]                      {spacecounter++;}
<SPACE>.                        {   yy_pop_state();
                                    unput(*yytext);
                                    if(indstack.empty()) {indstack.push(0);}
                                    if(spacecounter > indstack.top()){
                                        indstack.push(spacecounter);
                                        spacecounter = 0;
                                        return IND;    
                                    } else{
                                        if(spacecounter == indstack.top()){
                                            spacecounter = 0; 
                                        } else {
                                            unput('=');
                                            while( indstack.top() > spacecounter){
                                                indstack.pop();
                                                unput('&');
                                            }
                                            spacecounter = indstack.top();
                                            yy_push_state(INDEN);
                                        }
                                    }
                                }
 
<INDEN>=                        { spacecounter = 0;yy_pop_state(); return EOL;}
<INDEN>&                        { return DED;}
" "                             {}
aaa\ group\ server              {return AAASG;} 
aaa\ accounting\ default        {return AAAACC;} 
aaa\ authentication\ login      {return AAALOG;}
probe                           {return PROBE; }
rserver                         {return RSERVER; }
no                              {return NO;}

ldap                            {SAVE_TOKEN; return TIDENTIFIER;}
radius                          {SAVE_TOKEN; return TIDENTIFIER;}
tacacs\+                        {SAVE_TOKEN; return TIDENTIFIER;}
server                          {SAVE_TOKEN; return ATTRIPV4;} 
deadtime                        {SAVE_TOKEN; return ATTRINT;} 
attribute\ user-profile         {SAVE_TOKEN; return ATTRSTR;}
baseDN                          {SAVE_TOKEN; return ATTRSTR;}
filter\ search-user             {SAVE_TOKEN; return ATTRSTR;}
shutdown                        {SAVE_TOKEN; return ATTRBOOL;}
group                           {return ATTRSTR;}
local                           {SAVE_TOKEN; return ATTRBOOL;}
none                            {SAVE_TOKEN; return ATTRBOOL;}
dns                             {SAVE_TOKEN;return TIDENTIFIER;}
echo\ tcp                       {SAVE_TOKEN;return TIDENTIFIER;}
echo\ udp                       {SAVE_TOKEN;return TIDENTIFIER;}
finger                          {SAVE_TOKEN;return TIDENTIFIER;}
ftp                             {SAVE_TOKEN;return TIDENTIFIER;}
http                            {SAVE_TOKEN;return TIDENTIFIER;}
https                           {SAVE_TOKEN;return TIDENTIFIER;}
icmp                            {SAVE_TOKEN;return TIDENTIFIER;}
imap                            {SAVE_TOKEN;return TIDENTIFIER;}
pop                             {SAVE_TOKEN;return TIDENTIFIER;}
rtsp                            {SAVE_TOKEN;return TIDENTIFIER;}
scripted                        {SAVE_TOKEN;return TIDENTIFIER;}
sip\ tcp                        {SAVE_TOKEN;return TIDENTIFIER;}
sip\ udp                        {SAVE_TOKEN;return TIDENTIFIER;}
smtp                            {SAVE_TOKEN;return TIDENTIFIER;}
snmp                            {SAVE_TOKEN;return TIDENTIFIER;}
tcp                             {SAVE_TOKEN;return TIDENTIFIER;}
telnet                          {SAVE_TOKEN;return TIDENTIFIER;}
udp                             {SAVE_TOKEN;return TIDENTIFIER;}
vm                              {SAVE_TOKEN;return TIDENTIFIER;}

append-port-hosttag             {SAVE_TOKEN; return ATTRBOOL;}
community                       {SAVE_TOKEN; return ATTRSTR; }
connection\ term\ forced        {SAVE_TOKEN; return ATTRBOOL;}
credentials                     {SAVE_TOKEN; return ATTRSTR2;}
secret                          {SAVE_TOKEN; return ATTRSTR;}
mailbox                         {SAVE_TOKEN; return ATTRSTR;}
description                     {yy_push_state(noteol);SAVE_TOKEN; return ATTRSTR;}
domain                          {SAVE_TOKEN; return ATTRSTR;}
expect\ address                 {SAVE_TOKEN; return ATTRIPV4;}
expect\ regex                   {SAVE_TOKEN; return ATTRSTR;}
offset                          {SAVE_TOKEN; return ATTRINT;}
cache                           {SAVE_TOKEN; return ATTRINT;}
expect\ status                  {SAVE_TOKEN; return ATTRINT2;}
faildetect                      {SAVE_TOKEN; return ATTRINT;}
hash                            {SAVE_TOKEN; return ATTRSTR;}
header                          {SAVE_TOKEN; return ATTRCOMP;}
header-value                    {SAVE_TOKEN; return ATTRSTR;}
interval                        {SAVE_TOKEN; return ATTRINT;}
ip\ address                     {SAVE_TOKEN; return ATTRIPV4;}
routed                          {SAVE_TOKEN; return ATTRBOOL;}
nas\ ip\ address                {SAVE_TOKEN; return ATTRIPV4;}
oid                             {SAVE_TOKEN; return ATTRSNMPPROBE;}
open                            {SAVE_TOKEN; return ATTRINT;}
passdetect\ interval            {SAVE_TOKEN; return ATTRINT;}
passdetect\ count               {SAVE_TOKEN; return ATTRINT;}
port                            {SAVE_TOKEN; return ATTRSTR;}
receive                         {SAVE_TOKEN; return ATTRINT;}
request\ command                {SAVE_TOKEN; return ATTRSTR;}
request\ method                 {SAVE_TOKEN; return ATTRSTR;}
url                             {SAVE_TOKEN; return ATTRSTR;}
script                          {SAVE_TOKEN; return ATTRSTR2;}
send-data                       {SAVE_TOKEN; return ATTRSTR;}
ssl\ cipher                     {SAVE_TOKEN; return ATTRSTR;}
ssl\ version                    {SAVE_TOKEN; return ATTRSTR;}
version                         {SAVE_TOKEN; return ATTRSTR;}
rport\ enable                   {SAVE_TOKEN; return ATTRBOOL;}
threshold                       {SAVE_TOKEN; return ATTRINT;}
type\ absolute\ max             {SAVE_TOKEN; return ATTRINT;}
weight                          {SAVE_TOKEN; return ATTRINT;}
console                         {SAVE_TOKEN; return ATTRBOOL;}
default                         {SAVE_TOKEN; return ATTRBOOL;}
error-enable                    {SAVE_TOKEN; return ATTRBOOL;}

{num}                           {SAVE_TOKEN; return TIDENTIFIER;}
{ipaddr}                        {SAVE_TOKEN; return TIDENTIFIER;}
{alnum}+                        {SAVE_TOKEN; return TIDENTIFIER;}
{qt}                            {SAVE_TOKEN; return TIDENTIFIER;}
{nonspace}+                     {SAVE_TOKEN; return TIDENTIFIER;}
<noteol>{noteol}+               {SAVE_TOKEN; return TIDENTIFIER;}
