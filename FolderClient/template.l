%{
#include <stdio.h>
%}

cifra [0-9]
litera [a-z]
cifrai [1-9]
substr word

%%


.|\n ;

%%

int main(int argc, char** argv)
{
if(argc>0)
 yyin=fopen(argv[1], "r");
 yyout= fopen("rezultat.txt", "w");
yylex();
}
