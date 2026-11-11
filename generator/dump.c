#include <stdio.h>
#include "opcode/mn10300.h"
int main{
  int i;
  printf("{\"operands\":[");
  for(i=0;i<256;i++){ const struct mn10300_operand*o=&mn10300_operands[i]; if(i>0 && o->bits==0 && o->flags==0 && o->shift==0) break; printf("%s[%d,%d,%d]",i?",":"",o->bits,o->shift,o->flags);}
  printf("],\n\"opcodes\":[\n");
  for(i=0;mn10300_opcodes[i].name;i++){const struct mn10300_opcode*p=&mn10300_opcodes[i]; int j;
   printf("%s[\"%s\",%lu,%lu,%u,%u,%u,[",i?",\n":"",p->name,p->opcode,p->mask,p->no_match_operands,p->format,p->machine);
   for(j=0;j<8&&p->operands[j];j++) printf("%s%d",j?",":"",p->operands[j]); printf("]]");}
  printf("]}\n");}
