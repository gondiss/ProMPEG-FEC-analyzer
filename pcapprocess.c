/* compile it like: gcc pcapprocess.c -o pcapprocess.o */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define DIMENSION 2  
#define ROW_SIZE 5
#define COLUMN_SIZE 20
#define MATRIXSIZE (COLUMN_SIZE * ROW_SIZE)
#define KB64 64*1024
#define MAX_UNIT 20

int networkLoss = 0;
int actualLoss  = 0;
int expectedLoss = 0;

char plMatrix[MAX_UNIT*MAX_UNIT];
char colFec[MAX_UNIT];
char rowFec[MAX_UNIT];

FILE* debug;
// these variables can be overwritten based on configurations passed.
int sizeM = MATRIXSIZE;
int sizeCol = COLUMN_SIZE;
int sizeRow = ROW_SIZE;
int dimension = DIMENSION;

void Analyze1DFec();
void Analyze2DFec();
void PrintToFile(int startSeq,FILE* fp);
void PrintDebugInfo(FILE* fp);
bool IsRectLoss(int index);

main()
{
  FILE* payload;
  FILE* fec1;
  FILE* fec2;
  FILE* out;
  FILE* details;


  int payloadSeq =0;
  int fec1Seq = 0;
  int fec2Seq = 0 ;

  char ln1[20];
  char ln2[20];
  char ln3[20];


  int readl,readf1,readf2,i;
  long size_tellp;
  long size_tellf1;
  long size_tellf2;

  char* tmp;
  bool flag = false;

  details = fopen("tmp123.tmp","r");
  if (details!= NULL) {
    fgets(ln1,20, details);
    sscanf(ln1,"%d %d %d",&dimension,&sizeRow,&sizeCol);
    sizeM = sizeRow * sizeCol;
    fclose(details);
  }
  payload = fopen("payload.tmp","r");
  fec1 = fopen("fec1.tmp","r");
  fec2 = fopen("fec2.tmp","r");
  out = fopen("final.dat","w");
  debug = fopen("debug.dat","w");

  if ((dimension == 1 && (payload==NULL || fec1==NULL))||
       (dimension == 2 && (payload==NULL || fec1==NULL || fec2==NULL))) {
    fprintf(stderr,"Failed: Resourses not available");
    return;
  }
  while(fgets(ln1,20, payload) != NULL) {
    sscanf(ln1,"%d",&readl);
    if(readl > KB64) {
      fgets(ln1,20, payload);
      sscanf(ln1,"%d",&readl);
      payloadSeq = readl;
      fgets ( ln2,20, fec1 );
      sscanf(ln2,"%d",&readf1);
      fec1Seq = readf1;
      if (dimension == 2) {
        fgets ( ln3,20, fec2 );
        sscanf(ln3,"%d",&readf2);
        fec2Seq = readf2;
      }
      continue;
    }
    if ((readl - payloadSeq)>=0 && (readl - payloadSeq)< sizeM) {
      // inside the matrix
      plMatrix[readl-payloadSeq] = 1;
    }
    else if ((readl - payloadSeq)>=0 && (readl - payloadSeq)>= sizeM) {
      // into the next matrix. get the fec packets
      flag = true;
      fseek(payload,size_tellp,SEEK_SET);
    }
    else if ((readl - payloadSeq) < -1000 && ((readl+KB64-1) - payloadSeq)< sizeM) {
      // inside the matrix with seqno wrap around
      plMatrix[readl+KB64-1-payloadSeq] = 1;
    }
    else if ((readl - payloadSeq) < -1000 && ((readl+KB64-1) - payloadSeq)>= sizeM) {
      // into the next matrix with wrap around. get the fec packets
      flag = true;
      fseek(payload,size_tellp,SEEK_SET);
    }
    size_tellp = ftell(payload); 
    if(flag) {
      while((tmp=fgets( ln2,20, fec1 )) != NULL) {
        sscanf(ln2,"%d",&readf1);
        if ((readf1 - fec1Seq)>=0 && (readf1 - fec1Seq)< sizeCol) {
          // inside the matrix
          colFec[readf1-fec1Seq] = 1;
        }
        else if ((readf1 - fec1Seq)>=0 && (readf1 - fec1Seq)>= sizeCol) {
          // into the next matrix. break
          fseek(fec1,size_tellf1,SEEK_SET);
          break;
        }
        else if ((readf1 - fec1Seq) < -1000 && ((readf1+KB64-1) - fec1Seq)< sizeCol) {
          // inside the matrix with seqno wrap around
          colFec[readf1+KB64-1-fec1Seq] = 1;
        }
        else if ((readf1 - fec1Seq) < -1000 && ((readf1+KB64-1) - fec1Seq)>= sizeCol) {
          // into the next matrix with seq wrap around. break
          fseek(fec1,size_tellf1,SEEK_SET);
          break;
        }
        size_tellf1 = ftell(fec1); 
      }
      if (tmp==NULL)
        break;
      if(dimension == 2) {
      while((tmp=fgets( ln3,20, fec2 )) != NULL) {
        sscanf(ln3,"%d",&readf2);
        if ((readf2 - fec2Seq)>=0 && (readf2 - fec2Seq)< sizeRow) {
          // inside the matrix
          rowFec[readf2-fec2Seq] = 1;
        }
        else if ((readf2 - fec2Seq)>=0 && (readf2 - fec2Seq)>= sizeRow) {
          // into the next matrix. break
          fseek(fec2,size_tellf2,SEEK_SET);
          break;
        }
        else if ((readf2 - fec2Seq) < -1000 && ((readf2+KB64-1) - fec2Seq)< sizeRow) {
          // inside the matrix with seqno wrap around
          rowFec[readf2+KB64-1-fec2Seq] = 1;
        }
        else if ((readf2 - fec2Seq) < -1000 && ((readf2+KB64-1) - fec2Seq)>= sizeRow) {
          // into the next matrix with seq wrap around. break
          fseek(fec2,size_tellf2,SEEK_SET);
          break;
        }
        size_tellf2 = ftell(fec2); 
      }
      if (tmp==NULL)
        break;
      }
      flag = false;
      fprintf(debug,"\nBefore Fec\n");
      PrintDebugInfo(debug);
      if(dimension == 1)
        Analyze1DFec();
      else
        Analyze2DFec();
      fprintf(debug,"\nAfter Fec\n");
      PrintDebugInfo(debug);
      PrintToFile(payloadSeq,out); 
      fprintf(debug,"\npl-seq-%d col-seq-%d row-seq-%d netowrk-%d actual-%d expected-%d \n",payloadSeq,fec1Seq,fec2Seq,networkLoss,actualLoss,expectedLoss);
      fprintf(debug,"==================================================================\n");
      payloadSeq+=sizeM;
      payloadSeq = (payloadSeq < KB64)? payloadSeq:(payloadSeq-KB64+1); 
      fec1Seq+=sizeCol;
      fec1Seq = (fec1Seq < KB64)? fec1Seq:(fec1Seq-KB64+1);
      if (dimension == 2) {
        fec2Seq+=sizeRow;
        fec2Seq = (fec2Seq < KB64)? fec2Seq:(fec2Seq-KB64+1);
      }
      memset(plMatrix,0,MAX_UNIT*MAX_UNIT); 
      memset(colFec,0,MAX_UNIT); 
      memset(rowFec,0,MAX_UNIT); 
    }
  }  
  fprintf(stderr,"\nfinal.dat is ready for plot\n");
  fclose(payload);
  fclose(fec1);
  if (dimension == 2)
    fclose(fec2);
  fclose(out);
  fclose(debug);
  return;
}

void Analyze1DFec()
{
  bool a,b;
  int i,j,k;
  for(i =0 ;i < sizeM;i++) {
    a=b=false;
    if (plMatrix[i] == 1)
      continue;
    if(colFec[i%sizeCol] == 0)
      a = true;
    for (j = 0; j<sizeRow; j++) {
      if (((j*sizeCol)+(i%sizeCol))!=i && 
          (plMatrix[((j*sizeCol)+(i%sizeCol))]== 0 ||
           plMatrix[((j*sizeCol)+(i%sizeCol))]== 3))
        b = true;
    }
    if(!a && !b) plMatrix[i] = 2;
    else if(a && !b) plMatrix[i] = 3; 
    else plMatrix[i] = 0; 
  }
}

void Analyze2DFec()
{
  // to be extended for 2D analysis
  bool a,b,a1,b1;
  int i,j,k;
  for(i =0 ;i < sizeM;i++) {
    a=b=a1=b1=false;
    if (plMatrix[i] == 1)
      continue;
    if(colFec[i%sizeCol] == 0) a = true;
    if(rowFec[i/sizeCol] == 0) b = true;
    for (j = 0; j<sizeRow; j++) {
      if (((j*sizeCol)+(i%sizeCol))!=i && 
          ((plMatrix[((j*sizeCol)+(i%sizeCol))]== 0 ||
            plMatrix[((j*sizeCol)+(i%sizeCol))]== 5)))
        a1 = true;
    }
    for (j = 0; j<sizeCol; j++) {
      if ((j+((i/sizeCol)*sizeCol))!=i && 
          ((plMatrix[(j+((i/sizeCol)*sizeCol))]== 0)||
            (plMatrix[(j+((i/sizeCol)*sizeCol))]== 5)))
        b1 = true;
    }

    if(a && b) plMatrix[i] = 0 ;
    else if((!a && !a1) || (!b && !b1)) plMatrix[i] = 2;
    else plMatrix[i] = 5;  
  }
  //fprintf(debug,"\nIntermidiate Fec\n");
  //PrintDebugInfo(debug);
  //fprintf(debug,"\n");
  // now rerun the loop
  for(i =0 ;i < sizeM;i++) {
    a=b=a1=b1=false;
    if (plMatrix[i] == 1 || plMatrix[i] == 2)
      continue;
    if(colFec[i%sizeCol] == 0) a = true;
    if(rowFec[i/sizeCol] == 0) b = true;
    for (j = 0; j<sizeRow; j++) {
      if (((j*sizeCol)+(i%sizeCol))!=i && 
          (plMatrix[((j*sizeCol)+(i%sizeCol))]== 0 ||
           plMatrix[((j*sizeCol)+(i%sizeCol))]== 5 ||
           plMatrix[((j*sizeCol)+(i%sizeCol))]== 3))
        a1 = true;
    }
    for (j = 0; j<sizeCol; j++) {
      if ((j+((i/sizeCol)*sizeCol))!=i && 
          (plMatrix[(j+((i/sizeCol)*sizeCol))]== 0||
           plMatrix[(j+((i/sizeCol)*sizeCol))]== 5 ||
           plMatrix[(j+((i/sizeCol)*sizeCol))]== 3))
        b1 = true;
    }
    if(!a && !b) plMatrix[i] = (IsRectLoss(i))? 0:2 ;
    else if((!a && !a1) || (!b && !b1)) plMatrix[i] = 2;
    else if (a1 && b1) plMatrix[i] =(IsRectLoss(i))? 0:3;
    else if (a1 == false || b1 == false) plMatrix[i] = 3;
    else plMatrix[i]  = 0; 
  }
}

void PrintDebugInfo(FILE* fp)
{
  int i,seq;
  fprintf(fp,"\nData");
  for(i = 0 ;i < sizeM ;i++) {
    if(i%sizeCol == 0) {
      fprintf(fp,"\n");
      if(dimension == 2)
        fprintf(fp," -%d",rowFec[i/sizeCol]);
      else
        fprintf(fp," -r");
    }
    fprintf(fp,"  %d",plMatrix[i]);
  } 
  fprintf(fp,"\nFec Col");
  for(i = 0 ;i < sizeCol ;i++) {
    if(i%sizeCol == 0)
      fprintf(fp,"\n   ");
    fprintf(fp,"  %d",colFec[i]);
  } 
}
void PrintToFile(int startSeq,FILE* fp)
{
  int i,seq;
  for(i = 0 ;i < sizeM ;i++) {
    if (plMatrix[i] !=1 ) {
      networkLoss++;
      if (plMatrix[i] != 2) {
        actualLoss++;
        expectedLoss++;
      }
      if (plMatrix[i]== 3) 
        expectedLoss--;
    }
    seq = ((startSeq+i) > KB64-1) ? (startSeq+i-(KB64-1)): startSeq+i;
    fprintf(fp,"%d %d %d %d\n",seq,networkLoss,actualLoss,expectedLoss);
  } 
}
bool IsRectLoss(int index)
{
  int j, i=index;
  int col[20],row[20];
  int crow = 0;
  int ccol = 0;
  bool result = false;
  //fprintf(debug,"\n");
  for (j = 0; j<sizeCol; j++) {
    if ((j+((i/sizeCol)*sizeCol))!=i && 
        ((plMatrix[(j+((i/sizeCol)*sizeCol))]== 0)||
          (plMatrix[(j+((i/sizeCol)*sizeCol))]== 5)||
           (plMatrix[(j+((i/sizeCol)*sizeCol))]== 3))) {
      row[crow++] = (j+((i/sizeCol)*sizeCol));
      //fprintf(debug,"r-%d ",row[crow-1]);
    }
  }
  row[crow] = -1;
  for (j = 0; j<sizeRow; j++) {
    if (((j*sizeCol)+(i%sizeCol))!=i && 
        (plMatrix[((j*sizeCol)+(i%sizeCol))]== 0 ||
          plMatrix[((j*sizeCol)+(i%sizeCol))]== 5 ||
          plMatrix[((j*sizeCol)+(i%sizeCol))]== 3)) {
      col[ccol++] = ((j*sizeCol)+(i%sizeCol));
      //fprintf(debug,"c-%d ",col[ccol-1]);
    }
  }
  col[ccol] = -1;
  i = 0;
  while(row[i] != -1) {
    j = 0;
    while(col[j] != -1) {
      if (plMatrix[(col[j]-index)+row[i]] == 0 || plMatrix[(col[j]-index)+row[i]] == 5)
        result = true;
      j++;
    }
    i++;
  }
  return result;
}
