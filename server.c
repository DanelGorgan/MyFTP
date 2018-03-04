#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <math.h>
#include <pwd.h>
#include <time.h>
#include "sha256.h"
#include <memory.h>



/****************************** MACRO-URI ******************************/

/* portul folosit */
#define PORT 2024

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/* codul de eroare returnat de anumite apeluri */
extern int errno;

/**************************** VARIABILE *****************************/
static const WORD k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/* codul de eroare returnat de anumite apeluri */
extern int errno;

//descriptorul pentru client
int client;

//variabila pentru logarea cu administrator
int admin;

int nr=0;


/*********************** DEFINITII FUNCTII ***********************/

void sha256_transform(SHA256_CTX *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len)
{
	WORD i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

void sha256_final(SHA256_CTX *ctx, BYTE hash[])
{
	WORD i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

char* SPrintHex(unsigned char * data,char cod[100]) 
 {
    char tmp[16];	
    for (int i=0; i<32; i++) { 
    sprintf(tmp, "%02x",data[i]);  
    //printf("%s",tmp);
    strcat(cod,tmp);
    }
    return cod;
 }


int login(char u[20],char p[100])
{
	printf("[server]Am apelat functia de login cu numele %s si parola %s...\n",u,p);
	int c,a,ok=0,ok1=0,b,k=0,i,j;
    char s[20],nume[20],parola[20],phash[100];
    int len;
    char* pos;
    len=strlen(s);
    pos=s+len-1;
    *pos='\0';
	
    FILE *f,*f1; 
	//verificam daca este administrator
	f1=fopen("administrator.txt","r");	
        while(fgets(s,20,f1))
        {
	admin=1;
	bzero(parola,20);
	bzero(nume,20);
	k=0;
	for(i=0;i<strlen(s);i++)
	  {
	    if(s[i]!=' ') nume[i]=s[i];
	    if(s[i]==' ')  {
			  for(j=i+1;j<strlen(s)-1;j++)
			   {
			   parola[k++]=s[j];
			   }
			   break;
       			  }
			
	  }//for
        }//while


	// verificam hash-ul trimis de client	
	unsigned char hash[32];
	bzero(hash,32);
	bzero(phash,100);
	 SHA256_CTX ctx;
	 sha256_init(&ctx);
	 sha256_update(&ctx,(unsigned char*)parola,strlen(parola)+1);
	 sha256_final(&ctx,hash);
	 strcpy(phash,SPrintHex(hash,phash));
         a=strcmp(nume,u);
	 b=strcmp(phash,p);
	 //printf("Numele este %s si parola %s\n",u,phash);
         if(a==0)  
		ok=2;
	 if(b==0)  
		ok1=2;
	 if(ok==2 && ok1==2)
		return 2;
         else
         { ok=0; ok1=0; }
   
    //verificam daca e client normal
    bzero(phash,100);
    f=fopen("username.txt","r");
    while(fgets(s,20,f))
        {
	bzero(parola,20);
	bzero(nume,20);
	k=0;
	for(i=0;i<strlen(s);i++)
	{
	  if(s[i]!=' ') nume[i]=s[i];
	  if(s[i]==' ')  {
			  for(j=i+1;j<strlen(s)-1;j++)
			   {
			   parola[k++]=s[j];
			   }
			   break;
       			  }
			
	} //for
	
	
	// verificam hash-ul trimis de client	
	unsigned char hash[32];
	bzero(hash,32);
	bzero(phash,100);
	 SHA256_CTX ctx;
	 sha256_init(&ctx);
	 sha256_update(&ctx,(unsigned char*)parola,strlen(parola)+1);
	 sha256_final(&ctx,hash);
	 strcpy(phash,SPrintHex(hash,phash));
         a=strcmp(nume,u);
	 b=strcmp(phash,p);
         if(a==0)  
		ok=1;
	 if(b==0)  
		ok1=1;
	if(ok==1 && ok1==1)
        return 1;
        else
        { ok=0; ok1=0; }
        } // while
 return 0;
        
}

void Creare_director(char director[20])
{            	
	struct stat st = {0};
	
	if (stat(director, &st) == -1) 
    	mkdir(director, 0700);
	printf("[server]Am apelat functia de creare director!\n [server]Trimitem clientului raspuns ...\n");
	int ret=1;
	write(client,&ret,4);
	
}

void Afla_director()
{
	char cwd[1024];
    	getcwd(cwd, sizeof(cwd));
	printf("[server]Am apelat functia de aflare director\n [server]Trimitem clientului raspuns ... \n");
   	write(client,cwd,100);
}

void Continut_director()
{
  DIR *d;
  struct dirent *dir;
  d = opendir(".");
  if (d)
    while ((dir = readdir(d)) != NULL)
    {
    	nr++;
    }
 write(client,&nr,4);
  d = opendir(".");
 if (d)
  {
    while ((dir = readdir(d)) != NULL)
    {
    	write(client,dir->d_name,20);
    }

    closedir(d);
  }
}

long GetFileSize(char filename[100])
{
    long size;
    FILE *f;
 
    f = fopen(filename, "rb");
    if (f == NULL) return -1;
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fclose(f);
 
    return size;
}

int Obtine_fisier()
{
	printf("[server]Am apelat functia de obtinere fisier ...\n");
	char msg[100];
	if (read (client, msg, 100) <= 0)
		{
		  perror ("[server]Eroare la read() de la client.\n");
		}
        
        /* Open the file that we wish to transfer */
        FILE *fp = fopen(msg,"rb");
        if(fp==NULL)
        {
            printf("[server]File opern error");
            return 1;   
        }   
	
	//Aflam marime fisier
	long filesize,marime1;
	float marime;
	filesize = GetFileSize(msg);
	marime=(float)filesize/256;
	marime1=filesize/256;
	if(marime>marime1)
	{
	  marime1=marime1+1;
	  write(client,&marime1,sizeof(marime));
	}
	else
	write(client,&marime1,sizeof(marime));
	fseek(fp,0,SEEK_SET);
	
        //marime fisier/256
	 while(1)
        {
            /* First read file in chunks of 256 bytes */
            unsigned char buff[256]={0};
            int nread = fread(buff,1,256,fp);
            //printf("[server]Bytes cititi %d \n", nread);        

            /* If read was success, send data. */
            if(nread > 0)
            {
                //printf("[server]Trimitem data ... \n");
                write(client, buff, nread);
            }

            /*
             * There is something tricky going on with read .. 
             * Either there was error, or we reached end of file.
             */
            if (nread < 256)
            {
                if (feof(fp))
                    printf("[server]End of file\n");
                if (ferror(fp))
                    printf("[server]Error reading\n");
		break;
            }
            

        }
}

int Adauga_fisier()
{
    printf("[server]Am intrat in functia de adauga fisier ...\n");
    char fisier[100];
    read(client,fisier,100); 

    /* Create file where data will be stored */
    int bytesReceived = 0;
    char recvBuff[256];
    memset(recvBuff, '0', sizeof(recvBuff));
    FILE *fp;
    
    fp = fopen(fisier, "ab"); 
    if(NULL == fp)
    {
        printf("[server]Error opening file");
        return 1;
    }
    
    int blocuri;
    read(client,&blocuri,sizeof(blocuri));
    /* Receive data in chunks of 256 bytes */
    while(blocuri)
        {
	bytesReceived = read(client, recvBuff, 256);
	printf("[server]Bytes primiti %d\n",bytesReceived);    
        fwrite(recvBuff, 1,bytesReceived,fp);
	blocuri--;
	}
    printf("\n\n[server]Fisier primit cu succes!\n");    
}




int Myfind(char dir_name[100],char fisier[100])
{
    DIR * d;
    struct dirent * sd;
    d = opendir (dir_name);
    if (! d) {
        fprintf (stderr, "Nu s-a putut deschide directorul '%s': %s\n",
                 dir_name, strerror (errno));
        exit (EXIT_FAILURE);
    }
	
        while ( ( sd=readdir(d) )!=NULL) 
	{
        if (! sd) 
            break;
	char *d_name = malloc (sizeof(char)* 100);
        strcpy(d_name, sd->d_name);

        if(strcmp(d_name,fisier)==0)
        {
	    strcpy(d_name,dir_name);
	    strcat(d_name,"/");
	    strcat(d_name,fisier);
	    printf("[server]Trimitem raspuns clientului...\n");
	    write(client,d_name,100);
	    break;
        }

        if (sd->d_type & DT_DIR) {

            //Verificam daca directorul nu este "d" sau parintele lui$
                if (strcmp (d_name, "..") != 0 &&
                strcmp (d_name, ".") != 0) {
                char newpath[PATH_MAX];
                strcpy(newpath,dir_name);
                strcat(newpath,"/");
                strcat(newpath,d_name);
                //Chemam recursiv functia MyFind
                Myfind (newpath,fisier);
            }
        }
  }
if (closedir (d)) {
        fprintf (stderr, "Nu s-a putut inchide '%s': %s\n",
                 dir_name, strerror (errno));
        exit (EXIT_FAILURE);
}

}

char* myfind(char dir_name[100],char fisier[100])
{
    DIR * d;
    struct dirent * sd;
    d = opendir (dir_name);
    if (! d) {
        fprintf (stderr, "Nu s-a putut deschide directorul '%s': %s\n",
                 dir_name, strerror (errno));
        exit (EXIT_FAILURE);
    }
	
        while ( ( sd=readdir(d) )!=NULL) 
	{
        if (! sd) 
            break;
	char *d_name = malloc (sizeof(char)* 100);
        strcpy(d_name, sd->d_name);
	printf("d_name  este %sfoarte bine\n",d_name);

        if(strcmp(d_name,fisier)==0)
        {
	    strcpy(d_name,dir_name);
	    strcat(d_name,"/");
	    strcat(d_name,fisier);
	    //printf("Trimitem raspuns clientului...\n");
	    return d_name;
        }

        if (sd->d_type & DT_DIR) {

            //Verificam daca directorul nu este "d" sau parintele lui$
                if (strcmp (d_name, "..") != 0 &&
                strcmp (d_name, ".") != 0) {
                char newpath[PATH_MAX];
                strcpy(newpath,dir_name);
                strcat(newpath,"/");
                strcat(newpath,d_name);
                //Chemam recursiv functia MyFind
                return myfind (newpath,fisier);
            }
        }
  }
if (closedir (d)) {
        fprintf (stderr, "Nu s-a putut inchide '%s': %s\n",
                 dir_name, strerror (errno));
        exit (EXIT_FAILURE);
}

}

void mystat(char f[100])
{
    printf("[server]Am intrat in stat\n");
    struct stat buffer;
    
    char time1[100],time2[100],time3[100],user[100];
    int size =buffer.st_size;
    struct passwd *pwd;
    char s[100];	
    strcpy(s,myfind(".",f));
    stat(s,&buffer);
    
   
   
    if(S_ISDIR(buffer.st_mode)) 
	 write(client,"d",2); 
    else
	 write(client,"-",2);
    
    if(buffer.st_mode & S_IRUSR) 
	 write(client,"r",2); 
    else
	 write(client,"-",2);
    
    if(S_IWUSR & buffer.st_mode ) 
	 write(client,"w",2); 
    else
	 write(client,"-",2);

    if(S_IXUSR & buffer.st_mode) 
	 write(client,"x",2); 
    else
	 write(client,"-",2);

    if(S_IRGRP & buffer.st_mode) 
	 write(client,"r",2); 
    else
	 write(client,"-",2);

    if(S_IWGRP & buffer.st_mode) 
	 write(client,"w",2); 
    else
	 write(client,"-",2);

    if(S_IXGRP & buffer.st_mode) 
	 write(client,"x",2); 
    else
	 write(client,"-",2);

    if(S_IROTH & buffer.st_mode) 
	 write(client,"r",2); 
    else
	 write(client,"-",2);

    if(S_IWOTH & buffer.st_mode) 
	 write(client,"w",2); 
    else
	 write(client,"-",2);

    if(S_IXOTH & buffer.st_mode) 
	 write(client,"x",2); 
    else
	 write(client,"-",2);
    
    write(client,&size,4);

        strcpy(time1, ctime(&buffer.st_mtime));
        strcpy(time2, ctime(&buffer.st_mtime));
        strcpy(time3, ctime(&buffer.st_mtime));
    write(client,time1,100);
    write(client,time2,100);
    write(client,time3,100);
   
     
     pwd = getpwuid(buffer.st_uid);
     strcpy(user,pwd->pw_name); 
     write(client,user,100);
    

}

void Update_whitelist(char nume[100],char parola[100])
{

	FILE *f = fopen("username.txt", "a");
	if (f == NULL)
	{
	    printf("Error opening file!\n");
	    exit(1);
	}
	printf("[server]Numele este %s si parola %s\n",nume,parola);
	fprintf(f, "%s %s\n",nume,parola);
	fclose(f);
}

int Numar_linie(char nume[100])
{
    printf("[server]Determinam numarul liniei \n");
    FILE *f;
    f=fopen("username.txt", "r");
    char nume1[100],s[100];
	while(fgets(s,20,f))
        {
	 bzero(nume1,100);
	 nr++;
	 for(int i=0;i<strlen(s);i++)
	  {
	    if(s[i]!=' ') nume1[i]=s[i];
	    else break;
          }
	if(strcmp(nume,nume1)==0) return nr;
        }//while
	return 0;
}

int Delete_whitelist(char nume[100]) 
{
        FILE *fp1, *fp2;
	printf("[server]Am intrat in delete whitelist cu numele %s\n",nume);
        char c;
        int del_line=0, temp = 1;
        //determinam line number of the line to be deleted:
        del_line=Numar_linie(nume);
	if(del_line==0) { 
			  printf("[server]Client inexistent!\n");
			  return 0;
			}
	printf("[server]Numarul liniei este %d\n",del_line);
       
        //open new file in write mode
	printf("Vrem sa deschidem fisierul\n");
        fp2 = fopen("copie.txt", "w");
	fp1 = fopen("username.txt","r");
	if(fp2!=NULL) printf("Eu zic ca am deschis fisierul\n");
	printf("Ne pregatim sa intram in while\n");
        while (c != EOF) {
          c = fgetc(fp1);
	  if ( c == EOF) break;
          if (c == '\n')
          temp++;
          //except the line to be deleted
          if (temp != del_line)
          {
            //copy all lines in file copy.c
            fputc(c, fp2);
          }
        }
        //close both the files.
        fclose(fp2); 
        fclose(fp1); 
	//remove original file
        remove("username.txt");
        //rename the file copie.txt to original name
        rename("copie.txt", "username.txt");
}

void Afiseaza_whitelist()
{
	FILE *f1;
	char s[100];
	f1=fopen("username.txt","r");
	while(fgets(s,100,f1))
        {
	  nr++;			
        }
	fseek(f1,0,SEEK_SET);
	write(client,&nr,4);
	while(fgets(s,100,f1))
	{
	  write(client,s,100);
	}
	fclose(f1);
}


int main ()
{
  struct sockaddr_in server;	// structura folosita de server
  struct sockaddr_in from;	
  char msg[100];		//mesajul primit de la client 
  char nume[100],parola[100];               //numele si parola primita de la client  
  int sd;			//descriptorul de socket 
  int choice;                   // alegerea primita de la client
  int ok=0,r=0; 
 /* crearea unui socket */
  if ((sd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
      perror ("[server]Eroare la socket().\n");
      return errno;
    }

  /* pregatirea structurilor de date */
  bzero (&server, sizeof (server));
  bzero (&from, sizeof (from));
  
  /* umplem structura folosita de server */
  /* stabilirea familiei de socket-uri */
    server.sin_family = AF_INET;	
  /* acceptam orice adresa */
    server.sin_addr.s_addr = htonl (INADDR_ANY);
  /* utilizam un port utilizator */
    server.sin_port = htons (PORT);
  
  /* atasam socketul */
  if (bind (sd, (struct sockaddr *) &server, sizeof (struct sockaddr)) == -1)
    {
      perror ("[server]Eroare la bind().\n");
      return errno;
    }

  /* punem serverul sa asculte daca vin clienti sa se conecteze */
  if (listen (sd, 5) == -1)
    {
      perror ("[server]Eroare la listen().\n");
      return errno;
    }

  /* servim in mod concurent clientii... */
  while (1)
    {
      int length = sizeof (from);

      printf ("[server]Asteptam la portul %d...\n",PORT);
      fflush (stdout);

      /* acceptam un client (stare blocanta pina la realizarea conexiunii) */
      client = accept (sd, (struct sockaddr *) &from, &length);

      /* eroare la acceptarea conexiunii de la un client */
      if (client < 0)
	    {
	      perror ("Eroare la accept().\n");
	      continue;
	    }
	  fflush(stdout);
	  int pid=fork();
	  if(pid==0)
	  {
		while(1)
		{
		if (ok==0)
		{		
		if (read(client,nume,100) <= 0)
		{
		  printf("%d\n",choice);
		  perror ("[server]Eroare la read() de la client la nume.\n");
		  break;
		}
		if (read(client,parola,100) <= 0)
		{
		  printf("%d\n",choice);
		  perror ("[server]Eroare la read() de la client la parola.\n");
		  break;
		}
		r=login(nume,parola);
		if(r==1) printf("[server]Logare reusita ca client!\n");
		else if(r==2)
			 printf("[server]Logare reusita ca administrator!\n");
			 else printf("[server]Logare nereusita!\n");
		printf("[server]Trimitem raspuns clientului ...\n");
		write(client,&r,4); 
		//ok=1;
		}
		if(r==1 || r==2)
	  	if (read (client, &choice, 4) <= 0)
		{
		  printf("%d\n",choice);
		  perror ("[server]Eroare la read() de la client la choice.\n");
		  break;
		}
		printf("[server]Alegerea a fost %d...\n",choice);		
		if(choice==1)
			{
				if (read (client, msg, 100) <= 0)
				{
				  perror ("[server]Eroare la read() de la client la creare director.\n");
				} 
				printf("%s\n",msg);
				Creare_director(msg);
				ok=1;
			}

		if(choice==2)
			{
				Afla_director();
				ok=1;
			}
		if(choice==3)
			{
				Continut_director();
				ok=1;
			}

		if(choice==5)
			    {
				
				if (read (client, msg, 100) <= 0)
				{
				  perror ("[server]Eroare la read() de la client.\n");
				  
				}
				Myfind(".",msg);
				ok=1;	     			             
			    }			
		if(choice==6)
			{
				if (read (client, msg, 100) <= 0)
				{
				  perror ("[server]Eroare la read() de la client.\n");
				}
				//printf("Am primit fisierul %sfoarte bine\n",msg);
				mystat(msg);
				ok=1;
			}
		if(choice==7)
			{
				Adauga_fisier();
				ok=1;
				
			}
		if(choice==8)
			{
				Obtine_fisier();
				ok=1;
				
			}
		if(r==1)
		if(choice==9)
			{
				printf("Client deconectat ...\n");
				exit(0);
			}
		if(r==2)
		{
		if(choice==9)
			{
				char nume[100],parola[100];
				if (read(client,nume,100) <= 0)
				{
				  printf("%d\n",choice);
				  perror ("[server]Eroare la read() de la client la nume.\n");
				}
				if (read(client,parola,100) <= 0)
				{
				  printf("%d\n",choice);
				  perror ("[server]Eroare la read() de la client la parola.\n");
				}
				Update_whitelist(nume,parola);
				ok=1;
			}
				
			
		if(choice==10)
			{
				if (read(client,nume,100) <= 0)
				{
				  printf("%d\n",choice);
				  perror ("[server]Eroare la read() de la client la nume.\n");
				}
				ok=1;
				Delete_whitelist(nume);
				
			}	
		if(choice==11)
			{
				Afiseaza_whitelist();
				ok=1;
				
			}	
		if(choice==12)
			{
				printf("[server]Client deconectat ...\n");
				exit(0);
			}
		
		}
			
		} // while(1)
	  } // if pid
	  else
	  {
		 int status;
		 while(waitpid(-1,&status, WNOHANG));
		 close(client);
	  }
	
      
    }				/* while */
}				/* main */

