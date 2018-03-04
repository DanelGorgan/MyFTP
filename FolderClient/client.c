#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <limits.h>
#include <dirent.h>
#include <errno.h>
#include <sys/socket.h>
#include <time.h>
#include <pwd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <memory.h>
#include "sha256.h"
#define MAX_STRING 20

/****************************** MACRO-URI ******************************/
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

/* portul de conectare la server*/
int port;

char dir[100];
char msg[100]; //mesajul trimis la server
int alegere;
int sd;        // descriptorul de socket
int ret,nr;        //returnul de la server de tip int


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

void SPrintHex(unsigned char * data) 
 {
    char tmp[16],cod[100]={0};	
    for (int i=0; i<32; i++) { 
    sprintf(tmp, "%02x",data[i]);  
    //printf("%s",tmp);
    strcat(cod,tmp);
    }
    //printf("%s",cod);
    write(sd,cod,100);
 }

void Criptare()
{
	unsigned char hash[32];
	char p[100];
	bzero(hash,32);
	bzero(p,100);
	printf("Introduceti parola: ");
	scanf("%s",p);
	//write(sd,p,100);
	printf("\n");
	 SHA256_CTX ctx;
	 sha256_init(&ctx);
	 sha256_update(&ctx,(unsigned char*)p,strlen(p)+1);
	 sha256_final(&ctx,hash);
	 SPrintHex(hash);
}




int Afla_director(int choice)
{
/* trimiterea mesajului la server */
  if (write (sd, &choice, 4) <= 0)
    {
      perror ("[client]Eroare la write() spre server.\n");
      return errno;
    }
  read(sd,msg,100);
  printf("*************************\n");
  printf("Directorul curent de lucru este: %s\n\n", msg);
  printf("*************************\n");
}

int Continut_director_server(int choice)
{
  if (write (sd, &choice, 4) <= 0)
    {
      perror ("[client]Eroare la write() spre server.\n");
      return errno;
    }

  read(sd,&nr,4);
  int nr1=nr;
  printf("*************************\n");
  while(nr)
  {
    read(sd,msg,20);
    printf("%s\n",msg);
    nr--;
  }
  printf("*************************\n");
  nr=nr1;
  
}

void Continut_director_client()
{
  DIR *d;
  struct dirent *dir;
  d = opendir(".");
 if (d)
  {
    while ((dir = readdir(d)) != NULL)
    {
    	printf("%s\n",dir->d_name);
    }

    closedir(d);
  }
}



int Creare_director(char director[20],int alegere)
{
	if (write (sd, &alegere, 4) <= 0)
    {
      perror ("[client]Eroare la write() spre server.\n");
      return errno;
    }	


	if (write (sd, director, 100) <= 0)
    {
      perror ("[client]Eroare la write() spre server.\n");
      return errno;
    }
        read(sd,&ret,4);
	printf("*************************\n");
	if(ret==1) printf("Directorul cu numele %s a fost creat!\n",dir);
	printf("*************************\n");
}


int login(char u[20])
{

	if (write (sd, &alegere, 4) <= 0)
    {
      perror ("[client]Eroare la write() spre server.\n");
      return errno;
    }	

	if (write (sd, msg, 100) <= 0)
    {
      perror ("[client]Eroare la write() spre server.\n");
      return errno;
    }
}

int myfind (int alegere,char fisier[100])
{
	if (write (sd, &alegere, 4) <= 0)
    {
      perror ("[client]Eroare la write() spre server la alegere.\n");
      return errno;
    }    

	
        printf("Trimitem fisierul %s\n",fisier);
	if (write (sd, fisier, 100) <= 0)
    {
      perror ("[client]Eroare la write() spre server la fisier.\n");
      return errno;
    }
    
	if (read (sd, msg, 100) <= 0)
    {
      perror ("[client]Eroare la read() de la server la cale.\n");
      return errno;
    }
    printf("Calea fisierului este: %s\n",msg);
}

int mystat(int alegere,char fisier[100])
{

	if (write (sd, &alegere, 4) <= 0)
    {
      perror ("[client]Eroare la write() spre server.\n");
      return errno;
    }   

	if (write (sd, fisier, 100) <= 0)
    {
      perror ("[client]Eroare la write() spre server.\n");
      return errno;
    }
	printf("Permisiunea este: ");
	int nr1=10;
	while(nr1)
        {
	  read(sd,msg,2);
	  printf("%s",msg);
	  nr1--;
	}
	printf("\n\n");
	int size;
	read(sd,&size,4);
        printf ("Marimea blocului este de %d bytes\n",size);
	
        char time1[100],time2[100],time3[100],user[100];
        read(sd,time1,100);
	read(sd,time2,100);
	read(sd,time3,100);
	 printf ("Data ultimei modificari este %s \n",time1);
         printf ("Data schimbarii ultimului statusului este %s \n",time2);
         printf ("Data ultimei accesari este %s\n",time3);
        read(sd,user,100);
         printf("Userul fisierului este %s\n",user);


}

int Obtine_fisier(int alegere)
{
    if (write (sd, &alegere, 4) <= 0)
	{
	      perror ("[client]Eroare la write() spre server.\n");
	      return errno;
	}  
    /* Create file where data will be stored */
    int bytesReceived = 0;
    char recvBuff[256];
    memset(recvBuff, '0', sizeof(recvBuff));
    FILE *fp;
    char fisier[100];
    printf("Cititi numele fisierului pe care doriti sa il obtineti: ");
    scanf("%s",fisier);
    
    write(sd,fisier,100);

    fp = fopen(fisier, "ab"); 
    if(NULL == fp)
    {
        printf("Error opening file");
        return 1;
    }
    
    int blocuri;
    read(sd,&blocuri,sizeof(blocuri));
    /* Receive data in chunks of 256 bytes */
    printf("*************************\n");
    while(blocuri)
        {
	bytesReceived = read(sd, recvBuff, 256);
	//printf("Bytes received %d\n",bytesReceived);    
        fwrite(recvBuff, 1,bytesReceived,fp);
	blocuri--;
	}
    printf("\n\nFisier primit cu succes!\n");    
    printf("*************************\n");
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

int Adauga_fisier(int alegere)
{
	if (write (sd, &alegere, 4) <= 0)
	{
	      perror ("[client]Eroare la write() spre server.\n");
	      return errno;
	}  
	char msg[100];
	
	//trimitem numele fisierului	
	printf("Dati numele fisierlui pe care vreti sa il uploadati: ");
	scanf("%s",msg);	
	write(sd,msg,100);
        
        /* Open the file that we wish to transfer */
        FILE *fp = fopen(msg,"rb");
        if(fp==NULL)
        {
            printf("File opern error");
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
	  write(sd,&marime1,sizeof(marime));
	}
	else
	write(sd,&marime1,sizeof(marime));
	fseek(fp,0,SEEK_SET);
	
	 while(1)
        {
            /* First read file in chunks of 256 bytes */
            unsigned char buff[256]={0};
            int nread = fread(buff,1,256,fp);
            printf("Biti cititi: %d ", nread);        

            /* If read was success, send data. */
            if(nread > 0)
            {
                printf("Trimitem \n");
                write(sd, buff, nread);
            }

            /*
             * There is something tricky going on with read .. 
             * Either there was error, or we reached end of file.
             */
            if (nread < 256)
            {
                if (feof(fp))
                    printf("End of file\n");
                if (ferror(fp))
                    printf("Error reading\n");
		break;
            }
            

        }

}




int main (int argc, char *argv[])
{
  struct sockaddr_in server;	// structura folosita pentru conectare 

  /* exista toate argumentele in linia de comanda? */
  if (argc != 3)
    {
      printf ("Sintaxa: %s <adresa_server> <port>\n", argv[0]);
      return -1;
    }

  /* stabilim portul */
  port = atoi (argv[2]);

  /* cream socketul */
  if ((sd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
      perror ("Eroare la socket().\n");
      return errno;
    }

  /* umplem structura folosita pentru realizarea conexiunii cu serverul */
  /* familia socket-ului */
  server.sin_family = AF_INET;
  /* adresa IP a serverului */
  server.sin_addr.s_addr = inet_addr(argv[1]);
  /* portul de conectare */
  server.sin_port = htons (port);
  
  /* ne conectam la server */
  if (connect (sd, (struct sockaddr *) &server,sizeof (struct sockaddr)) == -1)
    {
      perror ("[client]Eroare la connect().\n");
      return errno;
    }

char u[20],p[100];
int choice,choice1,on=1,success=0,r;
char fisier[100];
char *director;
	
	while (success==0)
	{ 
		printf("Introduceti username-ul\n");
		scanf("%s",u);
		//trimitem username		
		write(sd,u,100);
		//citim si trimitem parola securizat
		Criptare();
		
		read(sd,&r,4);
		if (r==1 || r==2)
		{
			if (r==1)
			printf("Logare reusita ca user normal!\n\n");
			else printf("Logare reusita ca administrator!\n\n");
			success=1;	
			while(on==1)
  			{	  
			printf ("Meniu:\n");
			printf ("-------------------\n");
			printf ("1.Creeaza director\n");
			printf ("2.Afla directorul curent de lucru\n");
			printf ("3.Arata continut director server\n");
			printf ("4.Arata continut director client\n");
			printf ("5.Cauta un fisier\n");
			printf ("6.Afla detalii despre un fisier\n");
			printf ("7.Adauga fisier\n");
			printf ("8.Obtine fisier\n");
			
			if(r==2)
			{
				printf ("9.Adauga client in whitelist\n");
				printf ("10.Elimina client din whitelist\n");
				printf ("11.Afiseaza whitelist\n");
				printf ("12.quit\n");
			}
			else printf ("9.quit\n");
			printf ("--------------------\n");
			printf ("Introduceti alegerea dorita:\n");
			scanf("%d",&choice);
			switch (choice)
			{
			case 1:
			
				printf("Dati numele noului director \n");			    
				scanf("%s",dir);
				Creare_director(dir,choice);
				break;
			

			case 2:
			
				Afla_director(choice);
				break;
			
			case 3:
			
				Continut_director_server(choice);
				break;

			case 4:
			
				Continut_director_client();
				break;

			case 5:
			    
			
	   			printf("Dati numele fisierului ce doriti sa il cautati: \n");
	    			scanf("%s",fisier);
				myfind(choice,fisier);	     			            	break; 
			    				
			case 6:
			
				printf("Cititi fisierul despre care doriti sa aflati mai multe informatii: \n");
				scanf("%s",fisier);
				mystat(choice,fisier);
				break;

			case 7:
			 
				Adauga_fisier(choice);
				break;	
			
			case 8:
			  
				Obtine_fisier(choice);
				break;	
			
			case 9:			
			if(r==1)
			{
				write(sd,&choice,4);
				return 0;
			}
			if(r==2)
			{
				write(sd,&choice,4);
				printf("Cititi numele noului utilizator: ");
				scanf("%s",u);
				if (write (sd,u,100) <= 0)
				{
				      perror ("[client]Eroare la write() spre server.\n");
				      return errno;
				}  
				printf("Cititi parola utilizatorului: ");
				scanf("%s",p);
				if (write (sd,p,100) <= 0)
				{
				      perror ("[client]Eroare la write() spre server.\n");
				      return errno;
				}  

			}	
			
			break;
			case 10:
			if( r==2 )
			{
				
				write(sd,&choice,4);
				printf("Cititi numele utilizatorului ce doriti sa il stergeti: ");
				scanf("%s",u);
				if (write (sd,u,100) <= 0)
				{
				      perror ("[client]Eroare la write() spre server.\n");
				      return errno;
				}  
			break; 
				
			}

			case 12:
			if( r==2 )
			{
				write(sd,&choice,4);
				return 0;				
				break;
			}
			case 11:
			if( r==2 )
			{
				write(sd,&choice,4);
				read(sd,&nr,4);
				while(nr)
				{
				  read(sd,msg,100);
				  printf("%s",msg);
				  nr--;
				}
				
			}
			break;
			
			
			default:
			printf("Ati introdus o alegere gresita!\n");
			
			}//end switch
			}//enwhile on
			
  		}//endif
		else
			{
		
			  printf("Logare nereusita!\n");
			  printf("Vreti sa incercati cu alt user? Da/Nu\n");
			  char s[2];
			  int loop=0;
			  while (loop==0)
			  {
			    printf("Introduceti alegere: ");
			    scanf("%s",s);
			    if(strcmp(s,"Nu")==0) { success=1; loop=1; }
			    else if(strcmp(s,"Da")==0) {success=0; loop=1; }
				    else printf("Ati introdus o alegere gresita!\n");
			  }	
			  loop=0;		
			}
	}//endwhile success
  



  /* inchidem conexiunea, am terminat */
  close (sd);
}

