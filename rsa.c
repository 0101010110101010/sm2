#if 0

https://blog.csdn.net/ivalue/article/details/82625641

1）生成一个密钥：
openssl genrsa -out prikey.pem 1024
这里-out指定生成文件的。需要注意的是这个文件包含了公钥和密钥两部分，也就是说这个文件即可用来加密也可以用来解密。后面的1024是生成密钥的长度。
2）openssl可以将这个文件中的公钥提取出来：
openssl rsa -in prikey.pem -pubout -out pubkey.pem
-in指定输入文件，-out指定提取生成公钥的文件名。至此，我们手上就有了一个公钥，一个私钥（包含公钥）。现在可以将用公钥来加密文件了。
3）在目录中创建一个hello的文本文件，然后利用此前生成的公钥加密文件：
openssl rsautl -encrypt -in hello -inkey pubkey.pem -pubin -out hello.en
-in指定要加密的文件，-inkey指定密钥，-pubin表明是用纯公钥文件加密，-out为加密后的文件。
4）解密文件：
openssl rsautl -decrypt -in hello.en -inkey test.key -out hello.de
-in指定被加密的文件，-inkey指定私钥文件，-out为解密后的文件。
#endif
#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <errno.h>

#include <openssl/rsa.h>

#include <openssl/pem.h>

#include <openssl/err.h>

 

#define pubkey_path  "pubkey.pem"

#define prikey_path "prikey.pem"

 

char *auth_encrypt(char *data, char *key_path);    //加密

char *auth_decrypt(char *data, char *key_path);    //解密

	int length = 0;	
 

// encrypt

char *auth_encrypt(char *data, char *key_path) {

	char *encrypted_data = NULL;

	RSA *rsa_key = NULL;

	FILE *file = NULL;


 

 

	//1.打开秘钥文件

	if ((file = fopen(key_path, "rb")) == NULL) {

    	perror("fopen() error");

    	goto End;

	}

 

	//2.从公钥中获取 加密的秘钥

	if ((rsa_key = PEM_read_RSA_PUBKEY(file, NULL,NULL,NULL )) == NULL){

		ERR_print_errors_fp(stdout);

    	goto End;

	}

 

	length = strlen(data);

	

	encrypted_data = (char *)malloc(256);

	if (!encrypted_data) {

		perror("malloc() error");

		goto End;

	}

	

	memset(encrypted_data, 0, 256);

	

	//3. encrypt
int ret = RSA_public_encrypt(length, (unsigned char*)data, (unsigned char*)encrypted_data, rsa_key, RSA_PKCS1_PADDING);
	if ( ret< 0) {

		perror("RSA_public_encrypt()");

		goto End;

	}
	printf("encr = %d\n",ret);

 

End:

	if (rsa_key) {

		RSA_free(rsa_key);

	}

	if (file) {

		fclose(file);

	}

	

	return encrypted_data;

}

 

// decrypt

char *auth_decrypt(char *data, char *key_path) {

	char *decrypted_data = NULL;

	RSA *rsa_key = NULL;

	FILE *file = NULL;

 

	// 1.打开秘钥文件

    if ((file = fopen(key_path, "rb")) == NULL) {

        perror("fopen() error");

        goto End;

    }   

 

    // 2.从私钥中获取 解密的秘钥

    if ((rsa_key = PEM_read_RSAPrivateKey(file, NULL,NULL,NULL )) == NULL){

        ERR_print_errors_fp(stdout);

        goto End;

    }

 

    decrypted_data = (char *)malloc(256);

    if (!decrypted_data) {

        perror("malloc() error");

        goto End;

    }   

        

    memset(decrypted_data, 0, 256);

 

	// 3.decrypt
int ret = RSA_private_decrypt(128, (unsigned char*)data, (unsigned char*)decrypted_data, rsa_key, RSA_PKCS1_PADDING);
	if(ret < 0) {

		perror("RSA_public_decrypt() error");
		printf("ret=%d\n",ret);

		goto End;

	}

 

End:

    if (rsa_key) {

        RSA_free(rsa_key);

    }   

    if (file) {

        fclose(file);

    }   

        

    return decrypted_data;

}

 

 

int main(void)

{

	char *source = "{\"cip\": \"20.31数数据\"}";

	char *ptf_en, *ptf_de;

	printf("source is :%s\n", source);

 

     //1.加密

    ptf_en = auth_encrypt(source, pubkey_path);

    if (ptf_en  == NULL){

        return 0;

    }

	else {

    	printf("ptf_en is   :%s\n", ptf_en);

    }

     //2.解密

	ptf_de = auth_decrypt(ptf_en, prikey_path);

	if (ptf_de == NULL){

        return 0;

	}

	else {

    	printf("ptf_de is   :%s\n", ptf_de);

	}

    if(ptf_en) free(ptf_en);

    if(ptf_de) free(ptf_de);

 

    return 0;

}
