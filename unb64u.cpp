
/*
 * Copyright (c) 2017, Brian Leishman
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * USAGE INSTRUCTIONS:
 *
 * make sure libmysqlclient-dev is installed:
 * apt-get install libmysqlclient-dev
 *
 * Replace "/usr/lib/mysql/plugin" with your MySQL plugins directory (can be found by running "select @@plugin_dir;")
 * gcc -O3 -std=c++11 -I/usr/include/mysql -o unb64u.so -shared unb64u.cpp -fPIC && cp unb64u.so /usr/lib/mysql/plugin/unb64u.so
 *
 * Then, on the server:
 * create function`unb64u`returns string soname'unb64u.so';
 *
 * And use/test like:
 * select `unb64u`('eWVldA'); -- should return 'yeet'
 *
 * Yeet!
 *
 */

#include <my_global.h>
#include <my_sys.h>
#include <mysql.h>
#include <ctype.h>
#include <string.h>
#include <cstring>

/* Prototypes */

extern "C" {
   std::string b64decode_mod( const void *key, int len, unsigned int seed );
   my_bool unb64u_init( UDF_INIT* initid, UDF_ARGS* args, char* message );
   char* unb64u( UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error );
}

const unsigned char base64_dtable[256] = {
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 62  , 0x80, 62  , 0x80, 63  ,
	52  , 53  , 54  , 55  , 56  , 57  , 58  , 59  , 60  , 61  , 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0   , 1   , 2   , 3   , 4   , 5   , 6   , 7   , 8   , 9   , 10  , 11  , 12  , 13  , 14  ,
	15  , 16  , 17  , 18  , 19  , 20  , 21  , 22  , 23  , 24  , 25  , 0x80, 0x80, 0x80, 0x80, 63  ,
	0x80, 26  , 27  , 28  , 29  , 30  , 31  , 32  , 33  , 34  , 35  , 36  , 37  , 38  , 39  , 40  ,
	41  , 42  , 43  , 44  , 45  , 46  , 47  , 48  , 49  , 50  , 51  , 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80
};

std::string b64decode_mod(const unsigned char *table, const void* data, const size_t len)
{
	unsigned char* p = (unsigned char*)data;
	int pad = len > 0 && (len % 4 || p[len - 1] == '=');
	const size_t L = ((len + 3) / 4 - pad) * 4;
	std::string str;
	str.resize(3*((len+3)/4));

	int j = 0;
	for (size_t i = 0; i < L; i += 4)
	{
		int n = table[p[i]] << 18 | table[p[i + 1]] << 12 | table[p[i + 2]] << 6 | table[p[i + 3]];
		str[j++] = n >> 16;
		str[j++] = n >> 8 & 0xFF;
		str[j++] = n & 0xFF;
	}
	if (pad)
	{
		int n = table[p[L]] << 18 | table[p[L + 1]] << 12;
		str[j++] = n >> 16;

		if (len > L + 2 && p[L + 2] != '=')
		{
			n |= table[p[L + 2]] << 6;
			str[j++] = n >> 8 & 0xFF;
		}
	}

	str.resize(j);
	return std::move(str);
}

my_bool
unb64u_init( UDF_INIT* initid, UDF_ARGS* args, char* message) {
   if (args->arg_count == 0 ) {
      strcpy(message, "`unb64u`() requires 1 parameters: the string to be encoded");
      return 1;
   }
   initid->maybe_null = 1;      /* The result will never be NULL */
   return 0;
}

char*
unb64u( UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error ) {
	if (args->args[0] == NULL) {
		*is_null = 1;
		return 0;
	}

	std::string r = b64decode_mod(base64_dtable, args->args[0], args->lengths[0]);

	*length = r.size();
	char *c = (char*) malloc(sizeof (char) * *length);
	memcpy(c, &r[0u], *length);
	return c;
}