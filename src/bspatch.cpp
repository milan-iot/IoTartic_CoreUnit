/*-
 * Copyright 2003-2005 Colin Percival
 * Copyright 2012 Matthew Endsley
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions 
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <limits.h>

#ifdef ESP_PLATFORM
#include <sdkconfig.h>
#endif

#ifndef CONFIG_BSDIFF_BSPATCH_BUF_SIZE
#define CONFIG_BSDIFF_BSPATCH_BUF_SIZE (8 * 1024)
#endif


#include "bspatch.h"

/* CONFIG_BSDIFF_BSPATCH_BUF_SIZE can't be smaller than 8 */
#if 7 >= CONFIG_BSDIFF_BSPATCH_BUF_SIZE
#error "Error, CONFIG_BSDIFF_BSPATCH_BUF_SIZE can't be smaller than 8"
#endif

#define BUF_SIZE 128
#define ERROR_BSPATCH (-1)

#define RETURN_IF_NON_ZERO(expr)        \
    do                                  \
    {                                   \
        const int ret = (expr);         \
        if (ret) {                      \
            return ret;                 \
        }                               \
    } while(0)

#define min(A, B) ((A) < (B) ? (A) : (B))

static int64_t offtin(uint8_t *buf)
{
	int64_t y;

	y=buf[7]&0x7F;
	y=y*256;y+=buf[6];
	y=y*256;y+=buf[5];
	y=y*256;y+=buf[4];
	y=y*256;y+=buf[3];
	y=y*256;y+=buf[2];
	y=y*256;y+=buf[1];
	y=y*256;y+=buf[0];

	if(buf[7]&0x80) y=-y;

	return y;
}

int bspatch_read_old(const struct bspatch_stream_i* stream, File file, void* buffer, int pos, int length)
{
	file.seek(pos);
	int len_read = file.readBytes((char *)buffer, length);

	return 0;
}

int bspatch_read_patch(const struct bspatch_stream_i* stream, File file, void* buffer, int pos, int length)
{
	file.seek(pos);
	int len_read = file.readBytes((char *)buffer, length);
	
	return 0;
}

int bspatch_write_new(const struct bspatch_stream_n* stream, File file, const void* buffer, int length)
{
	file.write((uint8_t *)buffer, length);
	
	return 0;
}

void bspatch_fw(int64_t oldsize, int64_t newsize)
{
	struct bspatch_stream_i patch_stream, old_stream;
	struct bspatch_stream_n new_stream;

	old_stream.read = bspatch_read_old;
	patch_stream.read = bspatch_read_patch;
	new_stream.write = bspatch_write_new;

	Serial.println(bspatch(&old_stream, oldsize, &new_stream, newsize, &patch_stream));

	/*
	stream.read = __read;
	oldstream.read = old_read;
	newstream.write = new_write;
	stream.opaque = f;
	oldstream.opaque = old;
	struct NewCtx ctx = { .pos_write = 0, .new = new };
	newstream.opaque = &ctx;*/
}

/*
 * Returns 0 on success
 * Returns -1 on error in patching logic
 * Returns any non-zero return code from stream read() and write() functions (which imply error)
 */
int bspatch(struct bspatch_stream_i *old, int64_t oldsize, struct bspatch_stream_n *neww, int64_t newsize, struct bspatch_stream_i* stream)
{
	uint8_t buf[BUF_SIZE];
	int64_t oldpos,newpos,patchpos;
	int64_t ctrl[3];
	int64_t i,k;
	int64_t towrite;
	const int64_t half_len = BUF_SIZE / 2;

	File file_old = SD.open("/tmp/fw_old.bin");
	if(!file_old || file_old.isDirectory()){
		Serial.println("- failed to open file_old for reading");
		return 0;
	}
	File file_patch = SD.open("/tmp/fw_patch.bin");
	if(!file_patch || file_patch.isDirectory()){
		Serial.println("- failed to open file_patch for reading");
		return 0;
	}
	File file_new = SD.open("/firmware.bin", FILE_APPEND);
	if(!file_new || file_new.isDirectory()){
		Serial.println("- failed to open file_new for appending");
		return 0;
	}

	oldpos=0;newpos=0;patchpos=0;
	while(newpos<newsize) {
		/* Read control data */
		for(i=0;i<=2;i++) {
			RETURN_IF_NON_ZERO(stream->read(stream, file_patch, buf, patchpos + i*8, 8));
			ctrl[i]=offtin(buf);
		}

		patchpos+=24;

		/* Sanity-check */
		if (ctrl[0]<0 || ctrl[0]>INT_MAX ||
			ctrl[1]<0 || ctrl[1]>INT_MAX ||
			newpos+ctrl[0]>newsize)
			return ERROR_BSPATCH;

		/* Read diff string and add old data on the fly */
		i = ctrl[0];
		while (i) {
			towrite = min(i, half_len);
			RETURN_IF_NON_ZERO(stream->read(stream, file_patch, &buf[half_len], patchpos + (ctrl[0] - i), towrite));
			RETURN_IF_NON_ZERO(old->read(old, file_old, buf, oldpos + (ctrl[0] - i), towrite));

			for(k=0;k<towrite;k++)
				buf[k + half_len] += buf[k];

			RETURN_IF_NON_ZERO(neww->write(neww, file_new, &buf[half_len], towrite));
			i -= towrite;
		}

		/* Adjust pointers */
		newpos+=ctrl[0];
		oldpos+=ctrl[0];
		patchpos+=ctrl[0];

		/* Sanity-check */
		if(newpos+ctrl[1]>newsize)
			return ERROR_BSPATCH;

		/* Read extra string and copy over to new on the fly*/
		i = ctrl[1];
		while (i) {
			towrite = min(i, BUF_SIZE);
			RETURN_IF_NON_ZERO(stream->read(stream, file_patch, buf, patchpos + (ctrl[1] - i), towrite));
			RETURN_IF_NON_ZERO(neww->write(neww, file_new, buf, towrite));
			i -= towrite;
		}

		/* Adjust pointers */
		patchpos+=ctrl[1];
		newpos+=ctrl[1];
		oldpos+=ctrl[2];
	};

	file_old.close();
	file_patch.close();
	file_new.close();

	return 0;
}

#if defined(BSPATCH_EXECUTABLE)

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

static int __read(const struct bspatch_stream* stream, void* buffer, int length)
{
	if (fread(buffer, 1, length, (FILE*)stream->opaque) != length) {
		return -1;
	}
	return 0;
}

static int old_read(const struct bspatch_stream_i* stream, void* buffer, int pos, int length) {
	uint8_t* old;
	old = (uint8_t*)stream->opaque;
	memcpy(buffer, old + pos, length);
	return 0;
}

struct NewCtx {
	uint8_t* new;
	int pos_write;
};

static int new_write(const struct bspatch_stream_n* stream, const void *buffer, int length) {
	struct NewCtx* new;
	new = (struct NewCtx*)stream->opaque;
	memcpy(new->new + new->pos_write, buffer, length);
	new->pos_write += length;
	return 0;
}

int main(int argc,char * argv[])
{
	FILE * f;
	int fd;
	uint8_t *old, *new;
	int64_t oldsize, newsize;
	struct bspatch_stream stream;
	struct bspatch_stream_i oldstream;
	struct bspatch_stream_n newstream;
	struct stat sb;

	if(argc!=5) errx(1,"usage: %s oldfile newfile newsize patchfile\n",argv[0]);

	newsize = atoi(argv[3]);

	/* Open patch file */
	if ((f = fopen(argv[4], "r")) == NULL)
		err(1, "fopen(%s)", argv[4]);

	/* Close patch file and re-open it at the right places */
	if(((fd=open(argv[1],O_RDONLY,0))<0) ||
		((oldsize=lseek(fd,0,SEEK_END))==-1) ||
		((old=malloc(oldsize+1))==NULL) ||
		(lseek(fd,0,SEEK_SET)!=0) ||
		(read(fd,old,oldsize)!=oldsize) ||
		(fstat(fd, &sb)) ||
		(close(fd)==-1)) err(1,"%s",argv[1]);
	if((new=malloc(newsize+1))==NULL) err(1,NULL);

	stream.read = __read;
	oldstream.read = old_read;
	newstream.write = new_write;
	stream.opaque = f;
	oldstream.opaque = old;
	struct NewCtx ctx = { .pos_write = 0, .new = new };
	newstream.opaque = &ctx;
	if (bspatch(&oldstream, oldsize, &newstream, newsize, &stream))
		errx(1, "bspatch");

	/* Clean up */
	fclose(f);

	/* Write the new file */
	if(((fd=open(argv[2],O_CREAT|O_TRUNC|O_WRONLY,sb.st_mode))<0) ||
		(write(fd,new,newsize)!=newsize) || (close(fd)==-1))
		err(1,"%s",argv[2]);

	free(new);
	free(old);

	return 0;
}

#endif
