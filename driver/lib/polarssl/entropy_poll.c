/*
 *  Platform-specific and custom entropy polling functions
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <linux/kernel.h>
#include <linux/fs.h>

#if !defined(POLARSSL_CONFIG_FILE)
#include "config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_ENTROPY_C)

#include "entropy.h"
#include "entropy_poll.h"

#if defined(POLARSSL_TIMING_C)
#include "timing.h"
#endif
#if defined(POLARSSL_HAVEGE_C)
#include "havege.h"
#endif

#if !defined(POLARSSL_NO_PLATFORM_ENTROPY)
/*
#include <stdio.h>

int platform_entropy_poll( void *data,
                           unsigned char *output, size_t len, size_t *olen )
{
    FILE *file;
    size_t ret;
    ((void) data);

    *olen = 0;

    file = fopen( "/dev/urandom", "rb" );
    if( file == NULL )
        return( POLARSSL_ERR_ENTROPY_SOURCE_FAILED );

    ret = fread( output, 1, len, file );
    if( ret != len )
    {
        fclose( file );
        return( POLARSSL_ERR_ENTROPY_SOURCE_FAILED );
    }

    fclose( file );
    *olen = len;

    return( 0 );
}
*/

int platform_entropy_poll( void *data,
                           unsigned char *output, size_t len, size_t *olen ) //thatskriptkid | very happy done IO in kernel space (:
{
    struct file *filp;
    size_t       ret;
    loff_t       pos=0;
    ssize_t      bytes_read;
    
    ((void) data);

    *olen = 0;

    filp = filp_open("/dev/urandom",O_RDONLY,0);
    
    if(IS_ERR(filp))
		printk(KERN_WARNING "filp_open() failed!\n");
	else
		printk(KERN_WARNING "filp_open() success!\n");
	
	bytes_read = vfs_read(filp, output, len, &pos); 
	
	if (bytes_read<0) 
		printk(KERN_WARNING "vfs_read failed\n");
	else
		printk(KERN_WARNING "bytes_read = %d \n",((int)bytes_read));
	
	
    filp_close(filp,NULL);
    
    *olen = len;

    return 0;
}

#endif /* !POLARSSL_NO_PLATFORM_ENTROPY */

#if defined(POLARSSL_TIMING_C)
int hardclock_poll( void *data,
                    unsigned char *output, size_t len, size_t *olen )
{
    unsigned long timer = hardclock();
    ((void) data);
    *olen = 0;

    if( len < sizeof(unsigned long) )
        return( 0 );

    memcpy( output, &timer, sizeof(unsigned long) );
    *olen = sizeof(unsigned long);

    return( 0 );
}
#endif /* POLARSSL_TIMING_C */

#if defined(POLARSSL_HAVEGE_C)
int havege_poll( void *data,
                 unsigned char *output, size_t len, size_t *olen )
{
    havege_state *hs = (havege_state *) data;
    *olen = 0;

    if( havege_random( hs, output, len ) != 0 )
        return( POLARSSL_ERR_ENTROPY_SOURCE_FAILED );

    *olen = len;

    return( 0 );
}
#endif /* POLARSSL_HAVEGE_C */

#endif /* POLARSSL_ENTROPY_C */
