/**
 * \file bignum.h
 *
 * \brief  Multi-precision integer library
 *
 *  Copyright (C) 2006-2013, Brainspark B.V.
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
#ifndef POLARSSL_BIGNUM_H
#define POLARSSL_BIGNUM_H

#include <linux/types.h>

/*
 * Convert between bits/chars and number of limbs
 */
#define BITS_TO_LIMBS(i)  (((i) + biL - 1) / biL)
#define CHARS_TO_LIMBS(i) (((i) + ciL - 1) / ciL)

#define POLARSSL_ERR_MPI_FILE_IO_ERROR                     -0x0002  /**< An error occurred while reading from or writing to a file. */
#define POLARSSL_ERR_MPI_BAD_INPUT_DATA                    -0x0004  /**< Bad input parameters to function. */
#define POLARSSL_ERR_MPI_INVALID_CHARACTER                 -0x0006  /**< There is an invalid character in the digit string. */
#define POLARSSL_ERR_MPI_BUFFER_TOO_SMALL                  -0x0008  /**< The buffer is too small to write to. */
#define POLARSSL_ERR_MPI_NEGATIVE_VALUE                    -0x000A  /**< The input arguments are negative or result in illegal output. */
#define POLARSSL_ERR_MPI_DIVISION_BY_ZERO                  -0x000C  /**< The input argument for division is zero, which is not allowed. */
#define POLARSSL_ERR_MPI_NOT_ACCEPTABLE                    -0x000E  /**< The input arguments are not acceptable. */
#define POLARSSL_ERR_MPI_MALLOC_FAILED                     -0x0010  /**< Memory allocation failed. */

#define MPI_CHK(f) do { if( ( ret = f ) != 0 ) goto cleanup; } while( 0 )


/*
 * Maximum size MPIs are allowed to grow to in number of limbs.
 */
#define POLARSSL_MPI_MAX_LIMBS                             10000

/*
 * Maximum window size used for modular exponentiation. Default: 6
 * Minimum value: 1. Maximum value: 6.
 *
 * Result is an array of ( 2 << POLARSSL_MPI_WINDOW_SIZE ) MPIs used
 * for the sliding window calculation. (So 64 by default)
 *
 * Reduction in size, reduces speed.
 */
#define POLARSSL_MPI_WINDOW_SIZE                           6        /**< Maximum windows size used. */

/*
 * Maximum size of MPIs allowed in bits and bytes for user-MPIs.
 * ( Default: 512 bytes => 4096 bits, Maximum tested: 2048 bytes => 16384 bits )
 *
 * Note: Calculations can results temporarily in larger MPIs. So the number
 * of limbs required (POLARSSL_MPI_MAX_LIMBS) is higher.
 */
#define POLARSSL_MPI_MAX_SIZE                              512      /**< Maximum number of bytes for usable MPIs. */

#define POLARSSL_MPI_MAX_BITS                              ( 8 * POLARSSL_MPI_MAX_SIZE )    /**< Maximum number of bits for usable MPIs. */

/*
 * When reading from files with mpi_read_file() and writing to files with
 * mpi_write_file() the buffer should have space
 * for a (short) label, the MPI (in the provided radix), the newline
 * characters and the '\0'.
 *
 * By default we assume at least a 10 char label, a minimum radix of 10
 * (decimal) and a maximum of 4096 bit numbers (1234 decimal chars).
 * Autosized at compile time for at least a 10 char label, a minimum radix
 * of 10 (decimal) for a number of POLARSSL_MPI_MAX_BITS size.
 *
 * This used to be statically sized to 1250 for a maximum of 4096 bit
 * numbers (1234 decimal chars).
 *
 * Calculate using the formula:
 *  POLARSSL_MPI_RW_BUFFER_SIZE = ceil(POLARSSL_MPI_MAX_BITS / ln(10) * ln(2)) +
 *                                LabelSize + 6
 */
#define POLARSSL_MPI_MAX_BITS_SCALE100          ( 100 * POLARSSL_MPI_MAX_BITS )
#define LN_2_DIV_LN_10_SCALE100                 332
#define POLARSSL_MPI_RW_BUFFER_SIZE             ( ((POLARSSL_MPI_MAX_BITS_SCALE100 + LN_2_DIV_LN_10_SCALE100 - 1) / LN_2_DIV_LN_10_SCALE100) + 10 + 6 )


#define POLARSSL_HAVE_LONGLONG
#define POLARSSL_HAVE_INT32
typedef int32_t t_sint;
typedef uint32_t t_uint;
typedef unsigned long long t_udbl;

/**
 * \brief          MPI structure
 */
typedef struct
{
    int s;              /*!<  integer sign      */
    size_t n;           /*!<  total # of limbs  */
    t_uint *p;          /*!<  pointer to limbs  */
} mpi;

/**
 * \brief           Initialize one MPI
 *
 * \param X         One MPI to initialize.
 */
void mpi_init( mpi *X );

/**
 * \brief          Unallocate one MPI
 *
 * \param X        One MPI to unallocate.
 */
void mpi_free( mpi *X );

/**
 * \brief          Enlarge to the specified number of limbs
 *
 * \param X        MPI to grow
 * \param nblimbs  The target number of limbs
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int mpi_grow( mpi *X, size_t nblimbs );

/**
 * \brief          Set value from integer
 *
 * \param X        MPI to set
 * \param z        Value to use
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int mpi_lset( mpi *X, t_sint z );

/**
 * \brief          Return the number of zero-bits before the least significant
 *                 '1' bit
 *
 * Note: Thus also the zero-based index of the least significant '1' bit
 *
 * \param X        MPI to use
 */
size_t mpi_lsb( const mpi *X );

/**
 * \brief          Return the number of bits up to and including the most
 *                 significant '1' bit'
 *
 * Note: Thus also the one-based index of the most significant '1' bit
 *
 * \param X        MPI to use
 */
size_t mpi_msb( const mpi *X );

/**
 * \brief          Return the total size in bytes
 *
 * \param X        MPI to use
 */
size_t mpi_size( const mpi *X );

/**
 * \brief          Import from an ASCII string
 *
 * \param X        Destination MPI
 * \param radix    Input numeric base
 * \param s        Null-terminated string buffer
 *
 * \return         0 if successful, or a POLARSSL_ERR_MPI_XXX error code
 */
int mpi_read_string( mpi *X, int radix, const char *s );

/**
* \brief          Import X from unsigned binary data, big endian
*
* \param X        Destination MPI
* \param buf      Input buffer
* \param buflen   Input buffer size
*
* \return         0 if successful,
*                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
*/
int mpi_read_binary( mpi *X, const unsigned char *buf, size_t buflen );

/**
* \brief          Export X into unsigned binary data, big endian
*
* \param X        Source MPI
* \param buf      Output buffer
* \param buflen   Output buffer size
*
* \return         0 if successful,
*                 POLARSSL_ERR_MPI_BUFFER_TOO_SMALL if buf isn't large enough
*/
int mpi_write_binary( const mpi *X, unsigned char *buf, size_t buflen );

/**
 * \brief          Left-shift: X <<= count
 *
 * \param X        MPI to shift
 * \param count    Amount to shift
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int mpi_shift_l( mpi *X, size_t count );

/**
 * \brief          Right-shift: X >>= count
 *
 * \param X        MPI to shift
 * \param count    Amount to shift
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int mpi_shift_r( mpi *X, size_t count );

/**
 * \brief          Compare unsigned values
 *
 * \param X        Left-hand MPI
 * \param Y        Right-hand MPI
 *
 * \return         1 if |X| is greater than |Y|,
 *                -1 if |X| is lesser  than |Y| or
 *                 0 if |X| is equal to |Y|
 */
int mpi_cmp_abs( const mpi *X, const mpi *Y );

/**
 * \brief          Compare signed values
 *
 * \param X        Left-hand MPI
 * \param Y        Right-hand MPI
 *
 * \return         1 if X is greater than Y,
 *                -1 if X is lesser  than Y or
 *                 0 if X is equal to Y
 */
int mpi_cmp_mpi( const mpi *X, const mpi *Y );

/**
 * \brief          Compare signed values
 *
 * \param X        Left-hand MPI
 * \param z        The integer value to compare to
 *
 * \return         1 if X is greater than z,
 *                -1 if X is lesser  than z or
 *                 0 if X is equal to z
 */
int mpi_cmp_int( const mpi *X, t_sint z );

/**
 * \brief          Unsigned addition: X = |A| + |B|
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int mpi_add_abs( mpi *X, const mpi *A, const mpi *B );

/**
 * \brief          Unsigned subtraction: X = |A| - |B|
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_NEGATIVE_VALUE if B is greater than A
 */
int mpi_sub_abs( mpi *X, const mpi *A, const mpi *B );

/**
 * \brief          Signed addition: X = A + B
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int mpi_add_mpi( mpi *X, const mpi *A, const mpi *B );

/**
 * \brief          Signed subtraction: X = A - B
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int mpi_sub_mpi( mpi *X, const mpi *A, const mpi *B );

/**
 * \brief          Signed addition: X = A + b
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param b        The integer value to add
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int mpi_add_int( mpi *X, const mpi *A, t_sint b );

/**
 * \brief          Signed subtraction: X = A - b
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param b        The integer value to subtract
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int mpi_sub_int( mpi *X, const mpi *A, t_sint b );

/**
 * \brief          Baseline multiplication: X = A * B
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int mpi_mul_mpi( mpi *X, const mpi *A, const mpi *B );

/**
 * \brief          Baseline multiplication: X = A * b
 *                 Note: despite the functon signature, b is treated as a
 *                 t_uint.  Negative values of b are treated as large positive
 *                 values.
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param b        The integer value to multiply with
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed
 */
int mpi_mul_int( mpi *X, const mpi *A, t_sint b );

/**
 * \brief          Division by mpi: A = Q * B + R
 *
 * \param Q        Destination MPI for the quotient
 * \param R        Destination MPI for the rest value
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 POLARSSL_ERR_MPI_DIVISION_BY_ZERO if B == 0
 *
 * \note           Either Q or R can be NULL.
 */
int mpi_div_mpi( mpi *Q, mpi *R, const mpi *A, const mpi *B );

/**
 * \brief          Division by int: A = Q * b + R
 *
 * \param Q        Destination MPI for the quotient
 * \param R        Destination MPI for the rest value
 * \param A        Left-hand MPI
 * \param b        Integer to divide by
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 POLARSSL_ERR_MPI_DIVISION_BY_ZERO if b == 0
 *
 * \note           Either Q or R can be NULL.
 */
int mpi_div_int( mpi *Q, mpi *R, const mpi *A, t_sint b );

/**
 * \brief          Modulo: R = A mod B
 *
 * \param R        Destination MPI for the rest value
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 POLARSSL_ERR_MPI_DIVISION_BY_ZERO if B == 0,
 *                 POLARSSL_ERR_MPI_NEGATIVE_VALUE if B < 0
 */
int mpi_mod_mpi( mpi *R, const mpi *A, const mpi *B );

/**
 * \brief          Modulo: r = A mod b
 *
 * \param r        Destination t_uint
 * \param A        Left-hand MPI
 * \param b        Integer to divide by
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 POLARSSL_ERR_MPI_DIVISION_BY_ZERO if b == 0,
 *                 POLARSSL_ERR_MPI_NEGATIVE_VALUE if b < 0
 */
int mpi_mod_int( t_uint *r, const mpi *A, t_sint b );

/**
 * \brief          Sliding-window exponentiation: X = A^E mod N
 *
 * \param X        Destination MPI 
 * \param A        Left-hand MPI
 * \param E        Exponent MPI
 * \param N        Modular MPI
 * \param _RR      Speed-up MPI used for recalculations
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_MALLOC_FAILED if memory allocation failed,
 *                 POLARSSL_ERR_MPI_BAD_INPUT_DATA if N is negative or even or if
 *                 E is negative
 *
 * \note           _RR is used to avoid re-computing R*R mod N across
 *                 multiple calls, which speeds up things a bit. It can
 *                 be set to NULL if the extra performance is unneeded.
 */
int mpi_exp_mod( mpi *X, const mpi *A, const mpi *E, const mpi *N, mpi *_RR );


#endif
