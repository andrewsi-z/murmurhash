//-----------------------------------------------------------------------------
// MurmurHash2 was written by Austin Appleby, and is placed in the public
// domain. The author hereby disclaims copyright to this source code.

// Note - This code makes a few assumptions about how your machine behaves -

// 1. We can read a 4-byte value from any address without crashing
// 2. sizeof(int) == 4

// And it has a few limitations -

// 1. It will not work incrementally.
// 2. It will not produce the same results on little-endian and big-endian
//    machines.

#include "murmurhash/MurmurHash2.h"
//#include <inttypes.h>

//-----------------------------------------------------------------------------
// Platform-specific functions and macros

// Microsoft Visual Studio

#if defined(_MSC_VER)

#define BIG_CONSTANT(x) (x)
#define FORCE_INLINE	__forceinline

// Other compilers

#else	// defined(_MSC_VER)

#define BIG_CONSTANT(x) (x##LLU)

#define FORCE_INLINE

#endif // !defined(_MSC_VER)

/* Based on Murmurhash3 implementation to support consistent results on systems
   with different byteorder */

/* NO-OP for little-endian platforms */
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
# if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#   define BYTESWAP32(x) (x)
#   define BYTESWAP64(x) (x)
# endif
/* if __BYTE_ORDER__ is not predefined (like FreeBSD), use arch */
#elif defined(__i386)  || defined(__x86_64) \
  ||  defined(__alpha) || defined(__vax)

# define BYTESWAP32(x) (x)
# define BYTESWAP64(x) (x)
/* use __builtin_bswap32 if available */
#elif defined(__GNUC__) || defined(__clang__)
# ifdef __has_builtin
#    if __has_builtin(__builtin_bswap32)
#       define BYTESWAP32(x) __builtin_bswap32(x)
#    endif // __has_builtin(__builtin_bswap32)
#    if __has_builtin(__builtin_bswap64)
#       define BYTESWAP64(x) __builtin_bswap64(x)
#    endif // __has_builtin(__builtin_bswap64)
# endif // __has_builtin
#endif // defined(__GNUC__) || defined(__clang__)
/* last resort (big-endian w/o __builtin_bswap) */
#ifndef BYTESWAP32
# define BYTESWAP32(x)   ((((x)&0xFF)<<24) \
         |(((x)>>24)&0xFF) \
         |(((x)&0x0000FF00)<<8)    \
         |(((x)&0x00FF0000)>>8)    )
#endif
#ifndef BYTESWAP64
# define BYTESWAP64(x)                               \
        (((uint64_t)(x) << 56) |                           \
         (((uint64_t)(x) << 40) & 0X00FF000000000000ULL) | \
         (((uint64_t)(x) << 24) & 0X0000FF0000000000ULL) | \
         (((uint64_t)(x) << 8)  & 0X000000FF00000000ULL) | \
         (((uint64_t)(x) >> 8)  & 0X00000000FF000000ULL) | \
         (((uint64_t)(x) >> 24) & 0X0000000000FF0000ULL) | \
         (((uint64_t)(x) >> 40) & 0X000000000000FF00ULL) | \
         ((uint64_t)(x)  >> 56))
#endif

//-----------------------------------------------------------------------------
// Block read - if your platform needs to do endian-swapping or can only
// handle aligned reads, do the conversion here

FORCE_INLINE uint32_t getblock2(const uint32_t * p, int i) {
    return BYTESWAP32(p[i]);
}

FORCE_INLINE uint64_t getblock2(const uint64_t * p, int i) {
    return BYTESWAP64(p[i]);
}

//-----------------------------------------------------------------------------

uint32_t MurmurHash2 ( const void * key, int len, uint32_t seed )
{
  // 'm' and 'r' are mixing constants generated offline.
  // They're not really 'magic', they just happen to work well.

  const uint32_t m = 0x5bd1e995;
  const int r = 24;

  // Initialize the hash to a 'random' value

  uint32_t h = seed ^ len;

  // Mix 4 bytes at a time into the hash

  const unsigned char * data = (const unsigned char *)key;

  while(len >= 4)
  {
    uint32_t k = *(uint32_t*)data;

    k *= m;
    k ^= k >> r;
    k *= m;

    h *= m;
    h ^= k;

    data += 4;
    len -= 4;
  }

  // Handle the last few bytes of the input array

  switch(len)
  {
  case 3: h ^= data[2] << 16;
  case 2: h ^= data[1] << 8;
  case 1: h ^= data[0];
      h *= m;
  };

  // Do a few final mixes of the hash to ensure the last few
  // bytes are well-incorporated.

  h ^= h >> 13;
  h *= m;
  h ^= h >> 15;

  return h;
} 

//-----------------------------------------------------------------------------
// MurmurHash2, 64-bit versions, by Austin Appleby

// The same caveats as 32-bit MurmurHash2 apply here - beware of alignment 
// and endian-ness issues if used across multiple platforms.

// 64-bit hash for 64-bit platforms

uint64_t MurmurHash64A ( const void * key, int len, uint64_t seed )
{
  const uint64_t m = BIG_CONSTANT(0xc6a4a7935bd1e995);
  const int r = 47;
  const int nblocks = len / 8;

  uint64_t h = seed ^ (len * m);
  const uint8_t * data = (const uint8_t*)key;

  const uint64_t * blocks = (const uint64_t *)(data);
  for(int i = 0; i < nblocks; i++)
  {
    uint64_t k = getblock2(blocks,i);
    k *= m; 
    k ^= k >> r; 
    k *= m; 

    h ^= k;
    h *= m; 
  }

  const uint8_t * data2 = (const uint8_t*)(data + nblocks*8);

  switch(len & 7)
  {
  case 7: h ^= uint64_t(data2[6]) << 48;
  case 6: h ^= uint64_t(data2[5]) << 40;
  case 5: h ^= uint64_t(data2[4]) << 32;
  case 4: h ^= uint64_t(data2[3]) << 24;
  case 3: h ^= uint64_t(data2[2]) << 16;
  case 2: h ^= uint64_t(data2[1]) << 8;
  case 1: h ^= uint64_t(data2[0]);
          h *= m;
  };
 
  h ^= h >> r;
  h *= m;
  h ^= h >> r;

  return h;
} 

// 64-bit hash for 32-bit platforms

uint64_t MurmurHash64B ( const void * key, int len, uint64_t seed )
{
  const uint32_t m = 0x5bd1e995;
  const int r = 24;

  uint32_t h1 = uint32_t(seed) ^ len;
  uint32_t h2 = uint32_t(seed >> 32);

  const uint32_t * data = (const uint32_t *)key;

  while(len >= 8)
  {
    uint32_t k1 = *data++;
    k1 *= m; k1 ^= k1 >> r; k1 *= m;
    h1 *= m; h1 ^= k1;
    len -= 4;

    uint32_t k2 = *data++;
    k2 *= m; k2 ^= k2 >> r; k2 *= m;
    h2 *= m; h2 ^= k2;
    len -= 4;
  }

  if(len >= 4)
  {
    uint32_t k1 = *data++;
    k1 *= m; k1 ^= k1 >> r; k1 *= m;
    h1 *= m; h1 ^= k1;
    len -= 4;
  }

  switch(len)
  {
  case 3: h2 ^= ((unsigned char*)data)[2] << 16;
  case 2: h2 ^= ((unsigned char*)data)[1] << 8;
  case 1: h2 ^= ((unsigned char*)data)[0];
      h2 *= m;
  };

  h1 ^= h2 >> 18; h1 *= m;
  h2 ^= h1 >> 22; h2 *= m;
  h1 ^= h2 >> 17; h1 *= m;
  h2 ^= h1 >> 19; h2 *= m;

  uint64_t h = h1;

  h = (h << 32) | h2;

  return h;
} 

// 64-bit hash for 64-bit platforms, endian neutral

uint64_t MurmurHash64ANeutral ( const void * key, int len, uint64_t seed )
{
  const uint64_t m = BIG_CONSTANT(0xc6a4a7935bd1e995);
  const int r = 47;

  uint64_t h = seed ^ (len * m);

  const uint64_t * data = (const uint64_t *)key;
  const uint64_t * end = data + (len/8);

  while(data != end)
  {
    uint64_t k = *data++;

    k *= m; 
    k ^= k >> r; 
    k *= m; 
    
    h ^= k;
    h *= m; 
  }

  const unsigned char * data2 = (const unsigned char*)data;

  switch(len & 7)
  {
  case 7: h ^= uint64_t(data2[6]) << 48;
  case 6: h ^= uint64_t(data2[5]) << 40;
  case 5: h ^= uint64_t(data2[4]) << 32;
  case 4: h ^= uint64_t(data2[3]) << 24;
  case 3: h ^= uint64_t(data2[2]) << 16;
  case 2: h ^= uint64_t(data2[1]) << 8;
  case 1: h ^= uint64_t(data2[0]);
          h *= m;
  };
 
  h ^= h >> r;
  h *= m;
  h ^= h >> r;

  return h;
} 

//-----------------------------------------------------------------------------
// MurmurHash2A, by Austin Appleby

// This is a variant of MurmurHash2 modified to use the Merkle-Damgard 
// construction. Bulk speed should be identical to Murmur2, small-key speed 
// will be 10%-20% slower due to the added overhead at the end of the hash.

// This variant fixes a minor issue where null keys were more likely to
// collide with each other than expected, and also makes the function
// more amenable to incremental implementations.

#define mmix(h,k) { k *= m; k ^= k >> r; k *= m; h *= m; h ^= k; }

uint32_t MurmurHash2A ( const void * key, int len, uint32_t seed )
{
  const uint32_t m = 0x5bd1e995;
  const int r = 24;
  uint32_t l = len;

  const unsigned char * data = (const unsigned char *)key;

  uint32_t h = seed;

  while(len >= 4)
  {
    uint32_t k = *(uint32_t*)data;

    mmix(h,k);

    data += 4;
    len -= 4;
  }

  uint32_t t = 0;

  switch(len)
  {
  case 3: t ^= data[2] << 16;
  case 2: t ^= data[1] << 8;
  case 1: t ^= data[0];
  };

  mmix(h,t);
  mmix(h,l);

  h ^= h >> 13;
  h *= m;
  h ^= h >> 15;

  return h;
}

//-----------------------------------------------------------------------------
// CMurmurHash2A, by Austin Appleby

// This is a sample implementation of MurmurHash2A designed to work 
// incrementally.

// Usage - 

// CMurmurHash2A hasher
// hasher.Begin(seed);
// hasher.Add(data1,size1);
// hasher.Add(data2,size2);
// ...
// hasher.Add(dataN,sizeN);
// uint32_t hash = hasher.End()

class CMurmurHash2A
{
public:

  void Begin ( uint32_t seed = 0 )
  {
    m_hash  = seed;
    m_tail  = 0;
    m_count = 0;
    m_size  = 0;
  }

  void Add ( const unsigned char * data, int len )
  {
    m_size += len;

    MixTail(data,len);

    while(len >= 4)
    {
      uint32_t k = *(uint32_t*)data;

      mmix(m_hash,k);

      data += 4;
      len -= 4;
    }

    MixTail(data,len);
  }

  uint32_t End ( void )
  {
    mmix(m_hash,m_tail);
    mmix(m_hash,m_size);

    m_hash ^= m_hash >> 13;
    m_hash *= m;
    m_hash ^= m_hash >> 15;

    return m_hash;
  }

private:

  static const uint32_t m = 0x5bd1e995;
  static const int r = 24;

  void MixTail ( const unsigned char * & data, int & len )
  {
    while( len && ((len<4) || m_count) )
    {
      m_tail |= (*data++) << (m_count * 8);

      m_count++;
      len--;

      if(m_count == 4)
      {
        mmix(m_hash,m_tail);
        m_tail = 0;
        m_count = 0;
      }
    }
  }

  uint32_t m_hash;
  uint32_t m_tail;
  uint32_t m_count;
  uint32_t m_size;
};

//-----------------------------------------------------------------------------
// MurmurHashNeutral2, by Austin Appleby

// Same as MurmurHash2, but endian- and alignment-neutral.
// Half the speed though, alas.

uint32_t MurmurHashNeutral2 ( const void * key, int len, uint32_t seed )
{
  const uint32_t m = 0x5bd1e995;
  const int r = 24;

  uint32_t h = seed ^ len;

  const unsigned char * data = (const unsigned char *)key;

  while(len >= 4)
  {
    uint32_t k;

    k  = data[0];
    k |= data[1] << 8;
    k |= data[2] << 16;
    k |= data[3] << 24;

    k *= m; 
    k ^= k >> r; 
    k *= m;

    h *= m;
    h ^= k;

    data += 4;
    len -= 4;
  }
  
  switch(len)
  {
  case 3: h ^= data[2] << 16;
  case 2: h ^= data[1] << 8;
  case 1: h ^= data[0];
          h *= m;
  };

  h ^= h >> 13;
  h *= m;
  h ^= h >> 15;

  return h;
} 

//-----------------------------------------------------------------------------
// MurmurHashAligned2, by Austin Appleby

// Same algorithm as MurmurHash2, but only does aligned reads - should be safer
// on certain platforms. 

// Performance will be lower than MurmurHash2

#define MIX(h,k,m) { k *= m; k ^= k >> r; k *= m; h *= m; h ^= k; }


uint32_t MurmurHashAligned2 ( const void * key, int len, uint32_t seed )
{
  const uint32_t m = 0x5bd1e995;
  const int r = 24;

  const unsigned char * data = (const unsigned char *)key;

  uint32_t h = seed ^ len;

  int align = (uint64_t)data & 3;

  if(align && (len >= 4))
  {
    // Pre-load the temp registers

    uint32_t t = 0, d = 0;

    switch(align)
    {
      case 1: t |= data[2] << 16;
      case 2: t |= data[1] << 8;
      case 3: t |= data[0];
    }

    t <<= (8 * align);

    data += 4-align;
    len -= 4-align;

    int sl = 8 * (4-align);
    int sr = 8 * align;

    // Mix

    while(len >= 4)
    {
      d = *(uint32_t *)data;
      t = (t >> sr) | (d << sl);

      uint32_t k = t;

      MIX(h,k,m);

      t = d;

      data += 4;
      len -= 4;
    }

    // Handle leftover data in temp registers

    d = 0;

    if(len >= align)
    {
      switch(align)
      {
      case 3: d |= data[2] << 16;
      case 2: d |= data[1] << 8;
      case 1: d |= data[0];
      }

      uint32_t k = (t >> sr) | (d << sl);
      MIX(h,k,m);

      data += align;
      len -= align;

      //----------
      // Handle tail bytes

      switch(len)
      {
      case 3: h ^= data[2] << 16;
      case 2: h ^= data[1] << 8;
      case 1: h ^= data[0];
          h *= m;
      };
    }
    else
    {
      switch(len)
      {
      case 3: d |= data[2] << 16;
      case 2: d |= data[1] << 8;
      case 1: d |= data[0];
      case 0: h ^= (t >> sr) | (d << sl);
          h *= m;
      }
    }

    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;

    return h;
  }
  else
  {
    while(len >= 4)
    {
      uint32_t k = *(uint32_t *)data;

      MIX(h,k,m);

      data += 4;
      len -= 4;
    }

    //----------
    // Handle tail bytes

    switch(len)
    {
    case 3: h ^= data[2] << 16;
    case 2: h ^= data[1] << 8;
    case 1: h ^= data[0];
        h *= m;
    };

    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;

    return h;
  }
}

//-----------------------------------------------------------------------------

