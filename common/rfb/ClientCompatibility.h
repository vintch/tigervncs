// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef RFB_CLIENT_COMPATIBILITY_H
#define RFB_CLIENT_COMPATIBILITY_H
#include <rfb/PixelFormat.h>
#include <rfb/encodings.h>
namespace rfb {
inline bool appleProtocolVersion(int major, int minor)
{
  return major == 3 && minor == 889;
}
inline PixelFormat compatiblePixelFormat(bool apple, const PixelFormat& requested)
{
  // Apple Screen Sharing drops connections which request 8-bpp color.
  if (apple && requested.bpp < 16)
    return PixelFormat(16, 16, false, true, 31, 63, 31, 11, 5, 0);
  return requested;
}
inline int compatibleEncoding(bool apple, int requested)
{
  if (apple && requested != encodingRaw && requested != encodingHextile &&
      requested != encodingZRLE)
    return encodingZRLE;
  return requested;
}
}
#endif
