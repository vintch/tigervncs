// SPDX-License-Identifier: GPL-2.0-or-later
#include "VpnUi.h"
#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Return_Button.H>
#include <FL/Fl_Pixmap.H>
#include "icons/vpn_grey.xpm"
#include "icons/vpn_green.xpm"
#include "icons/vpn_amber.xpm"
namespace {
Fl_Pixmap grey(vpn_grey_pixels), green(vpn_green_pixels), amber(vpn_amber_pixels);
const char* shieldPixels[] = {
  "16 18 4 1", "  c None", ". c #546477", "+ c #F5CD41", "@ c #3974BB",
  "                ", "  ............  ", "  .++++@@@@@@.  ", "  .++++@@@@@@.  ",
  "  .++++@@@@@@.  ", "  .++++@@@@@@.  ", "  .++++@@@@@@.  ", "  .++++@@@@@@.  ",
  "  .@@@@++++++.  ", "  .@@@@++++++.  ", "   .@@@+++++.   ", "   .@@@+++++.   ",
  "    .@@++++.    ", "     .@+++.     ", "      .++.      ", "       ..       ",
  "                ", "                "
};
Fl_Pixmap shield(shieldPixels);
struct Choice { bool accepted = false; Fl_Window* window; };
void cancel(Fl_Widget*, void* data) { static_cast<Choice*>(data)->window->hide(); }
void accept(Fl_Widget*, void* data) { auto choice = static_cast<Choice*>(data); choice->accepted = true; choice->window->hide(); }
}
Fl_Image* vpnPlanet(vpnControl::Colour colour) {
  if (colour == vpnControl::Colour::Green) return &green;
  if (colour == vpnControl::Colour::Amber) return &amber;
  return &grey;
}
bool confirmVpnElevation() {
  Fl_Window window(440, 170, "TigerVNCs"); Choice choice; choice.window = &window;
  auto note = new Fl_Box(20, 15, 400, 85,
    "Administrator permission is required to control this Wireguard tunnel.\n\nElevate privileges for this command?");
  note->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_WRAP); note->labelsize(14);
  auto no = new Fl_Button(195, 120, 105, 30, "Cancel"); no->callback(cancel, &choice);
  auto yes = new Fl_Return_Button(310, 120, 110, 30, "Elevate"); yes->image(shield);
  yes->align(FL_ALIGN_CENTER | FL_ALIGN_INSIDE | FL_ALIGN_IMAGE_NEXT_TO_TEXT); yes->callback(accept, &choice);
  window.end(); window.callback(cancel, &choice); window.set_modal(); window.show();
  while (window.shown()) Fl::wait();
  return choice.accepted;
}
