// SPDX-License-Identifier: GPL-2.0-or-later
#include "ShellyDialog.h"
#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Progress.H>
#include <FL/fl_ask.H>
#include <algorithm>
#include <cmath>
namespace {
struct Controls { std::shared_ptr<shellyPower::Cycle> cycle; Fl_Button* cancel; };
void cancel(Fl_Widget*, void* data) {
  auto controls = static_cast<Controls*>(data); controls->cycle->cancel(); controls->cancel->deactivate();
}
}
void runShellyDialog(const shellyPower::Credentials& credentials, int delay, const std::string& computer) {
  auto cycle = shellyPower::start(credentials, delay, shellyPower::transport());
  Fl_Window window(430, 180, "Power On");
  auto name = new Fl_Box(20, 10, 390, 30); name->copy_label(computer.c_str()); name->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
  auto status = new Fl_Box(20, 45, 390, 30, "Switching power off..."); status->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
  auto progress = new Fl_Progress(20, 85, 390, 25); progress->minimum(0); progress->maximum(float(delay)); progress->value(0);
  auto button = new Fl_Button(305, 130, 105, 30, "Cancel");
  Controls controls{cycle,button}; button->callback(cancel, &controls);
  window.end(); window.callback(cancel, &controls); window.set_modal(); window.show();
  std::string previous;
  while (cycle->phase.load(std::memory_order_acquire) != shellyPower::Phase::Done) {
    auto phase = cycle->phase.load(std::memory_order_acquire); std::string message;
    if (cycle->cancelled.load() || phase == shellyPower::Phase::Restoring) message = "Restoring power...";
    else if (phase == shellyPower::Phase::Waiting) {
      double elapsed = std::max(0.0, (shellyPower::clockMs() - cycle->waitStarted.load()) / 1000.0);
      progress->value(float(std::min(double(delay), elapsed)));
      message = "Restoring power in " + std::to_string(std::max(0, delay - int(std::floor(elapsed)))) + " seconds...";
    } else message = "Switching power off...";
    if (message != previous) { status->copy_label(message.c_str()); status->redraw(); previous = message; }
    if (phase == shellyPower::Phase::Restoring) button->deactivate();
    Fl::wait(0.05);
  }
  window.hide();
  if (!cycle->onSucceeded) fl_message("Unable to restore power. Check the Shelly Plug.");
  else if (!cycle->offSucceeded) fl_message("The power-off request failed. Power has been restored.");
}
