// SPDX-License-Identifier: GPL-2.0-or-later
#include "ConnectionTree.h"
#include <FL/Fl_Pixmap.H>
#include <functional>
#include <stdexcept>

namespace {
// Original embedded artwork: ordinary folder and monitor, no runtime assets.
const char* folderPixels[] = {
  "16 16 5 1", "  c None", ". c #A87518", "+ c #E9AF36", "@ c #FFD875", "# c #FFCA50",
  "                ", "                ", " ......         ", " .@@@@.         ",
  " .@@@@........  ", " .@@@@@@@@@@@.  ", " .+++++++++++.  ", " .###########.  ",
  " .###########.  ", " .###########.  ", " .###########.  ", " .###########.  ",
  " .###########.  ", " .............  ", "                ", "                "
};
const char* computerPixels[] = {
  "16 16 5 1", "  c None", ". c #465568", "+ c #61B5E8", "@ c #D9F1FF", "# c #AAB5C2",
  "                ", " .............. ", " .@@@@@@@@@@@@. ", " .@++++++++++@. ",
  " .@++++++++++@. ", " .@++++++++++@. ", " .@++++++++++@. ", " .@++++++++++@. ",
  " .@@@@@@@@@@@@. ", " .############. ", " .............. ", "      .##.      ",
  "      .##.      ", "    ........    ", "                ", "                "
};
Fl_Pixmap folderIcon(folderPixels), computerIcon(computerPixels);
}

void populateConnectionTree(Fl_Tree& tree, const Json::Value& document,
                            std::list<ConnectionTreeEntry>& entries)
{
  tree.clear();
  entries.clear();
  // clear() deletes the root too. root_label() alone does not recreate it.
  tree.root(new Fl_Tree_Item(tree.prefs()));
  tree.root_label("Computers");
  std::function<void(Fl_Tree_Item*, const std::string&, unsigned)> addChildren;
  addChildren = [&](Fl_Tree_Item* parent, const std::string& parentId, unsigned depth) {
    if (!parent || depth > 128) throw std::runtime_error("Invalid folder hierarchy");
    for (const auto& folder : document["folders"]) {
      if (folder["parentId"].asString() != parentId) continue;
      auto id = folder["id"].asString();
      auto item = tree.add(parent, folder["name"].asCString());
      item->usericon(&folderIcon);
      entries.push_back({id, true}); item->user_data(&entries.back());
      addChildren(item, id, depth + 1);
    }
    for (const auto& computer : document["connections"]) {
      if (computer["folderId"].asString() != parentId) continue;
      auto item = tree.add(parent, computer["name"].asCString());
      item->usericon(&computerIcon);
      entries.push_back({computer["id"].asString(), false});
      item->user_data(&entries.back());
    }
  };
  addChildren(tree.root(), "", 0);
}
