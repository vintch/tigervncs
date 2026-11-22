// SPDX-License-Identifier: GPL-2.0-or-later
#include "ConnectionTree.h"
#include "ConnectionStore.h"
#include <FL/Fl_Pixmap.H>
#include <functional>
#include <stdexcept>
#include <map>
#include <set>

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
  "16 16 5 1", "  c None", ". c #77828D", "+ c #BCC5CD", "@ c #E5E9ED", "# c #C4CBD1",
  "                ", " .............. ", " .@@@@@@@@@@@@. ", " .@++++++++++@. ",
  " .@++++++++++@. ", " .@++++++++++@. ", " .@++++++++++@. ", " .@++++++++++@. ",
  " .@@@@@@@@@@@@. ", " .############. ", " .............. ", "      .##.      ",
  "      .##.      ", "    ........    ", "                ", "                "
};
Fl_Pixmap folderIcon(folderPixels), computerIcon(computerPixels);
const char* onlinePixels[] = {
  "16 16 5 1", "  c None", ". c #075A25", "+ c #00AE42", "@ c #BAF2CC", "# c #36A85F",
  "                ", " .............. ", " .@@@@@@@@@@@@. ", " .@++++++++++@. ",
  " .@++++++++++@. ", " .@++++++++++@. ", " .@++++++++++@. ", " .@++++++++++@. ",
  " .@@@@@@@@@@@@. ", " .############. ", " .............. ", "      .##.      ",
  "      .##.      ", "    ........    ", "                ", "                "
};
Fl_Pixmap onlineIcon(onlinePixels);
}

bool setConnectionOnlineIcon(Fl_Tree_Item* item, bool online) {
  auto icon = online ? &onlineIcon : &computerIcon;
  if (item->usericon() == icon) return false;
  item->usericon(icon);
  return true;
}

std::vector<std::string> visibleConnectionIds(Fl_Tree& tree) {
  std::vector<std::string> result;
  for (auto item = tree.first(); item; item = tree.next(item)) {
    auto entry = static_cast<ConnectionTreeEntry*>(item->user_data());
    if (!entry || entry->folder) continue;
    bool visible = true;
    for (auto parent = item->parent(); parent; parent = parent->parent())
      if (!parent->is_open()) { visible = false; break; }
    if (visible) result.push_back(entry->id);
  }
  return result;
}

void populateConnectionTree(Fl_Tree& tree, const Json::Value& document,
                            std::list<ConnectionTreeEntry>& entries)
{
  tree.clear();
  entries.clear();
  // clear() deletes the root too. root_label() alone does not recreate it.
  tree.root(new Fl_Tree_Item(tree.prefs()));
  tree.root_label("Computers");
  std::map<std::string, const Json::Value*> records;
  std::set<std::string> folderIds;
  for (const auto& folder : document["folders"]) {
    records[folder["id"].asString()] = &folder;
    folderIds.insert(folder["id"].asString());
  }
  for (const auto& computer : document["connections"]) records[computer["id"].asString()] = &computer;
  std::function<void(Fl_Tree_Item*, const std::string&, unsigned)> addChildren;
  addChildren = [&](Fl_Tree_Item* parent, const std::string& parentId, unsigned depth) {
    if (!parent || depth > 128) throw std::runtime_error("Invalid folder hierarchy");
    for (const auto& id : ConnectionStore::children(document, parentId)) {
      const auto& record = *records.at(id);
      bool folder = folderIds.count(id) != 0;
      auto item = tree.add(parent, record["name"].asCString());
      item->usericon(folder ? &folderIcon : &computerIcon);
      entries.push_back({id, folder});
      item->user_data(&entries.back());
      if (folder) {
        addChildren(item, id, depth + 1);
        if (!record.get("expanded", true).asBool()) item->close();
      }
    }
  };
  addChildren(tree.root(), "", 0);
}
