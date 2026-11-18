// SPDX-License-Identifier: GPL-2.0-or-later
#include "ServerDialog.h"
#include "fltk/util.h"
#include <FL/Fl.H>
#include <FL/Fl_Group.H>
#include <FL/Fl_Tree.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Secret_Input.H>
#include <FL/Fl_Choice.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Check_Button.H>
#include <FL/fl_ask.H>
#include <algorithm>
#include <functional>

namespace {
// FLTK's stable 1.3 ABI does not emit a callback when a selected item is
// clicked again. Explicitly notify for double-clicks, including that case.
class ComputerTree : public Fl_Tree {
public:
  ComputerTree(int x, int y, int w, int h) : Fl_Tree(x, y, w, h) {}
  int handle(int event) override {
    int result = Fl_Tree::handle(event);
    if (event == FL_RELEASE && Fl::event_button() == FL_LEFT_MOUSE && Fl::event_clicks()) {
      auto item = find_clicked();
      if (item) {
        callback_item(item); callback_reason(FL_TREE_REASON_SELECTED); do_callback();
      }
    }
    return result;
  }
};
}

void ServerDialog::createManager(int top)
{
  managerPane = new Fl_Group(0, top, w(), collapsedHeight * 3);
  const char* actions[] = {"New computer", "New folder", "Edit", "Delete"};
  for (int pos = 0; pos < 4; ++pos) {
    auto b = new Fl_Button(15 + pos * 108, top + 8, 102, 27, actions[pos]);
    b->callback(managerAction, this);
    if (pos == 2) editButton = b;
    if (pos == 3) deleteButton = b;
  }
  tree = new ComputerTree(15, top + 43, w() - 30, managerPane->h() - 58);
  tree->showroot(0);
  tree->selectmode(FL_TREE_SELECT_SINGLE);
  tree->connectorstyle(FL_TREE_CONNECTOR_NONE);
  tree->callback(treeAction, this);
  editor = new Fl_Group(15, top + managerPane->h() - 249, w() - 30, 234);
  int y = editor->y();
  entryName = new Fl_Input(112, y, 318, 25, "Name:"); y += 30;
  entryFolder = new Fl_Choice(112, y, 318, 25, "Folder:"); y += 30;
  entryAddress = new Fl_Input(112, y, 318, 25, "Address:"); y += 30;
  entryUser = new Fl_Input(112, y, 318, 25, "Username:"); y += 30;
  entryPassword = new Fl_Secret_Input(112, y, 318, 25, "Password:"); y += 30;
  entryPassword->tooltip("Leave blank to keep an existing saved password.");
  rememberPassword = new Fl_Check_Button(112, y, 318, 24, "Save password for this Windows account");
  rememberPassword->labelsize(12); y += 31;
  auto b = new Fl_Button(198, y, 110, 27, "Save entry"); b->callback(managerAction, this);
  b = new Fl_Button(318, y, 112, 27, "Cancel edit"); b->callback(managerAction, this);
  editor->end();
  editor->hide();
  managerPane->end();
  managerPane->hide();
  end();
}

void ServerDialog::expandManager(bool value)
{
  expanded = value;
  managerButton->value(value);
  if (value) managerPane->show(); else { closeEditor(); managerPane->hide(); }
  size(w(), collapsedHeight * (value ? 4 : 1));
  redraw();
}

void ServerDialog::refreshManager(const std::string& selected)
{
  managerData = store.read();
  rebuilding = true;
  populateConnectionTree(*tree, managerData, treeEntries);
  selectedId.clear(); selectedComputer.clear();
  editButton->deactivate(); deleteButton->deactivate();
  for (auto item = tree->first(); item; item = tree->next(item)) {
    auto entry = static_cast<ConnectionTreeEntry*>(item->user_data());
    if (!entry || entry->id != selected) continue;
    tree->select(item, 0);
    selectedId = entry->id; selectedFolder = entry->folder;
    editButton->activate(); deleteButton->activate();
    if (!entry->folder) {
      selectedComputer = entry->id;
      serverName->value(store.connection(entry->id)["address"].asCString());
    }
  }
  rebuilding = false;
  tree->redraw();
}

void ServerDialog::treeAction(Fl_Widget*, void* data)
{
  auto d = static_cast<ServerDialog*>(data);
  if (d->rebuilding) return;
  auto reason = d->tree->callback_reason();
  if (reason != FL_TREE_REASON_SELECTED) return;
  auto item = d->tree->callback_item();
  auto entry = item ? static_cast<ConnectionTreeEntry*>(item->user_data()) : nullptr;
  if (!entry) return;
  d->selectedId = entry->id; d->selectedFolder = entry->folder;
  d->editButton->activate(); d->deleteButton->activate();
  if (!entry->folder) {
    d->selectedComputer = entry->id;
    for (const auto& computer : d->managerData["connections"])
      if (computer["id"].asString() == entry->id)
        d->serverName->value(computer["address"].asCString());
    if (Fl::event() == FL_RELEASE && Fl::event_button() == FL_LEFT_MOUSE && Fl::event_clicks())
      handleConnect(nullptr, d);
  }
}

void ServerDialog::closeEditor()
{
  entryPassword->value("");
  editor->hide();
  tree->size(tree->w(), managerPane->h() - 58);
  redraw();
}

void ServerDialog::editEntry(bool folder, bool existing)
{
  managerData = store.read();
  editingFolder = folder; editingId = existing ? selectedId : "";
  Json::Value record;
  if (existing)
    for (const auto& entry : managerData[folder ? "folders" : "connections"])
      if (entry["id"].asString() == editingId) record = entry;
  std::string parent;
  if (existing) parent = record[folder ? "parentId" : "folderId"].asString();
  else if (!selectedId.empty()) {
    if (selectedFolder) parent = selectedId;
    else parent = store.connection(selectedId)["folderId"].asString();
  }
  entryName->value(existing ? record["name"].asCString() : "");
  entryAddress->value(existing && !folder ? record["address"].asCString() : serverName->value());
  entryUser->value(existing && !folder ? record["username"].asCString() : "");
  entryPassword->value("");
  rememberPassword->value(!existing || !record["password"].isNull());
  entryFolder->clear(); folderIds.clear(); folderLabels.clear();
  std::vector<Fl_Menu_Item> menu;
  auto addFolder = [&](const std::string& id, const std::string& label) {
    // Supply literal menu items rather than parsed paths: equal folder names,
    // slashes and backslashes must never merge entries or shift the ID mapping.
    folderIds.push_back(id); folderLabels.push_back(label);
    menu.push_back(Fl_Menu_Item{});
    menu.back().label(folderLabels.back().c_str());
    menu.back().labelsize(13);
  };
  addFolder("", "(Top level)");
  int selected = 0;
  for (const auto& f : managerData["folders"]) {
    auto id = f["id"].asString();
    // Moving a folder into itself or a descendant is forbidden.
    bool descendant = false;
    std::string cursor = id;
    while (!cursor.empty() && folder && existing) {
      if (cursor == editingId) { descendant = true; break; }
      for (const auto& p : managerData["folders"])
        if (p["id"].asString() == cursor) { cursor = p["parentId"].asString(); break; }
    }
    if (descendant) continue;
    addFolder(id, ConnectionStore::folderPath(managerData, id));
    if (parent == id) selected = int(folderIds.size()) - 1;
  }
  menu.push_back(Fl_Menu_Item{});
  entryFolder->copy(menu.data());
  entryFolder->value(selected);
  for (Fl_Widget* widget : std::vector<Fl_Widget*>{entryAddress, entryUser, entryPassword,
                                                 rememberPassword})
    if (folder) widget->hide(); else widget->show();
  tree->size(tree->w(), editor->y() - tree->y() - 10);
  editor->show(); entryName->take_focus(); redraw();
}

void ServerDialog::managerAction(Fl_Widget* widget, void* data)
{
  auto d = static_cast<ServerDialog*>(data);
  try {
    std::string action = widget->label();
    if (widget == d->managerButton) {
      d->store.setExpanded(!d->expanded);
      d->expandManager(!d->expanded);
    } else if (action == "New computer") d->editEntry(false, false);
    else if (action == "New folder") d->editEntry(true, false);
    else if (action == "Edit" && !d->selectedId.empty()) d->editEntry(d->selectedFolder, true);
    else if (action == "Cancel edit") d->closeEditor();
    else if (action == "Delete" && !d->selectedId.empty()) {
      if (fl_choice("Delete the selected entry?", "Cancel", "Delete", nullptr) != 1) return;
      d->store.remove(d->selectedId, d->selectedFolder);
      d->closeEditor(); d->refreshManager();
    } else if (action == "Save entry") {
      int index = d->entryFolder->value();
      if (index < 0 || size_t(index) >= d->folderIds.size()) return;
      std::string id;
      if (d->editingFolder)
        id = d->store.saveFolder(d->editingId, d->entryName->value(), d->folderIds[index]);
      else {
        auto change = ConnectionStore::KeepPassword;
        if (!d->rememberPassword->value()) change = ConnectionStore::ForgetPassword;
        else if (d->entryPassword->size() || d->editingId.empty() ||
                 d->store.connection(d->editingId)["password"].isNull()) change = ConnectionStore::SetPassword;
        std::string password = d->entryPassword->value();
        try {
          id = d->store.saveConnection(d->editingId, d->entryName->value(), d->entryAddress->value(),
            d->entryUser->value(), d->folderIds[index], change, password);
        } catch (...) { CredentialVault::erase(password); throw; }
        CredentialVault::erase(password);
      }
      d->closeEditor(); d->refreshManager(id);
    }
  } catch (std::exception& e) { fl_alert("Unable to update saved computers:\n\n%s", e.what()); }
}
