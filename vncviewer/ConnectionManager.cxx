// SPDX-License-Identifier: GPL-2.0-or-later
#include "ServerDialog.h"
#include "fltk/util.h"
#include "NetworkSettings.h"
#include "VpnProfiles.h"
#include <FL/Fl.H>
#include <FL/Fl_Group.H>
#include <FL/Fl_Tree.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Secret_Input.H>
#include <FL/Fl_Choice.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Check_Button.H>
#include <FL/Fl_Menu_Item.H>
#include <FL/fl_ask.H>
#include <algorithm>
#include <functional>

namespace {
// FLTK's stable 1.3 ABI does not emit a callback when a selected item is
// clicked again. Explicitly notify for double-clicks, including that case.
class ComputerTree : public Fl_Tree {
public:
  std::function<void(Fl_Tree_Item*)> contextMenu;
  ComputerTree(int x, int y, int w, int h) : Fl_Tree(x, y, w, h) {}
  int handle(int event) override {
    if (event == FL_PUSH && Fl::event_button() == FL_RIGHT_MOUSE) {
      if (contextMenu) contextMenu(find_clicked());
      return 1;
    }
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
  auto computerTree = new ComputerTree(15, top + 8, w() - 30, managerPane->h() - 23);
  computerTree->contextMenu = [this](Fl_Tree_Item* item) { showContextMenu(item); };
  tree = computerTree;
  tree->showroot(0);
  tree->selectmode(FL_TREE_SELECT_SINGLE);
  tree->connectorstyle(FL_TREE_CONNECTOR_NONE);
  tree->callback(treeAction, this);
  editor = new Fl_Group(15, top + managerPane->h() - 339, w() - 30, 324);
  int y = editor->y();
  entryName = new Fl_Input(112, y, 318, 25, "Name:"); y += 30;
  entryFolder = new Fl_Choice(112, y, 318, 25, "Folder:"); y += 30;
  entryAddress = new Fl_Input(112, y, 318, 25, "Address:"); y += 30;
  entryUser = new Fl_Input(112, y, 318, 25, "Username:"); y += 30;
  entryPassword = new Fl_Secret_Input(112, y, 318, 25, "Password:"); y += 30;
  entryPassword->tooltip("Leave blank to keep an existing saved password.");
  entrySessionMode = new Fl_Choice(112, y, 318, 25, "Session mode:"); y += 30;
  entrySessionMode->add("Current screen"); entrySessionMode->add("User session");
  entrySessionMode->value(0);
  rememberPassword = new Fl_Check_Button(112, y, 318, 24, "Save password for this Windows account");
  rememberPassword->labelsize(12); y += 31;
  associateVpn = new Fl_Check_Button(112, y, 318, 24, "Associate VPN-Connection"); y += 28;
  associateVpn->callback(vpnAction, this);
  vpnProvider = new Fl_Choice(112, y, 110, 25, "VPN:");
  vpnProvider->add("Wireguard"); vpnProvider->add("OpenVPN"); vpnProvider->value(0);
  vpnProvider->callback(vpnAction, this);
  vpnProfile = new Fl_Choice(230, y, 200, 25); y += 32;
  vpnProfile->tooltip("VPN profile");
  auto b = new Fl_Button(198, y, 110, 27, "Save entry"); b->callback(managerAction, this);
  b = new Fl_Button(318, y, 112, 27, "Cancel edit"); b->callback(managerAction, this);
  editor->end();
  editor->hide();
  managerPane->end();
  managerPane->hide();
  tree->tooltip("Right-click to create, edit or move an entry.");
  presence.reset(new PresenceMonitor(createPingTransport()));
  Fl::add_timeout(0.1, presenceTick, this);
  end();
}

void ServerDialog::expandManager(bool value)
{
  expanded = value;
  managerButton->value(value);
  if (value) managerPane->show(); else { closeEditor(); managerPane->hide(); }
  size(w(), collapsedHeight * (value ? 4 : 1));
  updatePresence();
  redraw();
}

void ServerDialog::refreshManager(const std::string& selected)
{
  managerData = store.read();
  connectionAddresses.clear();
  for (const auto& computer : managerData["connections"])
    connectionAddresses[computer["id"].asString()] = computer["address"].asString();
  rebuilding = true;
  populateConnectionTree(*tree, managerData, treeEntries);
  selectedId.clear(); selectedComputer.clear();
  for (auto item = tree->first(); item; item = tree->next(item)) {
    auto entry = static_cast<ConnectionTreeEntry*>(item->user_data());
    if (!entry || entry->id != selected) continue;
    tree->select(item, 0);
    selectedId = entry->id; selectedFolder = entry->folder;
    if (!entry->folder) {
      selectedComputer = entry->id;
      serverName->value(store.connection(entry->id)["address"].asCString());
    }
  }
  rebuilding = false;
  updatePresence();
  tree->redraw();
}

void ServerDialog::treeAction(Fl_Widget*, void* data)
{
  auto d = static_cast<ServerDialog*>(data);
  if (d->rebuilding) return;
  auto reason = d->tree->callback_reason();
  if (reason == FL_TREE_REASON_OPENED || reason == FL_TREE_REASON_CLOSED) {
    auto item = d->tree->callback_item();
    auto entry = item ? static_cast<ConnectionTreeEntry*>(item->user_data()) : nullptr;
    if (!entry || !entry->folder) return;
    try {
      d->store.setFolderExpanded(entry->id, item->is_open());
      for (auto& folder : d->managerData["folders"])
        if (folder["id"].asString() == entry->id) folder["expanded"] = bool(item->is_open());
    } catch (std::exception& e) { fl_alert("Unable to save folder state:\n\n%s", e.what()); }
    d->updatePresence();
    return;
  }
  if (reason != FL_TREE_REASON_SELECTED) return;
  auto item = d->tree->callback_item();
  auto entry = item ? static_cast<ConnectionTreeEntry*>(item->user_data()) : nullptr;
  if (!entry) return;
  d->selectedId = entry->id; d->selectedFolder = entry->folder;
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
  tree->size(tree->w(), managerPane->h() - 23);
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
  entrySessionMode->value(existing && record["sessionMode"] == "user-session" ? 1 : 0);
  const auto& vpn = record["vpn"];
  associateVpn->value(vpn.isObject() && vpn.get("enabled", false) == true);
  vpnProvider->value(vpn.isObject() && vpn.get("provider", "wireguard") == "openvpn" ? 1 : 0);
  updateVpnProfiles(vpn.isObject() && vpn["profileId"].isString() ? vpn["profileId"].asString() : "");
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
  for (Fl_Widget* widget : std::vector<Fl_Widget*>{entryAddress, entryUser, entryPassword, entrySessionMode,
                                                 rememberPassword, associateVpn, vpnProvider, vpnProfile})
    if (folder) widget->hide(); else widget->show();
  tree->size(tree->w(), editor->y() - tree->y() - 10);
  editor->show(); entryName->take_focus(); redraw();
}

void ServerDialog::managerAction(Fl_Widget* widget, void* data)
{
  auto d = static_cast<ServerDialog*>(data);
  d->performManagerAction(widget == d->managerButton ? "Computers" : widget->label());
}

void ServerDialog::performManagerAction(const std::string& action)
{
  auto d = this;
  try {
    if (action == "Computers") {
      d->store.setExpanded(!d->expanded);
      d->expandManager(!d->expanded);
    } else if (action == "New computer") d->editEntry(false, false);
    else if (action == "New folder") d->editEntry(true, false);
    else if (action == "Edit" && !d->selectedId.empty()) d->editEntry(d->selectedFolder, true);
    else if (action == "Cancel edit") d->closeEditor();
    else if ((action == "User session" || action == "Current screen") && !d->selectedComputer.empty()) {
      d->connectionModeOverride = action == "User session" ? "user-session" : "current-screen";
      handleConnect(nullptr, d);
    }
    else if ((action == "Move up" || action == "Move down") && !d->selectedId.empty()) {
      auto selected = d->selectedId;
      d->store.move(selected, d->selectedFolder, action == "Move up" ? -1 : 1);
      d->closeEditor(); d->refreshManager(selected);
    }
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
        Json::Value vpn(Json::objectValue);
        vpn["enabled"] = bool(d->associateVpn->value());
        vpn["provider"] = d->vpnProvider->value() == 1 ? "openvpn" : "wireguard";
        int profile = d->vpnProfile->value();
        vpn["profileId"] = profile >= 0 && size_t(profile) < d->vpnProfileIds.size() ? d->vpnProfileIds[profile] : "";
        try {
          id = d->store.saveConnection(d->editingId, d->entryName->value(), d->entryAddress->value(),
            d->entryUser->value(), d->folderIds[index], change, password,
            d->entrySessionMode->value() == 1 ? "user-session" : "current-screen", vpn);
        } catch (...) { CredentialVault::erase(password); throw; }
        CredentialVault::erase(password);
      }
      d->closeEditor(); d->refreshManager(id);
    }
  } catch (std::exception& e) { fl_alert("Unable to update saved computers:\n\n%s", e.what()); }
}

void ServerDialog::showContextMenu(Fl_Tree_Item* item)
{
  auto entry = item ? static_cast<ConnectionTreeEntry*>(item->user_data()) : nullptr;
  tree->deselect_all(0);
  selectedId.clear(); selectedComputer.clear();
  if (entry) {
    tree->select(item, 0);
    tree->callback_item(item); tree->callback_reason(FL_TREE_REASON_SELECTED);
    treeAction(tree, this);
  }
  Fl_Menu_Item menu[] = {
    {"New computer", 0, nullptr, nullptr, 0, 0, 0, 0, 0},
    {"New folder", 0, nullptr, nullptr, 0, 0, 0, 0, 0},
    {"Edit", 0, nullptr, nullptr, 0, 0, 0, 0, 0},
    {"Delete", 0, nullptr, nullptr, FL_MENU_DIVIDER, 0, 0, 0, 0},
    {"Move up", 0, nullptr, nullptr, 0, 0, 0, 0, 0},
    {"Move down", 0, nullptr, nullptr, FL_MENU_DIVIDER, 0, 0, 0, 0},
    {"Connect to", 0, nullptr, nullptr, FL_SUBMENU, 0, 0, 0, 0},
    {"User session", 0, nullptr, nullptr, 0, 0, 0, 0, 0},
    {"Current screen", 0, nullptr, nullptr, 0, 0, 0, 0, 0},
    {nullptr, 0, nullptr, nullptr, 0, 0, 0, 0, 0},
    {nullptr, 0, nullptr, nullptr, 0, 0, 0, 0, 0}
  };
  if (!entry) menu[2].label(nullptr);
  else {
    if (entry->folder) { menu[5].flags &= ~FL_MENU_DIVIDER; menu[6].label(nullptr); }
    if (!ConnectionStore::canMove(managerData, selectedId, selectedFolder, -1)) menu[4].deactivate();
    if (!ConnectionStore::canMove(managerData, selectedId, selectedFolder, 1)) menu[5].deactivate();
  }
  tree->redraw();
  auto chosen = menu->popup(Fl::event_x(), Fl::event_y());
  if (chosen) performManagerAction(chosen->label());
}

void ServerDialog::presenceTick(void* data)
{
  auto d = static_cast<ServerDialog*>(data);
  if (d->editor->visible() && d->vpnCatalogLoading && !vpnProfiles::snapshot().loading) {
    int selected = d->vpnProfile->value();
    d->updateVpnProfiles(selected >= 0 && size_t(selected) < d->vpnProfileIds.size() ? d->vpnProfileIds[selected] : "");
  }
  d->updatePresence();
  Fl::repeat_timeout(0.1, presenceTick, data);
}

void ServerDialog::updatePresence()
{
  auto d = this;
  try {
    std::vector<PingTarget> targets;
    if (d->shown() && d->expanded && networkSettings::pingEnabled) {
      resumePresence();
      auto visible = visibleConnectionIds(*d->tree);
      for (const auto& id : visible) {
        auto address = d->connectionAddresses.find(id);
        if (address != d->connectionAddresses.end()) targets.push_back({id, address->second});
      }
    }
    if (!networkSettings::pingEnabled) suspendPresence();
    d->presence->configure(networkSettings::pingPeriodMs(), networkSettings::pingMinimumMs(), networkSettings::pingTimeoutMs());
    d->presence->tick(pingClockMs(), targets);
    bool changed = false;
    for (auto item = d->tree->first(); item; item = d->tree->next(item)) {
      auto entry = static_cast<ConnectionTreeEntry*>(item->user_data());
      if (entry && !entry->folder) changed = setConnectionOnlineIcon(item, d->presence->online(entry->id)) || changed;
    }
    if (changed) d->tree->redraw();
  } catch (...) { /* Network monitoring must never interrupt the dialog. */ }
}

void ServerDialog::vpnAction(Fl_Widget* widget, void* data) {
  auto dialog = static_cast<ServerDialog*>(data);
  if (widget == dialog->vpnProvider) dialog->updateVpnProfiles();
  else {
    if (dialog->associateVpn->value()) { dialog->vpnProvider->activate(); dialog->vpnProfile->activate(); }
    else { dialog->vpnProvider->deactivate(); dialog->vpnProfile->deactivate(); }
  }
}
void ServerDialog::updateVpnProfiles(const std::string& selected) {
  auto catalog = vpnProfiles::snapshot(); vpnCatalogLoading = catalog.loading;
  const auto& profiles = vpnProvider->value() == 1 ? catalog.openvpn : catalog.wireguard;
  const auto& error = vpnProvider->value() == 1 ? catalog.openvpnError : catalog.wireguardError;
  vpnProfile->clear(); vpnProfileIds.clear();
  std::vector<Fl_Menu_Item> items;
  vpnProfileLabels.clear();
  int chosen = -1;
  auto add = [&](const std::string& id, const std::string& name) {
    vpnProfileLabels.push_back(name); vpnProfileIds.push_back(id);
    items.push_back(Fl_Menu_Item{}); items.back().label(vpnProfileLabels.back().c_str()); items.back().labelsize(13);
    if (id == selected) chosen = int(items.size()) - 1;
  };
  for (const auto& profile : profiles) add(profile.id, profile.name);
  if (!selected.empty() && chosen < 0) add(selected, selected + " (unavailable)");
  if (items.empty()) add("", catalog.loading ? "Loading profiles..." : "(No profiles found)");
  items.push_back(Fl_Menu_Item{}); vpnProfile->copy(items.data());
  vpnProfile->value(chosen >= 0 ? chosen : 0);
  vpnProfile->redraw();
  vpnProfile->copy_tooltip(error.empty() ? "VPN profile" : error.c_str());
  vpnAction(associateVpn, this);
}
