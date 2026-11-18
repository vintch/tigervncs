/* Copyright 2011 Pierre Ossman <ossman@cendio.se> for Cendio AB
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 * USA.
 */

#ifndef __SERVERDIALOG_H__
#define __SERVERDIALOG_H__

#include <FL/Fl_Window.H>
#include <string>
#include <list>
#include <vector>
#include "ConnectionStore.h"
#include "ConnectionTree.h"

#include "fltk/Fl_Suggestion_Input.h"

class Fl_Widget;
class Fl_Input_Choice;
class Fl_Tree;
class Fl_Tree_Item;
class Fl_Group;
class Fl_Input;
class Fl_Choice;
class Fl_Check_Button;
class Fl_Button;

class ServerDialog : public Fl_Window {
protected:
  ServerDialog();
  ~ServerDialog();

public:
  static std::string run(const char* servername);

protected:
  static void handleOptions(Fl_Widget *widget, void *data);
  static void handleLoad(Fl_Widget *widget, void *data);
  static void handleSaveAs(Fl_Widget *widget, void *data);
  static void handleAbout(Fl_Widget *widget, void *data);
  static void handleCancel(Fl_Widget *widget, void *data);
  static void handleConnect(Fl_Widget *widget, void *data);

private:
  void createManager(int top);
  void refreshManager(const std::string& selected = "");
  void expandManager(bool expanded);
  void editEntry(bool folder, bool existing);
  void closeEditor();
  static void managerAction(Fl_Widget*, void*);
  static void treeAction(Fl_Widget*, void*);
  Fl_Group *managerPane, *editor;
  Fl_Tree* tree;
  Fl_Input *entryName, *entryAddress, *entryUser, *entryPassword;
  Fl_Choice* entryFolder;
  Fl_Check_Button* rememberPassword;
  Fl_Button *managerButton, *editButton, *deleteButton;
  ConnectionStore store;
  Json::Value managerData;
  std::list<ConnectionTreeEntry> treeEntries;
  std::vector<std::string> folderIds;
  std::list<std::string> folderLabels;
  std::string selectedId, selectedComputer, editingId;
  bool selectedFolder = false, editingFolder = false, rebuilding = false;
  bool expanded = false;
  int collapsedHeight;
  void loadServerHistory();
  void saveServerHistory();
  void updateUsedDir(const char* filename);

  static void onServerHistoryRemove(Fl_Widget*, std::string s, void* data);
  static std::string serverHistoryNormalize(const std::string s);

protected:
  Fl_Suggestion_Input *serverName;
  std::list<std::string> serverHistory;
  std::string usedDir;
};

#endif
