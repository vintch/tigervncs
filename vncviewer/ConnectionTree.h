// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef TIGERVNCS_CONNECTION_TREE_H
#define TIGERVNCS_CONNECTION_TREE_H
#include <FL/Fl_Tree.H>
#include <json/json.h>
#include <list>
#include <string>

struct ConnectionTreeEntry { std::string id; bool folder; };
// Rebuilds the actual UI tree, including its hidden root and per-item icons.
// Entries own user_data pointers until the next rebuild.
void populateConnectionTree(Fl_Tree& tree, const Json::Value& document,
                            std::list<ConnectionTreeEntry>& entries);
#endif
