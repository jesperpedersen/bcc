/*
 * Copyright (c) 2015 PLUMgrid, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <unistd.h>

namespace llvm {
class Function;
}

namespace clang {
class ASTContext;
class QualType;
}

namespace ebpf {

class TableDesc;

/// FileDesc is a helper class for managing open file descriptors. Copy is
/// disallowed (call dup instead), and cleanup happens automatically.
class FileDesc {
  friend TableDesc;
 private:
  FileDesc & operator=(const FileDesc& that) {
    fd = ::dup(that.fd);
    return *this;
  }
  FileDesc(const FileDesc& that) { *this = that; }
 public:
  FileDesc(int fd = -1) : fd(fd) {}
  FileDesc & operator=(FileDesc &&that) {
    fd = that.fd;
    that.fd = -1;
    return *this;
  }
  FileDesc(FileDesc &&that) { *this = std::move(that); }
  ~FileDesc() {
    if (fd >= 0)
      ::close(fd);
  }
  FileDesc dup() const {
    return FileDesc(*this);
  }

  operator int() { return fd; }
  operator int() const { return fd; }
 private:
  int fd = -1;
};

/// TableDesc uniquely stores all of the runtime state for an active bpf table.
/// The copy constructor/assign operator are disabled since the file handles
/// owned by this table are not implicitly copyable. One should call the dup()
/// method if an explicit new handle is required. We define the move operators
/// so that objects of this class can reside in stl containers.
class TableDesc {
 private:
  TableDesc(const TableDesc &) = default;
  TableDesc & operator=(const TableDesc &) = default;
 public:
  TableDesc() = default;
  TableDesc(TableDesc&& that) = default;
  TableDesc & operator=(TableDesc&& that) = default;
  TableDesc dup() const {
    return TableDesc(*this);
  }

  std::string name;
  FileDesc fd;
  int type = {};
  size_t key_size = 0;  // sizes are in bytes
  size_t leaf_size = 0;
  size_t max_entries = 0;
  int flags = 0;
  std::string key_desc;
  std::string leaf_desc;
  llvm::Function *key_sscanf = nullptr;
  llvm::Function *leaf_sscanf = nullptr;
  llvm::Function *key_snprintf = nullptr;
  llvm::Function *leaf_snprintf = nullptr;
  bool is_shared = false;
  bool is_extern = false;
};

/// MapTypesVisitor gets notified of new bpf tables, and has a chance to parse
/// the key and leaf types for their own usage. Subclass this abstract class and
/// implement the Visit method, then add an instance of this class to the
/// StorageTable instance to be notified of each new key/leaf type.
class MapTypesVisitor {
 public:
  virtual ~MapTypesVisitor() {}
  virtual void Visit(TableDesc &desc, clang::ASTContext &C, clang::QualType
                     key_type, clang::QualType leaf_type) = 0;
};

std::unique_ptr<MapTypesVisitor> createJsonMapTypesVisitor();

}  // namespace ebpf
