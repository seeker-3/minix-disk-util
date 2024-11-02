#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <fstream>
#include <ios>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using i64 = int64_t;
using u32 = uint32_t;
using u16 = uint16_t;
using u8 = uint8_t;
using byte = char;

constexpr u32 ROOT_INUM = 1;

constexpr u32 MAX_DIRECT_ZONES = 7;

constexpr u32 S_IFREG = 0100000;
constexpr u32 S_IFDIR = 0040000;
constexpr u32 FULL_PERMISSIONS = 0777;

constexpr u32 MAGIC = 0x4D5A;
constexpr u32 BOOTBLOCK_SIZE = 1024;

void print_buffer(const byte *const buffer, const u32 size,
                  const std::string &message = "") {
  std::cout << "\nSTART\n";
  if (!message.empty()) {
    std::cout << message << '\n';
  }
  std::cout << "Size: " << size << "\n\n";
  for (u32 i = 0; i < size; ++i) {
    std::cout << buffer[i];
  }
  std::cout << "\n\nEND\n\n";
}

void print_zone_pointers(const u32 *const buffer) {
  for (u32 i = 0; i < 256; ++i) {
    std::cout << buffer[i] << " ";
  }
  std::cout << '\n';
}

u32 get_timestamp_seconds() {
  return static_cast<u32>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

u32 get_file_size(std::ifstream &fin) {
  fin.seekg(0, std::ios::end);
  const i64 size = fin.tellg();
  fin.seekg(0, std::ios::beg);
  return static_cast<u32>(size);
}

struct Superblock {
  u32 num_inodes;      // total number of inodes in the inode table.
  u16 pad0;            // padding bytes (not used).
  u16 imap_blocks;     // number of blocks used to store the inode map (imap).
  u16 zmap_blocks;     // number of blocks used to store the zone map (zmap).
  u16 first_data_zone; // index of first data zone. Use 1024 x first_data_zone
                       // for the byte offset.
  u16 log_zone_size;   // size of a zone using 1024<<log_zone_size.
  u16 pad1;            // padding bytes (not used).
  u32 max_size;        // maximum size of a single file in bytes.
  u32 num_zones;       // number of actual blocks that store data (zones).
  u16 magic;       // Must be 0x4D5A to identify this as a Minix 3 file system.
  u16 pad2;        // padding bytes (not used).
  u16 zone_size;   // The size of a block in bytes.
  u8 disk_version; // The subversion of the particular disk (not really used).
  u8 pad4;         // padding byte to 32 bytes (not used).

  void print() const {
    std::cout << "Superblock:" << '\n';
    std::cout << "    num_inodes: " << num_inodes << '\n';
    std::cout << "    imap_blocks: " << imap_blocks << '\n';
    std::cout << "    zmap_blocks: " << zmap_blocks << '\n';
    std::cout << "    first_data_zone: " << first_data_zone << '\n';
    std::cout << "    log_zone_size: " << log_zone_size << '\n';
    std::cout << "    max_size: " << max_size << '\n';
    std::cout << "    num_zones: " << num_zones << '\n';
    std::cout << "    magic: " << magic << '\n';
    std::cout << "    block_size: " << zone_size << '\n';
    std::cout << "    disk_version: " << disk_version << '\n';
    std::cout << '\n';
  }
};

struct Inode {
  u16 mode;
  u16 nlinks;
  u16 uid;
  u16 gid;
  u32 size;
  u32 atime;
  u32 mtime;
  u32 ctime;
  u32 zones[10];

  [[nodiscard]] u32 get_num_zones(const u32 zone_size) const {
    return size / zone_size + (size % zone_size == 0 ? 0 : 1);
  }

  void print() const {
    std::cout << "Inode:" << '\n';
    std::cout << "    mode: " << mode << '\n';
    std::cout << "    nlinks: " << nlinks << '\n';
    std::cout << "    uid: " << uid << '\n';
    std::cout << "    gid: " << gid << '\n';
    std::cout << "    size: " << size << '\n';
    std::cout << "    atime: " << atime << '\n';
    std::cout << "    mtime: " << mtime << '\n';
    std::cout << "    ctime: " << ctime << '\n';
    std::cout << "    zones: " << zones[0] << " " << zones[1] << " " << zones[2]
              << " " << zones[3] << " " << zones[4] << " " << zones[5] << " "
              << zones[6] << " " << zones[7] << " " << zones[8] << " "
              << zones[9] << '\n';
    std::cout << '\n';
  }
};

constexpr u32 DIR_ENTRY_NAME_SIZE = 60;

struct DirEntry {
  u32 inum;
  char name[DIR_ENTRY_NAME_SIZE] = {};
  DirEntry(const u32 inode, const std::string &name) : inum(inode) {
    if (name.size() > DIR_ENTRY_NAME_SIZE) {
      throw std::runtime_error("DirEntry name is too long: " + name);
    }

    strncpy(this->name, name.c_str(), name.size());
  }

  void print() const {
    std::cout << "DirEntry: (" << inum << ") " << name << '\n';
  }
};

enum InodeZoneOperation {
  READ,
  WRITE,
};

struct FilesystemInfo {
  const Superblock superblock;
  const u32 zone_size;
  const u32 data_zone_start;
  const u32 inode_bitmap_size;
  const u32 zone_bitmap_size;
  const i64 inode_bitmap_pos;
  const i64 zone_bitmap_pos;
  const i64 inodes_pos;
};

FilesystemInfo read_filesystem_info(const std::string &minix_image) {
  std::fstream minix_fs(minix_image);
  if (!minix_fs.is_open()) {
    throw std::runtime_error("Could not open minix image: " + minix_image);
  }
  Superblock superblock{};

  minix_fs.seekg(BOOTBLOCK_SIZE);
  minix_fs.read(reinterpret_cast<byte *>(&superblock), sizeof(Superblock));

  assert(superblock.magic == MAGIC);

  const u32 zone_size = superblock.zone_size << superblock.log_zone_size;
  const u32 data_zone_start = superblock.first_data_zone
                              << superblock.log_zone_size;

  const i64 inode_bitmap_pos = BOOTBLOCK_SIZE + zone_size;
  const u32 inode_bitmap_size = superblock.imap_blocks * zone_size;

  const i64 zone_bitmap_pos =
      inode_bitmap_pos + static_cast<i64>(inode_bitmap_size);
  const u32 zone_bitmap_size = superblock.zmap_blocks * zone_size;

  const i64 inodes_pos = zone_bitmap_pos + static_cast<i64>(zone_bitmap_size);

  minix_fs.close();

  return {
      .superblock = superblock,
      .zone_size = zone_size,
      .data_zone_start = data_zone_start,
      .inode_bitmap_size = inode_bitmap_size,
      .zone_bitmap_size = zone_bitmap_size,
      .inode_bitmap_pos = inode_bitmap_pos,
      .zone_bitmap_pos = zone_bitmap_pos,
      .inodes_pos = inodes_pos,
  };
}

struct ZoneIndexes {
  const u32 index1;
  const std::optional<u32> index2;
  const std::optional<u32> index3;
  const std::optional<u32> index4;
};

struct PathParser {
  std::string filename;
  std::vector<std::string> path;
  explicit PathParser(const std::string &name) {
    if (name.empty()) {
      throw std::runtime_error("Empty path");
    }
    if (name.front() != '/') {
      throw std::runtime_error("Path must start with '/'");
    }
    if (name.back() == '/') {
      throw std::runtime_error(
          "Path must not end with '/'. Path must be a file.");
    }

    std::string chunk;
    std::istringstream parser(name);
    while (std::getline(parser, chunk, '/')) {
      if (!chunk.empty()) {
        path.push_back(chunk);
      }
    }

    filename = path.back();
    path.pop_back();
  }
  void print() const {
    for (const auto &chunk : path) {
      std::cout << '/' << chunk;
    }
    std::cout << '/' << filename << '\n';
  }
};

struct Bitmap {
  const i64 pos;
  const u32 size;

  const u32 num_bits;
  const u32 num_blocks;

  const std::unique_ptr<u8[]> bitmap;
  Bitmap() = delete;
  explicit Bitmap(const i64 pos, const u32 size, const u32 num_bits,
                  const u32 num_blocks)
      : pos(pos), size(size), num_bits(num_bits), num_blocks(num_blocks),
        bitmap(std::make_unique<u8[]>(size)) {}

  u32 claim() {
    for (u32 i = 0; i < size; i++) {
      for (u32 j = 0; j < 8; j++) {
        const u32 mask = 1U << j;
        if ((bitmap[i] & mask) == 0) {
          this->bitmap[i] |= mask;
          return i * 8 + j;
        }
      }
    }
    throw std::runtime_error("No free bits");
  }

  [[nodiscard]] bool is_taken(const u32 index) const {
    const u32 byte_index = index / 8;
    const u32 bit_index = index % 8;
    const u32 mask = 1U << bit_index;
    return (bitmap[byte_index] & mask) != 0;
  }

  [[nodiscard]] size_t count_taken() const {
    size_t taken = 0;
    for (u32 i = 0; i < size; i++) {
      for (u32 j = 0; j < 8; j++) {
        const u32 mask = 1U << j;
        if ((bitmap[i] & mask) != 0) {
          ++taken;
        }
      }
    }
    return taken;
  }
};

struct MinixDiskUtil {
  const FilesystemInfo info;
  std::fstream minix_fs;
  Bitmap inode_bitmap;
  Bitmap zone_bitmap;
  MinixDiskUtil() = delete;
  explicit MinixDiskUtil(const std::string &minix_image,
                         const FilesystemInfo info)
      : info(info), minix_fs(minix_image),
        inode_bitmap(info.inode_bitmap_pos, info.inode_bitmap_size,
                     info.superblock.num_inodes, info.superblock.imap_blocks),
        zone_bitmap(info.zone_bitmap_pos, info.zone_bitmap_size,
                    info.superblock.num_zones, info.superblock.zmap_blocks) {
    minix_fs.seekg(info.inode_bitmap_pos);
    minix_fs.read(reinterpret_cast<byte *>(inode_bitmap.bitmap.get()),
                  inode_bitmap.size);
    minix_fs.read(reinterpret_cast<byte *>(zone_bitmap.bitmap.get()),
                  zone_bitmap.size);
  }
  ~MinixDiskUtil() { minix_fs.close(); }

  std::unique_ptr<byte[]> new_buffer() const {
    return std::make_unique<byte[]>(info.zone_size);
  }

  u32 create_inode(const u16 mode, const u32 size) {
    const u32 inum = inode_bitmap.claim() + 1;
    write_bitmap(inode_bitmap);

    const u32 timestamp = get_timestamp_seconds();

    const Inode inode{
        .mode = mode,
        .nlinks = 1,
        .uid = 0,
        .gid = 0,
        .size = size,
        .atime = timestamp,
        .mtime = timestamp,
        .ctime = timestamp,
        .zones{},
    };

    write_inode(inum, inode);

    return inum;
  }

  Inode read_inode(const u32 inum) {
    const i64 inode_pos =
        info.inodes_pos + static_cast<i64>((inum - 1) * sizeof(Inode));
    minix_fs.seekg(inode_pos);

    Inode inode{};
    minix_fs.read(reinterpret_cast<byte *>(&inode), sizeof(Inode));
    return inode;
  }

  void write_inode(const u32 inum, const Inode &inode) {
    const i64 inode_pos =
        info.inodes_pos + static_cast<i64>((inum - 1) * sizeof(Inode));
    minix_fs.seekg(inode_pos);

    minix_fs.write(reinterpret_cast<const byte *>(&inode), sizeof(Inode));
  }

  void write_bitmap(const Bitmap &bitmap) {
    minix_fs.seekg(bitmap.pos);
    minix_fs.write(reinterpret_cast<byte *>(bitmap.bitmap.get()), bitmap.size);
  }

  void read_zone(const u32 zone_number, byte *const buffer, const u32 size) {
    minix_fs.seekg(static_cast<i64>(zone_number * info.zone_size));
    minix_fs.read(buffer, size);
  }

  void write_zone(const u32 zone_number, const byte *const buffer,
                  const u32 size) {
    minix_fs.seekg(static_cast<i64>(zone_number * info.zone_size));
    minix_fs.write(buffer, size);
  }

  void read_write_zone(const u32 zone_number, byte *const buffer,
                       const u32 size, const InodeZoneOperation operation) {
    switch (operation) {
    case READ:
      read_zone(zone_number, buffer, size);
      break;
    case WRITE:
      write_zone(zone_number, buffer, size);
      break;
    }
  }

  u32 create_zone() {
    const u32 zone_number =
        zone_bitmap.claim() + info.superblock.first_data_zone;
    write_bitmap(zone_bitmap);

    minix_fs.seekg(static_cast<i64>(zone_number * info.zone_size));
    const std::unique_ptr buffer = new_buffer();
    // Fill with zeros
    minix_fs.write(buffer.get(), info.zone_size);

    return zone_number;
  }

  u32 create_directory(const u32 inum_parent, const std::string &name,
                       const bool exists_ok = false) {
    if (name == "." || name == "..") {
      throw std::runtime_error("Reserved file name: " + name);
    }

    const std::optional optional_inum = find_dir_entry(inum_parent, name);

    if (optional_inum) {
      if (!exists_ok) {
        throw std::runtime_error("Directory entry already exists: " + name);
      }

      return optional_inum.value();
    }

    const u32 inum = create_inode(S_IFDIR | FULL_PERMISSIONS, 0);
    create_dir_entry(inum_parent, name, inum);
    create_dir_entry(inum, ".", inum);
    create_dir_entry(inum, "..", inum_parent);

    return inum;
  }

  std::optional<u32> find_dir_entry(const u32 inum, const std::string &name) {
    const Inode inode = read_inode(inum);
    const u32 num_zones = inode.get_num_zones(info.zone_size);

    const std::unique_ptr buffer = new_buffer();

    for (size_t zone_index = 0; zone_index < num_zones; ++zone_index) {
      const u32 bytes =
          inode_zone_operation(inum, zone_index, buffer.get(), READ);
      const u32 num_dir_entries = bytes / sizeof(DirEntry);
      const auto *const dir_entries =
          reinterpret_cast<DirEntry *>(buffer.get());

      for (size_t j = 0; j < num_dir_entries; ++j) {
        if (dir_entries[j].inum == 0) {
          continue;
        }
        if (std::string(dir_entries[j].name) == name) {
          return {dir_entries[j].inum};
        }
      }
    }

    return std::nullopt;
  }

  void create_dir_entry(const u32 inum_parent, const std::string &name,
                        const u32 inum) {
    if (name.size() + 1 > DIR_ENTRY_NAME_SIZE) {
      throw std::runtime_error("File name too long: " + name);
    }
    if (find_dir_entry(inum_parent, name)) {
      throw std::runtime_error("File already exists: " + name);
    }

    Inode inode_parent = read_inode(inum_parent);

    inode_parent.size += sizeof(DirEntry);

    const u32 timestamp = get_timestamp_seconds();

    inode_parent.mtime = timestamp;
    inode_parent.atime = timestamp;

    // Update the inode size for `inode_zone_operation`
    write_inode(inum_parent, inode_parent);

    const DirEntry new_dir_entry(inum, name);

    const u32 zone_index = inode_parent.get_num_zones(info.zone_size) - 1;
    const std::unique_ptr buffer = new_buffer();

    const u32 bytes =
        inode_zone_operation(inum_parent, zone_index, buffer.get(), READ, true);

    const u32 num_dir_entries = bytes / sizeof(DirEntry);
    auto *const dir_entries = reinterpret_cast<DirEntry *>(buffer.get());
    dir_entries[num_dir_entries - 1] = new_dir_entry;

    inode_zone_operation(inum_parent, zone_index, buffer.get(), WRITE);
  }

  void print_dir_entries(const u32 inum) {
    const Inode inode = read_inode(inum);
    const u32 num_zones = inode.get_num_zones(info.zone_size);

    const std::unique_ptr buffer = new_buffer();

    for (size_t zone_index = 0; zone_index < num_zones; ++zone_index) {
      const u32 bytes =
          inode_zone_operation(inum, zone_index, buffer.get(), READ);
      const u32 num_dir_entries = bytes / sizeof(DirEntry);
      const auto *const dir_entries =
          reinterpret_cast<DirEntry *>(buffer.get());

      for (size_t j = 0; j < num_dir_entries; ++j) {
        dir_entries[j].print();
      }
    }
  }

  u32 create_file(const u32 inum_parent, const std::string &name,
                  std::ifstream &fin)

  {
    const u32 file_size = get_file_size(fin);

    if (file_size > info.superblock.max_size) {
      throw std::runtime_error("File size exceeds max size: " +
                               std::to_string(file_size));
    }

    const u32 inum = create_inode(S_IFREG | FULL_PERMISSIONS, file_size);

    const Inode inode = read_inode(inum);

    create_dir_entry(inum_parent, name, inum);

    const u32 num_zones = inode.get_num_zones(info.zone_size);

    for (u32 zone_index = 0; zone_index < num_zones; ++zone_index) {
      const std::unique_ptr data = new_buffer();

      fin.read(data.get(), info.zone_size);

      const u32 data_size =
          inode_zone_operation(inum, zone_index, data.get(), WRITE, true);
      (void)data_size;
    }

    return inum;
  }

  void print_file(const u32 inum) {
    const Inode inode = read_inode(inum);
    const u32 num_zones = inode.get_num_zones(info.zone_size);

    const std::unique_ptr data = new_buffer();

    for (u32 zone_index = 0; zone_index < num_zones; ++zone_index) {
      const u32 data_size =
          inode_zone_operation(inum, zone_index, data.get(), READ);

      for (u32 i = 0; i < data_size; ++i) {
        std::cout << data[i];
      }
    }
  }

  u32 inode_zone_operation(const u32 inum, const u32 zone_index,
                           byte *const data, const InodeZoneOperation operation,
                           const bool allocate = false);
};

int main(const int argc, const char *const *const argv) {
  try {
    if (argc != 4) {
      std::cout << "Usage: " << argv[0]
                << " <minix image> <local path> <image path>" << '\n';
      return 1;
    }

    const std::string minix_image = argv[1];
    const std::string local_path = argv[2];
    const std::string image_path = argv[3];

    MinixDiskUtil minix_disk_util(minix_image,
                                  read_filesystem_info(minix_image));

    std::ifstream fin(local_path, std::ios::binary);

    if (!fin.is_open()) {
      std::cerr << "Could not open file: " << local_path << '\n';
      return 1;
    }

    const PathParser path_parser(image_path);

    u32 dir_inum = ROOT_INUM;

    // Recursively create directories and ignores any that already exist
    for (const auto &chunk : path_parser.path) {
      dir_inum = minix_disk_util.create_directory(dir_inum, chunk, true);
    }

    const u32 file_inum =
        minix_disk_util.create_file(dir_inum, path_parser.filename, fin);
    (void)file_inum;

    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}

ZoneIndexes get_zone_indexes(const FilesystemInfo &info, const u32 zone_index) {
  const u32 zone_size = info.zone_size;
  const u32 max_index = info.superblock.max_size / zone_size;

  const u32 entries_per_zone = zone_size / sizeof(u32);
  const u32 entries_per_zone_squared = entries_per_zone * entries_per_zone;

  const u32 max_singly_indirect_zones = MAX_DIRECT_ZONES + entries_per_zone;
  const u32 max_doubly_indirect_zones =
      max_singly_indirect_zones + entries_per_zone_squared;
  const u32 max_triply_indirect_zones =
      max_doubly_indirect_zones + entries_per_zone_squared * entries_per_zone;

  //? > or >=
  if (zone_index >= max_index) {
    throw std::runtime_error(
        "Zone index exceeds max index: " + std::to_string(zone_index) +
        " >= " + std::to_string(zone_index));
  }

  if (zone_index < MAX_DIRECT_ZONES) {
    return {
        .index1 = zone_index,
        .index2 = std::nullopt,
        .index3 = std::nullopt,
        .index4 = std::nullopt,
    };
  }

  if (zone_index < max_singly_indirect_zones) {
    const u32 offset = zone_index - MAX_DIRECT_ZONES;
    return {
        .index1 = 7,
        .index2 = offset,
        .index3 = std::nullopt,
        .index4 = std::nullopt,
    };
  }

  if (zone_index < max_triply_indirect_zones) {
    const u32 offset = zone_index - max_singly_indirect_zones;
    return {
        .index1 = 8,
        .index2 = offset / entries_per_zone,
        .index3 = offset % entries_per_zone,
        .index4 = std::nullopt,
    };
  }

  const u32 offset = zone_index - max_doubly_indirect_zones;
  return {
      .index1 = 9,
      .index2 = offset / entries_per_zone_squared,
      .index3 = (offset % entries_per_zone_squared) / entries_per_zone,
      .index4 = offset % entries_per_zone,
  };
}

u32 MinixDiskUtil::inode_zone_operation(const u32 inum, const u32 zone_index,
                                        byte *const data,
                                        const InodeZoneOperation operation,
                                        const bool allocate) {
  Inode inode = read_inode(inum);

  const u32 zone_size = info.zone_size;

  const u32 total_size = zone_index * zone_size;
  const u32 data_size = std::min(inode.size - total_size, zone_size);

  if (total_size > inode.size) {
    throw std::runtime_error(
        "Zone index exceeds inode size: " + std::to_string(total_size) + " > " +
        std::to_string(inode.size));
  }

  const ZoneIndexes zone_indexes = get_zone_indexes(info, zone_index);
  const u32 index1 = zone_indexes.index1;
  const std::optional optional_index2 = zone_indexes.index2;
  const std::optional optional_index3 = zone_indexes.index3;
  const std::optional optional_index4 = zone_indexes.index4;

  // Direct
  const std::unique_ptr buffer = new_buffer();
  auto *const buffer_u32 = reinterpret_cast<u32 *>(buffer.get());

  // TODO: Maybe check the bitmap instead of assuming zero means undefined
  if (inode.zones[index1] == 0) {
    if (!allocate) {
      throw std::runtime_error("Zone number 1 is undefined");
    }

    inode.zones[index1] = create_zone();
    write_inode(inum, inode);
  }

  const u32 zone_number1 = inode.zones[index1];

  if (!optional_index2) {
    read_write_zone(zone_number1, data, data_size, operation);
    return data_size;
  }

  // Singly indirect
  const u32 index2 = optional_index2.value();

  read_zone(zone_number1, buffer.get(), zone_size);

  if (buffer_u32[index2] == 0) {
    if (!allocate) {
      throw std::runtime_error("Zone number 2 is undefined");
    }

    buffer_u32[index2] = create_zone();
    write_zone(zone_number1, buffer.get(), zone_size);
  }

  const u32 zone_number2 = buffer_u32[index2];

  if (!optional_index3) {
    read_write_zone(zone_number2, data, data_size, operation);
    return data_size;
  }

  // Doubly indirect
  const u32 index3 = optional_index3.value();

  read_zone(zone_number2, buffer.get(), zone_size);

  if (buffer_u32[index3] == 0) {
    if (!allocate) {
      throw std::runtime_error("Zone number 3 is undefined");
    }

    buffer_u32[index3] = create_zone();
    write_zone(zone_number1, buffer.get(), zone_size);
  }

  const u32 zone_number3 = buffer_u32[index3];

  if (!optional_index4) {
    read_write_zone(zone_number3, data, data_size, operation);
    return data_size;
  }

  // Triply indirect
  const u32 index4 = optional_index4.value();

  read_zone(zone_number3, buffer.get(), zone_size);

  if (buffer_u32[index4] == 0) {
    if (!allocate) {
      throw std::runtime_error("Zone number 4 is undefined");
    }

    buffer_u32[index4] = create_zone();
    write_zone(zone_number1, buffer.get(), zone_size);
  }

  const u32 zone_number4 = buffer_u32[index4];

  read_write_zone(zone_number4, data, data_size, operation);

  return data_size;
}
