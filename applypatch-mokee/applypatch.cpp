/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "applypatch.h"
#include "applypatch-mokee/applypatch.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef __linux__
#include <sys/statfs.h>
#endif
#include <sys/types.h>
#include <unistd.h>

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <openssl/sha.h>

#include "edify/expr.h"
#include "otafault/ota_io.h"
#include "otautil-mokee/cache_location.h"
#include "otautil/print_sha1.h"

static int LoadPartitionContents(const std::string& filename, FileContents* file);
static size_t FileSink(const unsigned char* data, size_t len, int fd);
static int GenerateTarget(FileContents* source_file,
                          const Value* source_patch_value,
                          FileContents* copy_file,
                          const Value* copy_patch_value,
                          const char* source_filename,
                          const char* target_filename,
                          const uint8_t target_sha1[SHA_DIGEST_LENGTH],
                          size_t target_size,
                          const Value* bonus_data);

// Read a file into memory; store the file contents and associated metadata in *file.
// Return 0 on success.
int LoadFileContents(const char* filename, FileContents* file) {
  // A special 'filename' beginning with "EMMC:" means to load the contents of a partition.
  if (strncmp(filename, "EMMC:", 5) == 0) {
    return LoadPartitionContents(filename, file);
  }

  if (stat(filename, &file->st) == -1) {
    printf("failed to stat \"%s\": %s\n", filename, strerror(errno));
    return -1;
  }

  std::vector<unsigned char> data(file->st.st_size);
  unique_file f(ota_fopen(filename, "rb"));
  if (!f) {
    printf("failed to open \"%s\": %s\n", filename, strerror(errno));
    return -1;
  }

  size_t bytes_read = ota_fread(data.data(), 1, data.size(), f.get());
  if (bytes_read != data.size()) {
    printf("short read of \"%s\" (%zu bytes of %zu)\n", filename, bytes_read, data.size());
    return -1;
  }
  file->data = std::move(data);
  SHA1(file->data.data(), file->data.size(), file->sha1);
  return 0;
}

// Load the contents of an EMMC partition into the provided
// FileContents.  filename should be a string of the form
// "EMMC:<partition_device>:...".  The smallest size_n bytes for
// which that prefix of the partition contents has the corresponding
// sha1 hash will be loaded.  It is acceptable for a size value to be
// repeated with different sha1s.  Will return 0 on success.
//
// This complexity is needed because if an OTA installation is
// interrupted, the partition might contain either the source or the
// target data, which might be of different lengths.  We need to know
// the length in order to read from a partition (there is no
// "end-of-file" marker), so the caller must specify the possible
// lengths and the hash of the data, and we'll do the load expecting
// to find one of those hashes.
static int LoadPartitionContents(const std::string& filename, FileContents* file) {
  std::vector<std::string> pieces = android::base::Split(filename, ":");
  if (pieces.size() < 4 || pieces.size() % 2 != 0 || pieces[0] != "EMMC") {
    printf("LoadPartitionContents called with bad filename \"%s\"\n", filename.c_str());
    return -1;
  }

  size_t pair_count = (pieces.size() - 2) / 2;  // # of (size, sha1) pairs in filename
  std::vector<std::pair<size_t, std::string>> pairs;
  for (size_t i = 0; i < pair_count; ++i) {
    size_t size;
    if (!android::base::ParseUint(pieces[i * 2 + 2], &size) || size == 0) {
      printf("LoadPartitionContents called with bad size \"%s\"\n", pieces[i * 2 + 2].c_str());
      return -1;
    }
    pairs.push_back({ size, pieces[i * 2 + 3] });
  }

  // Sort the pairs array so that they are in order of increasing size.
  std::sort(pairs.begin(), pairs.end());

  const char* partition = pieces[1].c_str();
  unique_file dev(ota_fopen(partition, "rb"));
  if (!dev) {
    printf("failed to open emmc partition \"%s\": %s\n", partition, strerror(errno));
    return -1;
  }

  SHA_CTX sha_ctx;
  SHA1_Init(&sha_ctx);

  // Allocate enough memory to hold the largest size.
  std::vector<unsigned char> buffer(pairs[pair_count - 1].first);
  unsigned char* buffer_ptr = buffer.data();
  size_t buffer_size = 0;  // # bytes read so far
  bool found = false;

  for (const auto& pair : pairs) {
    size_t current_size = pair.first;
    const std::string& current_sha1 = pair.second;

    // Read enough additional bytes to get us up to the next size. (Again,
    // we're trying the possibilities in order of increasing size).
    size_t next = current_size - buffer_size;
    if (next > 0) {
      size_t read = ota_fread(buffer_ptr, 1, next, dev.get());
      if (next != read) {
        printf("short read (%zu bytes of %zu) for partition \"%s\"\n", read, next, partition);
        return -1;
      }
      SHA1_Update(&sha_ctx, buffer_ptr, read);
      buffer_size += read;
      buffer_ptr += read;
    }

    // Duplicate the SHA context and finalize the duplicate so we can
    // check it against this pair's expected hash.
    SHA_CTX temp_ctx;
    memcpy(&temp_ctx, &sha_ctx, sizeof(SHA_CTX));
    uint8_t sha_so_far[SHA_DIGEST_LENGTH];
    SHA1_Final(sha_so_far, &temp_ctx);

    uint8_t parsed_sha[SHA_DIGEST_LENGTH];
    if (ParseSha1(current_sha1.c_str(), parsed_sha) != 0) {
      printf("failed to parse SHA-1 %s in %s\n", current_sha1.c_str(), filename.c_str());
      return -1;
    }

    if (memcmp(sha_so_far, parsed_sha, SHA_DIGEST_LENGTH) == 0) {
      // We have a match. Stop reading the partition; we'll return the data we've read so far.
      printf("partition read matched size %zu SHA-1 %s\n", current_size, current_sha1.c_str());
      found = true;
      break;
    }
  }

  if (!found) {
    // Ran off the end of the list of (size, sha1) pairs without finding a match.
    printf("contents of partition \"%s\" didn't match %s\n", partition, filename.c_str());
    return -1;
  }

  SHA1_Final(file->sha1, &sha_ctx);

  buffer.resize(buffer_size);
  file->data = std::move(buffer);
  // Fake some stat() info.
  file->st.st_mode = 0644;
  file->st.st_uid = 0;
  file->st.st_gid = 0;

  return 0;
}

// Save the contents of the given FileContents object under the given
// filename.  Return 0 on success.
int SaveFileContents(const char* filename, const FileContents* file) {
  unique_fd fd(ota_open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, S_IRUSR | S_IWUSR));
  if (fd == -1) {
    printf("failed to open \"%s\" for write: %s\n", filename, strerror(errno));
    return -1;
  }

  size_t bytes_written = FileSink(file->data.data(), file->data.size(), fd);
  if (bytes_written != file->data.size()) {
    printf("short write of \"%s\" (%zd bytes of %zu): %s\n", filename, bytes_written,
           file->data.size(), strerror(errno));
    return -1;
  }
  if (ota_fsync(fd) != 0) {
    printf("fsync of \"%s\" failed: %s\n", filename, strerror(errno));
    return -1;
  }
  if (ota_close(fd) != 0) {
    printf("close of \"%s\" failed: %s\n", filename, strerror(errno));
    return -1;
  }

  if (chmod(filename, file->st.st_mode) != 0) {
    printf("chmod of \"%s\" failed: %s\n", filename, strerror(errno));
    return -1;
  }
  if (chown(filename, file->st.st_uid, file->st.st_gid) != 0) {
    printf("chown of \"%s\" failed: %s\n", filename, strerror(errno));
    return -1;
  }

  return 0;
}

// Write a memory buffer to 'target' partition, a string of the form
// "EMMC:<partition_device>[:...]". The target name
// might contain multiple colons, but WriteToPartition() only uses the first
// two and ignores the rest. Return 0 on success.
int WriteToPartition(const unsigned char* data, size_t len, const std::string& target) {
  std::vector<std::string> pieces = android::base::Split(target, ":");
  if (pieces.size() < 2 || pieces[0] != "EMMC") {
    printf("WriteToPartition called with bad target (%s)\n", target.c_str());
    return -1;
  }

  const char* partition = pieces[1].c_str();
  unique_fd fd(ota_open(partition, O_RDWR));
  if (fd == -1) {
    printf("failed to open %s: %s\n", partition, strerror(errno));
    return -1;
  }

  size_t start = 0;
  bool success = false;
  for (size_t attempt = 0; attempt < 2; ++attempt) {
    if (TEMP_FAILURE_RETRY(lseek(fd, start, SEEK_SET)) == -1) {
      printf("failed seek on %s: %s\n", partition, strerror(errno));
      return -1;
    }
    while (start < len) {
      size_t to_write = len - start;
      if (to_write > 1 << 20) to_write = 1 << 20;

      ssize_t written = TEMP_FAILURE_RETRY(ota_write(fd, data + start, to_write));
      if (written == -1) {
        printf("failed write writing to %s: %s\n", partition, strerror(errno));
        return -1;
      }
      start += written;
    }

    if (ota_fsync(fd) != 0) {
      printf("failed to sync to %s: %s\n", partition, strerror(errno));
      return -1;
    }
    if (ota_close(fd) != 0) {
      printf("failed to close %s: %s\n", partition, strerror(errno));
      return -1;
    }

    fd.reset(ota_open(partition, O_RDONLY));
    if (fd == -1) {
      printf("failed to reopen %s for verify: %s\n", partition, strerror(errno));
      return -1;
    }

    // Drop caches so our subsequent verification read won't just be reading the cache.
    sync();
    unique_fd dc(ota_open("/proc/sys/vm/drop_caches", O_WRONLY));
    if (TEMP_FAILURE_RETRY(ota_write(dc, "3\n", 2)) == -1) {
      printf("write to /proc/sys/vm/drop_caches failed: %s\n", strerror(errno));
    } else {
      printf("  caches dropped\n");
    }
    ota_close(dc);
    sleep(1);

    // Verify.
    if (TEMP_FAILURE_RETRY(lseek(fd, 0, SEEK_SET)) == -1) {
      printf("failed to seek back to beginning of %s: %s\n", partition, strerror(errno));
      return -1;
    }

    unsigned char buffer[4096];
    start = len;
    for (size_t p = 0; p < len; p += sizeof(buffer)) {
      size_t to_read = len - p;
      if (to_read > sizeof(buffer)) {
        to_read = sizeof(buffer);
      }

      size_t so_far = 0;
      while (so_far < to_read) {
        ssize_t read_count = TEMP_FAILURE_RETRY(ota_read(fd, buffer + so_far, to_read - so_far));
        if (read_count == -1) {
          printf("verify read error %s at %zu: %s\n", partition, p, strerror(errno));
          return -1;
        } else if (read_count == 0) {
          printf("verify read reached unexpected EOF, %s at %zu\n", partition, p);
          return -1;
        }
        if (static_cast<size_t>(read_count) < to_read) {
          printf("short verify read %s at %zu: %zd %zu\n", partition, p, read_count, to_read);
        }
        so_far += read_count;
      }

      if (memcmp(buffer, data + p, to_read) != 0) {
        printf("verification failed starting at %zu\n", p);
        start = p;
        break;
      }
    }

    if (start == len) {
      printf("verification read succeeded (attempt %zu)\n", attempt + 1);
      success = true;
      break;
    }

    if (ota_close(fd) != 0) {
      printf("failed to close %s: %s\n", partition, strerror(errno));
      return -1;
    }

    fd.reset(ota_open(partition, O_RDWR));
    if (fd == -1) {
      printf("failed to reopen %s for retry write && verify: %s\n", partition, strerror(errno));
      return -1;
    }
  }

  if (!success) {
    printf("failed to verify after all attempts\n");
    return -1;
  }

  if (ota_close(fd) == -1) {
    printf("error closing %s: %s\n", partition, strerror(errno));
    return -1;
  }
  sync();

  return 0;
}

// Take a string 'str' of 40 hex digits and parse it into the 20
// byte array 'digest'.  'str' may contain only the digest or be of
// the form "<digest>:<anything>".  Return 0 on success, -1 on any
// error.
int ParseSha1(const char* str, uint8_t* digest) {
    const char* ps = str;
    uint8_t* pd = digest;
    for (int i = 0; i < SHA_DIGEST_LENGTH * 2; ++i, ++ps) {
        int digit;
        if (*ps >= '0' && *ps <= '9') {
            digit = *ps - '0';
        } else if (*ps >= 'a' && *ps <= 'f') {
            digit = *ps - 'a' + 10;
        } else if (*ps >= 'A' && *ps <= 'F') {
            digit = *ps - 'A' + 10;
        } else {
            return -1;
        }
        if (i % 2 == 0) {
            *pd = digit << 4;
        } else {
            *pd |= digit;
            ++pd;
        }
    }
    if (*ps != '\0') return -1;
    return 0;
}

// Search an array of sha1 strings for one matching the given sha1.
// Return the index of the match on success, or -1 if no match is
// found.
static int FindMatchingPatch(uint8_t* sha1, const std::vector<std::string>& patch_sha1_str) {
  for (size_t i = 0; i < patch_sha1_str.size(); ++i) {
    uint8_t patch_sha1[SHA_DIGEST_LENGTH];
    if (ParseSha1(patch_sha1_str[i].c_str(), patch_sha1) == 0 &&
        memcmp(patch_sha1, sha1, SHA_DIGEST_LENGTH) == 0) {
      return i;
    }
  }
  return -1;
}

// Returns 0 if the contents of the file (argv[2]) or the cached file
// match any of the sha1's on the command line (argv[3:]).  Returns
// nonzero otherwise.
int mokee_applypatch_check(const char* filename, const std::vector<std::string>& patch_sha1_str) {
  FileContents file;

  // It's okay to specify no sha1s; the check will pass if the
  // LoadFileContents is successful.  (Useful for reading
  // partitions, where the filename encodes the sha1s; no need to
  // check them twice.)
  if (LoadFileContents(filename, &file) != 0 ||
      (!patch_sha1_str.empty() && FindMatchingPatch(file.sha1, patch_sha1_str) < 0)) {
    printf("file \"%s\" doesn't have any of expected sha1 sums; checking cache\n", filename);

    // If the source file is missing or corrupted, it might be because we were killed in the middle
    // of patching it.  A copy of it should have been made in cache_temp_source.  If that file
    // exists and matches the sha1 we're looking for, the check still passes.
    if (LoadFileContents(CacheLocation::location().cache_temp_source().c_str(), &file) != 0) {
      printf("failed to load cache file\n");
      return 1;
    }

    if (FindMatchingPatch(file.sha1, patch_sha1_str) < 0) {
      printf("cache bits don't match any sha1 for \"%s\"\n", filename);
      return 1;
    }
  }
  return 0;
}

int ShowLicenses() {
    ShowBSDiffLicense();
    return 0;
}

static size_t FileSink(const unsigned char* data, size_t len, int fd) {
  size_t done = 0;
  while (done < len) {
    ssize_t wrote = TEMP_FAILURE_RETRY(ota_write(fd, data + done, len - done));
    if (wrote == -1) {
      printf("error writing %zd bytes: %s\n", (len - done), strerror(errno));
      return done;
    }
    done += wrote;
  }
  return done;
}

// Return the amount of free space (in bytes) on the filesystem
// containing filename.  filename must exist.  Return -1 on error.
size_t FreeSpaceForFile(const char* filename) {
#ifdef __linux__
    struct statfs sf;
    if (statfs(filename, &sf) != 0) {
        printf("failed to statfs %s: %s\n", filename, strerror(errno));
        return -1;
    }
    return sf.f_bsize * sf.f_bavail;
#else
    (void)filename;
    return 1 * 1024 * 1024 * 1024;
#endif
}

int CacheSizeCheck(size_t bytes) {
    if (MakeFreeSpaceOnCache(bytes) < 0) {
        printf("unable to make %zu bytes available on /cache\n", bytes);
        return 1;
    }
    return 0;
}

// This function applies binary patches to EMMC target files in a way that is safe (the original
// file is not touched until we have the desired replacement for it) and idempotent (it's okay to
// run this program multiple times).
//
// - If the SHA-1 hash of <target_filename> is <target_sha1_string>, does nothing and exits
//   successfully.
//
// - Otherwise, if the SHA-1 hash of <source_filename> is one of the entries in <patch_sha1_str>,
//   the corresponding patch from <patch_data> (which must be a VAL_BLOB) is applied to produce a
//   new file (the type of patch is automatically detected from the blob data). If that new file
//   has SHA-1 hash <target_sha1_str>, moves it to replace <target_filename>, and exits
//   successfully. Note that if <source_filename> and <target_filename> are not the same,
//   <source_filename> is NOT deleted on success. <target_filename> may be the string "-" to mean
//   "the same as <source_filename>".
//
// - Otherwise, or if any error is encountered, exits with non-zero status.
//
// <source_filename> must refer to an EMMC partition to read the source data. See the comments for
// the LoadPartitionContents() function above for the format of such a filename. <target_size> has
// become obsolete since we have dropped the support for patching non-EMMC targets (EMMC targets
// have the size embedded in the filename).
int mokee_applypatch(const char* source_filename, const char* target_filename,
               const char* target_sha1_str, size_t target_size,
               const std::vector<std::string>& patch_sha1_str,
               const std::vector<std::unique_ptr<Value>>& patch_data, const Value* bonus_data) {
  printf("patch %s: ", source_filename);

  if (target_filename[0] == '-' && target_filename[1] == '\0') {
    target_filename = source_filename;
  }

  uint8_t target_sha1[SHA_DIGEST_LENGTH];
  if (ParseSha1(target_sha1_str, target_sha1) != 0) {
    printf("failed to parse tgt-sha1 \"%s\"\n", target_sha1_str);
    return 1;
  }

  // We try to load the target file into the source_file object.
  FileContents source_file;
  const Value* source_patch_value = nullptr;
  if (LoadFileContents(target_filename, &source_file) == 0) {
    if (memcmp(source_file.sha1, target_sha1, SHA_DIGEST_LENGTH) == 0) {
      // The early-exit case: the patch was already applied, this file has the desired hash, nothing
      // for us to do.
      printf("already %s\n", short_sha1(target_sha1).c_str());
      return 0;
    }
  }

  if (source_file.data.empty() ||
      (target_filename != source_filename && strcmp(target_filename, source_filename) != 0)) {
    // Need to load the source file: either we failed to load the target file, or we did but it's
    // different from the source file.
    source_file.data.clear();
    LoadFileContents(source_filename, &source_file);
  }

  if (!source_file.data.empty()) {
    int to_use = FindMatchingPatch(source_file.sha1, patch_sha1_str);
    if (to_use >= 0) {
      source_patch_value = patch_data[to_use].get();
    }
  }

  FileContents copy_file;
  const Value* copy_patch_value = nullptr;
  if (source_patch_value == nullptr) {
    source_file.data.clear();
    printf("source file is bad; trying copy\n");

    if (LoadFileContents(CacheLocation::location().cache_temp_source().c_str(), &copy_file) < 0) {
      // fail.
      printf("failed to read copy file\n");
      return 1;
    }

    int to_use = FindMatchingPatch(copy_file.sha1, patch_sha1_str);
    if (to_use >= 0) {
      copy_patch_value = patch_data[to_use].get();
    }

    if (copy_patch_value == nullptr) {
      // fail.
      printf("copy file doesn't match source SHA-1s either\n");
      return 1;
    }
  }

  return GenerateTarget(&source_file, source_patch_value,
                        &copy_file, copy_patch_value,
                        source_filename, target_filename,
                        target_sha1, target_size, bonus_data);
}

static int GenerateTarget(FileContents* source_file,
                          const Value* source_patch_value,
                          FileContents* copy_file,
                          const Value* copy_patch_value,
                          const char* source_filename,
                          const char* target_filename,
                          const uint8_t target_sha1[SHA_DIGEST_LENGTH],
                          size_t target_size,
                          const Value* bonus_data) {
  // assume that target_filename (eg "/system/app/Foo.apk") is located
  // on the same filesystem as its top-level directory ("/system").
  // We need something that exists for calling statfs().
  std::string target_fs = target_filename;
  auto slash_pos = target_fs.find('/', 1);
  if (slash_pos != std::string::npos) {
    target_fs.resize(slash_pos);
  }

  FileContents* source_to_use;
  const Value* patch;
  if (source_patch_value != nullptr) {
    source_to_use = source_file;
    patch = source_patch_value;
  } else {
    source_to_use = copy_file;
    patch = copy_patch_value;
  }

  if (patch->type != Value::Type::BLOB) {
    printf("patch is not a blob\n");
    return 1;
  }

  const char* header = &patch->data[0];
  size_t header_bytes_read = patch->data.size();
  bool use_bsdiff = false;
  if (header_bytes_read >= 8 && memcmp(header, "BSDIFF40", 8) == 0) {
    use_bsdiff = true;
  } else if (header_bytes_read >= 8 && memcmp(header, "IMGDIFF2", 8) == 0) {
    use_bsdiff = false;
  } else {
    printf("Unknown patch file format\n");
    return 1;
  }

  bool target_is_partition = (strncmp(target_filename, "EMMC:", 5) == 0);
  const std::string tmp_target_filename = std::string(target_filename) + ".patch";

  // We store the decoded output in memory.
  std::string memory_sink_str;  // Don't need to reserve space.
  SinkFn sink = [&memory_sink_str](const unsigned char* data, size_t len) {
    memory_sink_str.append(reinterpret_cast<const char*>(data), len);
    return len;
  };

  int retry = 1;
  bool made_copy = false;
  SHA_CTX ctx;
  do {
    // Is there enough room in the target filesystem to hold the patched file?

    if (target_is_partition) {
      // If the target is a partition, we're actually going to
      // write the output to /tmp and then copy it to the
      // partition.  statfs() always returns 0 blocks free for
      // /tmp, so instead we'll just assume that /tmp has enough
      // space to hold the file.

      // We still write the original source to cache, in case
      // the partition write is interrupted.
      if (MakeFreeSpaceOnCache(source_file->data.size()) < 0) {
        printf("not enough free space on /cache\n");
        return 1;
      }
      if (SaveFileContents(CacheLocation::location().cache_temp_source().c_str(), source_file) < 0) {
        printf("failed to back up source file\n");
        return 1;
      }
      made_copy = true;
      retry = 0;
    } else {
      bool enough_space = false;
      if (retry > 0) {
        size_t free_space = FreeSpaceForFile(target_fs.c_str());
        enough_space = (free_space > (256 << 10)) &&          // 256k (two-block) minimum
                       (free_space > (target_size * 3 / 2));  // 50% margin of error
        if (!enough_space) {
          printf("target %zu bytes; free space %zu bytes; retry %d; enough %d\n", target_size,
                 free_space, retry, enough_space);
        }
      }

      if (!enough_space) {
        retry = 0;
      }

      if (!enough_space && source_patch_value != nullptr) {
        // Using the original source, but not enough free space.  First
        // copy the source file to cache, then delete it from the original
        // location.

        if (strncmp(source_filename, "EMMC:", 5) == 0) {
          // It's impossible to free space on the target filesystem by
          // deleting the source if the source is a partition.  If
          // we're ever in a state where we need to do this, fail.
          printf("not enough free space for target but source is partition\n");
          return 1;
        }

        if (MakeFreeSpaceOnCache(source_file->data.size()) < 0) {
          printf("not enough free space on /cache\n");
          return 1;
        }

        if (SaveFileContents(CacheLocation::location().cache_temp_source().c_str(), source_file) < 0) {
          printf("failed to back up source file\n");
          return 1;
        }
        made_copy = true;
        unlink(source_filename);

        size_t free_space = FreeSpaceForFile(target_fs.c_str());
        printf("(now %zu bytes free for target) ", free_space);
      }
    }

    SinkFn sink = nullptr;
    unique_fd output_fd;
    if (target_is_partition) {
      // We store the decoded output in memory.
      sink = [&memory_sink_str](const unsigned char* data, size_t len) {
        memory_sink_str.append(reinterpret_cast<const char*>(data), len);
        return len;
      };
    } else {
      // We write the decoded output to "<tgt-file>.patch".
      output_fd.reset(ota_open(tmp_target_filename.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_SYNC,
                               S_IRUSR | S_IWUSR));
      if (output_fd == -1) {
        printf("failed to open output file %s: %s\n", tmp_target_filename.c_str(), strerror(errno));
        return 1;
      }
      sink = [&output_fd](const unsigned char* data, size_t len) {
        size_t done = 0;
        while (done < len) {
          ssize_t wrote = TEMP_FAILURE_RETRY(ota_write(output_fd, data + done, len - done));
          if (wrote == -1) {
            printf("error writing %zd bytes: %s\n", (len - done), strerror(errno));
            return done;
          }
          done += wrote;
        }
        return done;
      };
    }

    SHA1_Init(&ctx);

    int result;
    if (use_bsdiff) {
      result = ApplyBSDiffPatch(source_to_use->data.data(), source_to_use->data.size(), *patch, 0,
                                sink, &ctx);
    } else {
      result = ApplyImagePatch(source_to_use->data.data(), source_to_use->data.size(), *patch, sink,
                               &ctx, bonus_data);
    }

    if (!target_is_partition) {
      if (ota_fsync(output_fd) != 0) {
        printf("failed to fsync file \"%s\": %s\n", tmp_target_filename.c_str(), strerror(errno));
        result = 1;
      }
      if (ota_close(output_fd) != 0) {
        printf("failed to close file \"%s\": %s\n", tmp_target_filename.c_str(), strerror(errno));
        result = 1;
      }
    }

    if (result != 0) {
      if (retry == 0) {
        printf("applying patch failed\n");
        return 1;
      } else {
        printf("applying patch failed; retrying\n");
      }
      if (!target_is_partition) {
        unlink(tmp_target_filename.c_str());
      }
    } else {
      // succeeded; no need to retry
      break;
    }
  } while (retry-- > 0);

  uint8_t current_target_sha1[SHA_DIGEST_LENGTH];
  SHA1_Final(current_target_sha1, &ctx);
  if (memcmp(current_target_sha1, target_sha1, SHA_DIGEST_LENGTH) != 0) {
    printf("patch did not produce expected sha1\n");
    return 1;
  } else {
    printf("now %s\n", short_sha1(target_sha1).c_str());
  }

  if (target_is_partition) {
    // Copy the temp file to the partition.
    if (WriteToPartition(reinterpret_cast<const unsigned char*>(memory_sink_str.c_str()),
                         memory_sink_str.size(), target_filename) != 0) {
      printf("write of patched data to %s failed\n", target_filename);
      return 1;
    }
  } else {
    // Give the .patch file the same owner, group, and mode of the original source file.
    if (chmod(tmp_target_filename.c_str(), source_to_use->st.st_mode) != 0) {
      printf("chmod of \"%s\" failed: %s\n", tmp_target_filename.c_str(), strerror(errno));
      return 1;
    }
    if (chown(tmp_target_filename.c_str(), source_to_use->st.st_uid,
              source_to_use->st.st_gid) != 0) {
      printf("chown of \"%s\" failed: %s\n", tmp_target_filename.c_str(), strerror(errno));
      return 1;
    }

    // Finally, rename the .patch file to replace the target file.
    if (rename(tmp_target_filename.c_str(), target_filename) != 0) {
      printf("rename of .patch to \"%s\" failed: %s\n", target_filename, strerror(errno));
      return 1;
    }
  }

  // If this run of applypatch created the copy, and we're here, we can delete it.
  if (made_copy) {
    unlink(CacheLocation::location().cache_temp_source().c_str());
  }

  // Success!
  return 0;
}